package org.dashfoundation.dashsdk.security

import android.app.KeyguardManager
import android.content.Context
import android.security.keystore.UserNotAuthenticatedException
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.security.GeneralSecurityException
import java.util.Base64

private val Context.secretsStore: DataStore<Preferences> by preferencesDataStore(
    name = "org.dashfoundation.wallet.secrets",
)

/**
 * Encrypted-at-rest secret storage — the Android counterpart of
 * `WalletStorage.swift` (iOS Keychain items under service
 * `org.dashfoundation.wallet`).
 *
 * Values are ciphertext under [KeystoreManager]'s non-exportable Keystore
 * keys, stored base64 in a dedicated Preferences DataStore.
 * Key layout mirrors the iOS account naming:
 * - `mnemonic.<walletIdHex>` — wallet mnemonics (master alias, AES-GCM)
 * - `privkey.<pubkeyHex>` — identity private keys (the [keystore]'s
 *   [KeystoreManager.keysAlias]: RSA public-key encrypt / private-key
 *   decrypt that is auth-gated or not per the keystore's
 *   [KeySecurityPolicy])
 *
 * Consuming apps should exclude this DataStore from Android's default app-data
 * backup — Keystore keys are device-bound and never restored, so a backed-up
 * blob can never be decrypted on the new device. See
 * `res/xml/dash_sdk_backup_rules.xml` and `res/xml/dash_sdk_data_extraction_rules.xml`
 * for ready-made exclusion rules and the manifest snippet to reference them.
 *
 * The identity-key security policy is fixed by the [keystore] this storage
 * wraps; use the policy-taking constructor to opt into
 * [KeySecurityPolicy.DEVICE_BOUND] (see [KeySecurityPolicy] for the
 * semantics and the stability requirement). The default is the historical
 * [KeySecurityPolicy.AUTH_GATED] behavior, unchanged.
 */
class WalletStorage(
    context: Context,
    private val keystore: KeystoreManager =
        KeystoreManager(deviceSecureProbe = deviceSecureProbe(context)),
) {
    /**
     * Construct with an explicit identity-key [keySecurityPolicy] —
     * convenience for host apps that don't otherwise need to touch
     * [KeystoreManager]. `WalletStorage(context)` keeps the
     * [KeySecurityPolicy.AUTH_GATED] default.
     */
    constructor(context: Context, keySecurityPolicy: KeySecurityPolicy) :
        this(context, KeystoreManager(keySecurityPolicy, deviceSecureProbe(context)))

    private val store = context.secretsStore

    /** The identity-key security policy this storage was constructed with. */
    val keySecurityPolicy: KeySecurityPolicy get() = keystore.keySecurityPolicy

    /**
     * Serializes every `privkey.*` alias mutation. A single DataStore
     * `edit` is already atomic, but compound sequences (wallet deletion's
     * enumerate → refcount → batch-delete) must not interleave with a
     * concurrent [storePrivateKey] — an alias written after the snapshot
     * would survive deletion and lose its discoverable Room row to the
     * cascade. Writers take this internally; compound readers-then-writers
     * use [withPrivateKeyExclusion]. The mutex is NOT reentrant: code
     * running inside [withPrivateKeyExclusion] must use the scope's own
     * operations, never the public locking entry points.
     */
    private val privateKeyMutex = Mutex()

    /**
     * Deleted-wallet ids rejected by [storePrivateKey] / [storeIfAbsent]
     * until [clearTombstone] un-marks them — guarded by [privateKeyMutex]
     * like every other mutation here. Process-lifetime only: NOT persisted
     * across process restart, and deliberately cleared on (re-)creation
     * rather than kept forever, because wallet ids are deterministic
     * functions of seed+network — deleting a wallet and re-importing the
     * same recovery phrase later in the same process reuses the same id,
     * and that is a real, supported recovery flow, not a resurrection bug.
     */
    private val tombstonedWalletIds = mutableSetOf<String>()

    /** Operations available while the private-key exclusion is held. */
    interface PrivateKeyExclusion {
        /** [WalletStorage.deletePrivateKeys], lock already held. */
        suspend fun deletePrivateKeys(pubkeyHexes: Collection<String>)

        /**
         * Drop a wallet's owner-index entry after its aliases were swept.
         * Aliases retained by the sweep (shared with another wallet) stay
         * discoverable through the OTHER wallet's index / Room rows.
         */
        suspend fun deleteOwnerIndex(walletId: ByteArray)

        /**
         * True if any wallet OTHER than [excludingWalletId] still claims
         * [pubkeyHex] in its durable owner index — i.e. a sibling wallet
         * pre-stored this alias but hasn't (yet) committed a `public_keys`
         * row for it, so a committed-row-only reference check would miss
         * it and delete a sibling's key out from under it.
         */
        suspend fun isOwnedByAnotherWallet(pubkeyHex: String, excludingWalletId: ByteArray): Boolean

        /**
         * Mark [walletId] as deleted. Subsequent [storePrivateKey] /
         * [storeIfAbsent] calls for it are rejected (thrown as
         * [WalletTombstonedException]) until [clearTombstone] un-marks it —
         * closes the window where an app-level coroutine that started
         * before deletion (e.g. an in-flight identity-key preview/derive)
         * completes its store AFTER deletion finished, resurrecting the
         * wallet's owner-index entry with fresh ciphertext.
         */
        suspend fun tombstoneWallet(walletId: ByteArray)
    }

    private val privateKeyExclusionScope = object : PrivateKeyExclusion {
        override suspend fun deletePrivateKeys(pubkeyHexes: Collection<String>) =
            deletePrivateKeysLocked(pubkeyHexes)

        override suspend fun deleteOwnerIndex(walletId: ByteArray) {
            store.edit { it.remove(ownerIndexKey(walletId.toHex())) }
        }

        override suspend fun isOwnedByAnotherWallet(
            pubkeyHex: String,
            excludingWalletId: ByteArray,
        ): Boolean {
            val excludingHex = excludingWalletId.toHex()
            val normalized = pubkeyHex.lowercase()
            return store.data.first().asMap().any { (key, value) ->
                key.name.startsWith(PRIVKEY_OWNERS_PREFIX) &&
                    key.name.removePrefix(PRIVKEY_OWNERS_PREFIX) != excludingHex &&
                    (value as? Set<*>)?.contains(normalized) == true
            }
        }

        override suspend fun tombstoneWallet(walletId: ByteArray) {
            tombstonedWalletIds += walletId.toHex()
        }
    }

    /**
     * Run [block] with the private-key mutation lock held, so no
     * [storePrivateKey] / [deletePrivateKey] can interleave with a
     * compound snapshot-then-delete sequence. The block must not call
     * the public locking entry points (non-reentrant); it must also never
     * call into native code (a persistence callback parked on this lock
     * inside [storePrivateKey] can be holding native locks).
     */
    suspend fun <T> withPrivateKeyExclusion(
        block: suspend PrivateKeyExclusion.() -> T,
    ): T = privateKeyMutex.withLock { privateKeyExclusionScope.block() }

    /**
     * Clear a deletion tombstone for [walletId] — called when a wallet with
     * that (deterministic, seed-derived) id is (re-)created, so a prior
     * delete-then-reimport doesn't permanently reject its stores. A no-op
     * if [walletId] was never tombstoned.
     */
    suspend fun clearTombstone(walletId: ByteArray) {
        privateKeyMutex.withLock { tombstonedWalletIds -= walletId.toHex() }
    }

    private fun rejectIfTombstonedLocked(ownerWalletId: ByteArray) {
        if (ownerWalletId.toHex() in tombstonedWalletIds) {
            throw WalletTombstonedException(ownerWalletId)
        }
    }

    // ── Mnemonics ─────────────────────────────────────────────────────

    suspend fun storeMnemonic(walletId: ByteArray, mnemonic: String) {
        val blob = keystore.encrypt(mnemonic.encodeToByteArray())
        store.edit { it[mnemonicKey(walletId)] = encode(blob) }
    }

    /**
     * Decrypt the mnemonic as a display `String`. For explicit
     * user-facing reveal flows ONLY (seed backup, biometric reveal) —
     * a String cannot be scrubbed afterwards. Programmatic consumers
     * (the FFI resolver, signers) must use [retrieveMnemonicUtf8].
     */
    suspend fun retrieveMnemonic(walletId: ByteArray): String? {
        val encoded = store.data.first()[mnemonicKey(walletId)] ?: return null
        val plain = keystore.decrypt(decode(encoded))
        val phrase = plain.decodeToString()
        plain.fill(0)
        return phrase
    }

    /**
     * Decrypt the mnemonic as raw UTF-8 bytes, never materializing a JVM
     * `String` (the iOS `retrieveMnemonicUTF8Bytes` discipline). The
     * caller OWNS the returned array and MUST `fill(0)` it as soon as the
     * bytes are consumed — unlike a String, a ByteArray can actually be
     * scrubbed, so the plaintext exposure window is bounded by the call
     * instead of by the garbage collector.
     */
    suspend fun retrieveMnemonicUtf8(walletId: ByteArray): ByteArray? {
        val encoded = store.data.first()[mnemonicKey(walletId)] ?: return null
        return keystore.decrypt(decode(encoded))
    }

    /**
     * Whether a mnemonic is stored for [walletId]. Existence-only — never
     * decrypts, never materializes plaintext (Swift `hasMnemonic(for:)`).
     */
    suspend fun hasMnemonic(walletId: ByteArray): Boolean =
        store.data.first().contains(mnemonicKey(walletId))

    suspend fun deleteMnemonic(walletId: ByteArray) {
        store.edit { it.remove(mnemonicKey(walletId)) }
    }

    /** Wallet ids (hex) that have a stored mnemonic — drives orphan detection. */
    suspend fun listWalletIdsWithMnemonic(): List<String> =
        store.data.first().asMap().keys
            .map { it.name }
            .filter { it.startsWith(MNEMONIC_PREFIX) }
            .map { it.removePrefix(MNEMONIC_PREFIX) }

    // ── Identity private keys ─────────────────────────────────────────

    /**
     * Store raw private-key bytes for [pubkeyHex], encrypted with the
     * [KeystoreManager.keysAlias] RSA public key. Public-key encrypt is
     * never auth-gated (under either [KeySecurityPolicy]), so this never
     * prompts and never throws `UserNotAuthenticatedException` — matching
     * iOS's silent identity-key write, and letting the persistence callback
     * (which runs on a Rust Tokio thread under the wallet-manager write
     * lock, where a prompt is impossible) store keys. Per the CLAUDE.md
     * doctrine this is the one allowed Kotlin-side persistence of key
     * material: Rust derives, we encrypt. Reads ([retrievePrivateKey])
     * require auth only under [KeySecurityPolicy.AUTH_GATED].
     */
    /**
     * @param ownerWalletId when given, the alias is also recorded in the
     *   wallet's DURABLE owner index (`privkeyowners.<walletIdHex>` — a
     *   string-set entry written in the SAME atomic edit). The index is
     *   what makes the alias discoverable by wallet deletion when no
     *   committed `public_keys` row references it yet: app-prestored keys
     *   for an in-flight registration, and deriver writes orphaned by
     *   process death (the in-memory pending-alias fence does not survive
     *   termination). Pass it whenever the owning wallet is known.
     */
    suspend fun storePrivateKey(
        pubkeyHex: String,
        privateKey: ByteArray,
        ownerWalletId: ByteArray? = null,
    ) {
        privateKeyMutex.withLock {
            // No tombstone check when ownerWalletId is null: a null owner
            // was never recorded in any owner index either, so it can't be
            // resurrecting a deleted wallet's discoverable state the way a
            // durable-owner write could. No caller on the derive/register
            // path passes null today.
            if (ownerWalletId != null) rejectIfTombstonedLocked(ownerWalletId)
            storePrivateKeyEntryLocked(pubkeyHex, privateKey, ownerWalletId)
        }
    }

    /**
     * Delete each of [pubkeyHexes] that no wallet OTHER than
     * [excludingWalletId] durably owns, ATOMICALLY with that ownership
     * check — a rolled-back changeset round's cleanup needs this, not two
     * separate calls (a check via [PrivateKeyExclusion.isOwnedByAnotherWallet]
     * then a delete via [deletePrivateKeys]): a sibling wallet's
     * [storeIfAbsent] could adopt one of these aliases in the window
     * between two separately-locked calls and lose its just-adopted key
     * to this delete anyway. Returns the hexes actually deleted (a subset
     * of [pubkeyHexes] — the rest are retained because another wallet
     * owns them, not because anything failed).
     *
     * A retained alias (owned elsewhere) still gets [excludingWalletId]
     * removed from ITS OWN owner-index entry for that alias — this is a
     * rollback: [excludingWalletId]'s round that created the alias failed,
     * so it never legitimately owned it, only the OTHER wallet that
     * adopted it via [storeIfAbsent] does. Leaving [excludingWalletId]'s
     * claim in place would strand a phantom owner: a later delete of the
     * real owner would see [excludingWalletId] still listed, wrongly
     * retain the ciphertext, and never clean up either index.
     */
    suspend fun deleteUnownedPrivateKeys(
        pubkeyHexes: Collection<String>,
        excludingWalletId: ByteArray,
    ): Set<String> {
        if (pubkeyHexes.isEmpty()) return emptySet()
        return privateKeyMutex.withLock {
            val toDelete = pubkeyHexes.filterTo(mutableSetOf()) { hex ->
                !privateKeyExclusionScope.isOwnedByAnotherWallet(hex, excludingWalletId)
            }
            if (toDelete.isNotEmpty()) deletePrivateKeysLocked(toDelete)
            val retained = pubkeyHexes.toSet() - toDelete
            if (retained.isNotEmpty()) removeFromOwnerIndexLocked(excludingWalletId, retained)
            toDelete
        }
    }

    /**
     * Drop just [pubkeyHexes] from [walletId]'s owner-index entry, leaving
     * any other aliases it owns intact (unlike [deleteOwnerIndex], which
     * drops the whole entry). Lock must already be held.
     */
    private suspend fun removeFromOwnerIndexLocked(walletId: ByteArray, pubkeyHexes: Collection<String>) {
        if (pubkeyHexes.isEmpty()) return
        val normalized = pubkeyHexes.map { it.lowercase() }.toSet()
        val indexKey = ownerIndexKey(walletId.toHex())
        store.edit { prefs ->
            val current = prefs[indexKey] ?: return@edit
            val next = current - normalized
            if (next.size != current.size) {
                if (next.isEmpty()) prefs.remove(indexKey) else prefs[indexKey] = next
            }
        }
    }

    /**
     * If [pubkeyHex] has no *usable* stored ciphertext — absent, or present
     * but not [isPrivateKeyDecryptable] (a legacy pre-RSA blob) — derive it
     * via [derive] and store it; either way record [ownerWalletId] in the
     * owner index. Returns whether a derive+store actually happened (the
     * "existed before" complement the identity-key persist callback needs).
     *
     * [derive] runs OUTSIDE the private-key lock (it's a native FFI call —
     * [withPrivateKeyExclusion]'s own contract forbids native calls while
     * holding it, since a callback parked on this lock can be holding
     * native locks), so this isn't one atomic transaction: a concurrent
     * caller can derive the same alias in parallel. The lock is retaken
     * before the write and the existence check re-run — the loser's
     * derived bytes are discarded and only its ownership is recorded, so
     * two racing derivations settle on one stored copy either way.
     *
     * This function does NOT scrub the bytes [derive] returns — on every
     * path (stored, discarded as the race loser, or a
     * [WalletTombstonedException] thrown before either) the caller still
     * holds the array `derive` returned and owns zeroing it.
     * [IdentityKeyPrivateKeyDeriver.deriveAndStore], the only caller today,
     * does this in a `finally`; a future second caller must too.
     *
     * Throws [WalletTombstonedException] if [ownerWalletId] was deleted.
     */
    suspend fun storeIfAbsent(
        pubkeyHex: String,
        ownerWalletId: ByteArray,
        derive: suspend () -> ByteArray,
    ): Boolean {
        if (privateKeyMutex.withLock { addOwnerIfUsableLocked(pubkeyHex, ownerWalletId) }) {
            return false
        }
        val derived = derive()
        return privateKeyMutex.withLock {
            if (addOwnerIfUsableLocked(pubkeyHex, ownerWalletId)) {
                false // another writer won the race while this derived
            } else {
                storePrivateKeyEntryLocked(pubkeyHex, derived, ownerWalletId)
                true
            }
        }
    }

    /**
     * If [pubkeyHex] already has a decryptable ciphertext entry (under any
     * owner), record [ownerWalletId]'s ownership and return `true`;
     * otherwise leave everything untouched and return `false`. Lock must
     * already be held.
     */
    private suspend fun addOwnerIfUsableLocked(pubkeyHex: String, ownerWalletId: ByteArray): Boolean {
        rejectIfTombstonedLocked(ownerWalletId)
        val prefs = store.data.first()
        val encoded = prefs[privateKeyKey(pubkeyHex)] ?: return false
        if (!isCurrentKeysBlob(pubkeyHex, encoded, prefs)) return false
        val indexKey = ownerIndexKey(ownerWalletId.toHex())
        store.edit { it[indexKey] = (it[indexKey] ?: emptySet()) + pubkeyHex.lowercase() }
        return true
    }

    /** Encrypt-and-write [privateKey] for [pubkeyHex]; lock must already be held. */
    private suspend fun storePrivateKeyEntryLocked(
        pubkeyHex: String,
        privateKey: ByteArray,
        ownerWalletId: ByteArray?,
    ) {
        val blob = keystore.encrypt(privateKey, alias = keystore.keysAlias)
        store.edit {
            it[privateKeyKey(pubkeyHex)] = encode(blob)
            it[privateKeyFingerprintKey(pubkeyHex)] = keystore.keysAliasFingerprint()
            if (ownerWalletId != null) {
                val indexKey = ownerIndexKey(ownerWalletId.toHex())
                it[indexKey] = (it[indexKey] ?: emptySet()) + pubkeyHex.lowercase()
            }
        }
    }

    /**
     * Whether the stored blob for [pubkeyHex] is both structurally an RSA
     * blob and was encrypted under the [KeystoreManager.keysAlias] keypair
     * currently in the Keystore — see [KeystoreManager.keysAliasFingerprint].
     * A missing fingerprint (written before this check existed) is treated
     * as unusable rather than trusted, since a stale RSA-shaped blob is
     * indistinguishable from a current one by shape alone.
     */
    private fun isCurrentKeysBlob(
        pubkeyHex: String,
        encoded: String,
        prefs: Preferences,
    ): Boolean {
        if (!keystore.isKeysBlobDecryptable(decode(encoded))) return false
        val fingerprint = prefs[privateKeyFingerprintKey(pubkeyHex)] ?: return false
        return fingerprint == keystore.keysAliasFingerprint()
    }

    /**
     * The wallet's durable owner-index entries — pubkey hexes of aliases
     * stored on its behalf (see [storePrivateKey]). Read-only snapshot;
     * call inside [withPrivateKeyExclusion] when it must be consistent
     * with a following delete.
     */
    suspend fun ownedPrivateKeyAliases(walletId: ByteArray): Set<String> =
        store.data.first()[ownerIndexKey(walletId.toHex())] ?: emptySet()

    /**
     * Decrypt the private key for [pubkeyHex]. Under
     * [KeySecurityPolicy.AUTH_GATED] this throws
     * `UserNotAuthenticatedException` when the auth window expired — the
     * caller (KeystoreSigner) routes through [BiometricGate] and retries;
     * under [KeySecurityPolicy.DEVICE_BOUND] it never auth-gates.
     * Callers must zero the returned array after use.
     *
     * Upgrade path — two legacy on-disk schemes are recovered and migrated
     * forward transparently (so old identity keys are never stranded), then
     * future reads use the current aliased RSA scheme:
     *  1. **Pre-RSA AES-GCM** blob (non-empty IV) under the legacy
     *     [KeystoreManager.KEYS_ALIAS] AES key — decrypted with that retained
     *     key ([KeystoreManager.decryptLegacyKeysBlob]).
     *  2. **Pre-alias-split RSA** blob (empty IV) encrypted under the former RSA
     *     keypair still at [KeystoreManager.KEYS_ALIAS] — the current policy
     *     alias cannot open it, so we fall back to that keypair
     *     ([KeystoreManager.decryptLegacyRsaKeysBlob]) (dashpay/platform#4060).
     * Both are re-encrypted under [KeystoreManager.keysAlias] and rewritten. A
     * fresh install has no legacy blobs and always takes the current-alias path.
     */
    suspend fun retrievePrivateKey(pubkeyHex: String): ByteArray? {
        val encoded = store.data.first()[privateKeyKey(pubkeyHex)] ?: return null
        val blob = decode(encoded)
        if (keystore.isLegacyKeysBlob(blob)) {
            // Scheme 1 — legacy AES-GCM blob: recover with the retained legacy
            // AES key (may throw UserNotAuthenticatedException — the legacy key
            // was auth-gated — which the signer handles exactly as the RSA
            // path), or null if that key is already gone (unrecoverable).
            val plain = keystore.decryptLegacyKeysBlob(blob) ?: return null
            migrateToPolicyAlias(pubkeyHex, plain, encoded)
            return plain
        }
        // Empty-IV RSA blob: encrypted under the current policy alias (steady
        // state), the former RSA keypair still at KEYS_ALIAS (scheme 2 blobs
        // written before the alias split), or — after a policy switch (e.g.
        // AUTH_GATED→DEVICE_BOUND) — a *sibling* policy alias we no longer target
        // (dashpay/platform#4060). Key *presence* never proves which alias wrote
        // THIS blob: an unrelated former RSA key can linger next to a
        // sibling-alias blob, so every candidate key is TRIED and a wrong-key
        // crypto failure is treated as "not this key" (per the
        // [KeystoreManager.decryptLegacyRsaKeysBlob] contract) rather than letting
        // a BadPaddingException escape uncaught into KeystoreSigner. A blob that no
        // present key can open is unrecoverable → null (key-health then offers a
        // re-derive), mirroring the legacy-AES stranded path above — never a bogus
        // plaintext. UserNotAuthenticatedException is NOT a wrong-key signal and
        // always propagates so KeystoreSigner can prompt and retry.

        // Upgrade fast path: an unprovisioned policy alias cannot have produced
        // the blob, so recover with the former RSA keypair directly instead of
        // provisioning a throwaway policy keypair only to fail. If that key does
        // not open it either (former key absent, or the blob belongs to a sibling
        // alias), the blob is unrecoverable here → null.
        if (!keystore.hasIdentityKeysKey(keystore.keysAlias)) {
            val recovered = tryFormerRsaRecovery(blob) ?: return null
            migrateToPolicyAlias(pubkeyHex, recovered, encoded)
            return recovered
        }
        // Steady state: try the current policy alias first; on a wrong-key crypto
        // failure (a scheme-2 / sibling blob lingering while a key already lives at
        // the policy alias) fall back to the former RSA keypair and migrate, else
        // report the blob unrecoverable (null).
        return try {
            keystore.decrypt(blob, alias = keystore.keysAlias)
        } catch (e: UserNotAuthenticatedException) {
            throw e
        } catch (e: GeneralSecurityException) {
            val recovered = tryFormerRsaRecovery(blob) ?: return null
            migrateToPolicyAlias(pubkeyHex, recovered, encoded)
            recovered
        }
    }

    /**
     * Attempt recovery of an empty-IV RSA blob with the retained former
     * pre-alias-split RSA keypair at [KeystoreManager.KEYS_ALIAS], converting a
     * wrong-key crypto failure to `null` ("not this key",
     * dashpay/platform#4060). [KeystoreManager.decryptLegacyRsaKeysBlob] returns
     * `null` when that key is absent and throws a JCE `BadPaddingException` when
     * the key is present but did not write the blob — presence alone is not proof
     * of origin, so that throw must be absorbed here rather than escaping
     * uncaught. `UserNotAuthenticatedException` is a closed-auth-window signal,
     * never a wrong key, so it propagates unchanged.
     */
    private fun tryFormerRsaRecovery(blob: KeystoreManager.EncryptedBlob): ByteArray? =
        try {
            keystore.decryptLegacyRsaKeysBlob(blob)
        } catch (e: UserNotAuthenticatedException) {
            throw e
        } catch (e: GeneralSecurityException) {
            null
        }

    /**
     * Best-effort re-encrypt [plain] under the current policy alias
     * ([KeystoreManager.keysAlias], a never-auth-gated public-key encrypt) and
     * rewrite the stored blob, migrating a recovered legacy value forward. A
     * rewrite failure must not lose the value the caller just recovered, so this
     * stays best-effort (migration retries on the next read).
     *
     * The rewrite is CONDITIONAL on the entry still holding [sourceEncoded] —
     * the exact encoded blob the caller read and recovered. [retrievePrivateKey]
     * runs without [privateKeyMutex], so between its read and this rewrite a
     * wallet deletion can win [withPrivateKeyExclusion], sweep the alias plus
     * its owner-index entry, and cascade the Room rows; an unconditional edit
     * would then RESURRECT `privkey.<pubkeyHex>` as undiscoverable ciphertext
     * with no owner-index or database reference, violating removeWallet's
     * no-surviving-ciphertext guarantee (dashpay/platform#4060, finding
     * 1049be675782). DataStore serializes edits, so the still-present check and
     * the write commit atomically against the deletion's edit: if the deletion
     * (or any concurrent overwrite — e.g. a [storePrivateKey] racing in a newer
     * value) got there first, the migration is skipped; the caller still
     * returns the plaintext it legitimately recovered.
     */
    private suspend fun migrateToPolicyAlias(
        pubkeyHex: String,
        plain: ByteArray,
        sourceEncoded: String,
    ) {
        runCatching {
            val migrated = keystore.encrypt(plain, alias = keystore.keysAlias)
            store.edit {
                val key = privateKeyKey(pubkeyHex)
                if (it[key] == sourceEncoded) {
                    it[key] = encode(migrated)
                    // Keep the write-time fingerprint coherent with the
                    // re-encrypted blob, so [isCurrentKeysBlob] (the
                    // storeIfAbsent usability check) recognizes the migrated
                    // entry instead of re-deriving it.
                    it[privateKeyFingerprintKey(pubkeyHex)] = keystore.keysAliasFingerprint()
                }
            }
        }
    }

    suspend fun deletePrivateKey(pubkeyHex: String) {
        privateKeyMutex.withLock {
            store.edit {
                it.remove(privateKeyKey(pubkeyHex))
                it.remove(privateKeyFingerprintKey(pubkeyHex))
            }
        }
    }

    /**
     * Remove every `privkey.<pubkeyHex>` entry in [pubkeyHexes] in ONE
     * DataStore `edit` — a single atomic commit, so either every alias is
     * removed or none are. The wallet-deletion sweep depends on this:
     * per-key deletes commit independently, and a failure between them
     * would leave a live wallet missing some of its signing keys.
     */
    suspend fun deletePrivateKeys(pubkeyHexes: Collection<String>) {
        privateKeyMutex.withLock { deletePrivateKeysLocked(pubkeyHexes) }
    }

    private suspend fun deletePrivateKeysLocked(pubkeyHexes: Collection<String>) {
        if (pubkeyHexes.isEmpty()) return
        val normalized = pubkeyHexes.map { it.lowercase() }.toSet()
        store.edit { prefs ->
            for (pubkeyHex in normalized) {
                prefs.remove(privateKeyKey(pubkeyHex))
                prefs.remove(privateKeyFingerprintKey(pubkeyHex))
            }
            // Keep every owner index accurate in the same atomic commit:
            // a deleted alias must leave all wallets' index sets, or a
            // later wallet deletion would "discover" a ghost.
            prefs.asMap().keys
                .filter { it.name.startsWith(PRIVKEY_OWNERS_PREFIX) }
                .forEach { prefKey ->
                    val setKey = stringSetPreferencesKey(prefKey.name)
                    val current = prefs[setKey] ?: return@forEach
                    val next = current - normalized
                    if (next.size != current.size) {
                        if (next.isEmpty()) prefs.remove(setKey) else prefs[setKey] = next
                    }
                }
        }
    }

    suspend fun hasPrivateKey(pubkeyHex: String): Boolean =
        store.data.first().contains(privateKeyKey(pubkeyHex))

    /**
     * Whether the blob stored for [pubkeyHex] can actually be recovered. This
     * PROBES the same candidate keys [retrievePrivateKey] would use and returns
     * true only when a present key actually opens the blob — NOT a bare
     * key-presence check, which reported a stranded/sibling-alias blob "healthy"
     * merely because an unrelated key of the right shape existed
     * (dashpay/platform#4060, finding e17e265dc680), so `WalletKeyHealthSheet`
     * never offered the re-derive/repair path this check exists to drive.
     *
     * The probe never prompts: [KeystoreManager.decrypt] /
     * [KeystoreManager.decryptLegacyRsaKeysBlob] / [KeystoreManager.decryptLegacyKeysBlob]
     * are bare Cipher operations — the biometric prompt is driven only by
     * `KeystoreSigner`/`BiometricGate`, never here. An auth-gated key whose auth
     * window is closed therefore throws `UserNotAuthenticatedException` (rather
     * than showing UI), which counts as DECRYPTABLE: the key is present and the
     * value would recover after the user authenticates, so a health check must not
     * report it strandable. Only a wrong-key crypto failure (BadPadding / AEAD tag)
     * or an absent key yields "not decryptable". Recovered plaintext is scrubbed
     * immediately — a health check must not leave key bytes on the heap.
     *
     *  - **Legacy AES-GCM** blob (non-empty IV): probe [KeystoreManager.decryptLegacyKeysBlob].
     *  - **Empty-IV RSA** blob: first let a prompt-free DEVICE_BOUND sibling
     *    DISPROVE ownership (see below), then probe the current policy alias
     *    (only if provisioned — an unprovisioned alias can't have written it),
     *    then the retained former KEYS_ALIAS RSA keypair. A structurally non-RSA
     *    blob is not decryptable.
     *
     * **AUTH_GATED residual (dashpay/platform#4060, finding b80a15c93339).** A
     * locked auth-gated alias throws `UserNotAuthenticatedException` at
     * `cipher.init` — before the ciphertext is examined — so a bare catch cannot
     * tell a locked *legitimate owner* from a locked *wrong* alias, and would
     * mis-report a sibling-written blob as decryptable. The prompt-free
     * DEVICE_BOUND sibling ([KeystoreManager.opensUnderNonGatedDeviceBoundSibling])
     * resolves the common case: if that non-gated sibling opens the blob, the
     * current (auth-gated) policy alias does NOT own it, and since
     * [retrievePrivateKey] never falls back to the sibling the blob is genuinely
     * strandable → `false` (drives the re-derive/repair path). The irreducible
     * residual is the symmetric one — a locked auth-gated FORMER RSA key at
     * KEYS_ALIAS whose ownership can't be disproved prompt-free: it is still
     * reported decryptable until the first real unlock surfaces the BadPadding,
     * at which point [retrievePrivateKey]'s fallback→null drives the same repair.
     */
    suspend fun isPrivateKeyDecryptable(pubkeyHex: String): Boolean {
        val encoded = store.data.first()[privateKeyKey(pubkeyHex)] ?: return false
        val blob = decode(encoded)
        return when {
            keystore.isLegacyKeysBlob(blob) ->
                probeOpensBlob { keystore.decryptLegacyKeysBlob(blob) }
            !keystore.isKeysBlobDecryptable(blob) -> false
            // A prompt-free sibling proves the blob belongs to the non-gated
            // DEVICE_BOUND alias, not the current (auth-gated, possibly locked)
            // policy alias — and retrieve never tries the sibling — so it is
            // unrecoverable here (finding b80a15c93339).
            keystore.opensUnderNonGatedDeviceBoundSibling(blob) -> false
            else ->
                (keystore.hasIdentityKeysKey(keystore.keysAlias) &&
                    probeOpensBlob { keystore.decrypt(blob, keystore.keysAlias) }) ||
                    (keystore.hasLegacyRsaKeysKey() &&
                        probeOpensBlob { keystore.decryptLegacyRsaKeysBlob(blob) })
        }
    }

    /**
     * True iff [decrypt] recovers [blob] with a PRESENT key (plaintext scrubbed
     * immediately), or the key is auth-gated with a closed window
     * (`UserNotAuthenticatedException` — present and would recover after auth, so
     * decryptable). A wrong-key crypto failure or an absent key (`null`) is false.
     * Prompt-free by construction — see [isPrivateKeyDecryptable]. Used only by the
     * non-prompting key-health probe, never on a signing path.
     */
    private fun probeOpensBlob(decrypt: () -> ByteArray?): Boolean =
        try {
            val plain = decrypt()
            if (plain != null) {
                plain.fill(0)
                true
            } else {
                false
            }
        } catch (e: UserNotAuthenticatedException) {
            true
        } catch (e: GeneralSecurityException) {
            false
        }

    /** All entry names (masked listing for the Keystore Explorer screen). */
    suspend fun listEntryNames(): List<String> =
        store.data.first().asMap().keys.map { it.name }.sorted()

    suspend fun deleteAll() {
        // Clears privkey.* entries too — take the same exclusion as the
        // targeted mutators so it can't interleave with a compound sweep.
        privateKeyMutex.withLock {
            store.edit { it.clear() }
        }
    }

    private fun mnemonicKey(walletId: ByteArray) =
        stringPreferencesKey(MNEMONIC_PREFIX + walletId.toHex())

    private fun privateKeyKey(pubkeyHex: String) =
        stringPreferencesKey(PRIVKEY_PREFIX + pubkeyHex.lowercase())

    private fun privateKeyFingerprintKey(pubkeyHex: String) =
        stringPreferencesKey(PRIVKEY_FINGERPRINT_PREFIX + pubkeyHex.lowercase())

    private fun ownerIndexKey(walletIdHex: String) =
        stringSetPreferencesKey(PRIVKEY_OWNERS_PREFIX + walletIdHex.lowercase())

    private fun encode(blob: KeystoreManager.EncryptedBlob): String =
        Base64.getEncoder().encodeToString(blob.encode())

    private fun decode(value: String): KeystoreManager.EncryptedBlob =
        KeystoreManager.EncryptedBlob.decode(Base64.getDecoder().decode(value))

    private companion object {
        const val MNEMONIC_PREFIX = "mnemonic."
        const val PRIVKEY_PREFIX = "privkey."

        /** Per-alias [KeystoreManager.keysAliasFingerprint] snapshot, taken at write time. */
        const val PRIVKEY_FINGERPRINT_PREFIX = "privkeyfp."

        /** Durable wallet → alias-hex-set owner index (string-set entries). */
        const val PRIVKEY_OWNERS_PREFIX = "privkeyowners."

        fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

        /**
         * A prompt-free probe of whether the device currently has a secure lock
         * screen (`KeyguardManager.isDeviceSecure`), captured against the
         * application context so it re-reads live state at each key generation
         * (a lock can be added/removed at any time). Handed to [KeystoreManager]
         * so it can drop the lock-screen-bound key-gen parameters when no lock is
         * configured — the wallet must work without a screen lock
         * (dashpay/platform#4060).
         */
        fun deviceSecureProbe(context: Context): () -> Boolean {
            val appContext = context.applicationContext
            return {
                (appContext.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager)
                    ?.isDeviceSecure == true
            }
        }
    }
}
