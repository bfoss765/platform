package org.dashfoundation.dashsdk.security

import android.content.Context
import android.security.keystore.UserNotAuthenticatedException
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.first
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
 * The identity-key security policy is fixed by the [keystore] this storage
 * wraps; use the policy-taking constructor to opt into
 * [KeySecurityPolicy.DEVICE_BOUND] (see [KeySecurityPolicy] for the
 * semantics and the stability requirement). The default is the historical
 * [KeySecurityPolicy.AUTH_GATED] behavior, unchanged.
 */
class WalletStorage(
    context: Context,
    private val keystore: KeystoreManager = KeystoreManager(),
) {
    /**
     * Construct with an explicit identity-key [keySecurityPolicy] —
     * convenience for host apps that don't otherwise need to touch
     * [KeystoreManager]. `WalletStorage(context)` keeps the
     * [KeySecurityPolicy.AUTH_GATED] default.
     */
    constructor(context: Context, keySecurityPolicy: KeySecurityPolicy) :
        this(context, KeystoreManager(keySecurityPolicy))

    private val store = context.secretsStore

    /** The identity-key security policy this storage was constructed with. */
    val keySecurityPolicy: KeySecurityPolicy get() = keystore.keySecurityPolicy

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
    suspend fun storePrivateKey(pubkeyHex: String, privateKey: ByteArray) {
        val blob = keystore.encrypt(privateKey, alias = keystore.keysAlias)
        store.edit { it[privateKeyKey(pubkeyHex)] = encode(blob) }
    }

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
            migrateToPolicyAlias(pubkeyHex, plain)
            return plain
        }
        // Empty-IV RSA blob: encrypted under EITHER the current policy alias
        // (steady state) or the former RSA keypair still at KEYS_ALIAS (scheme 2
        // blobs written before the alias split, dashpay/platform#4060).
        //
        // Upgrade fast path: when the policy alias has no keypair yet it cannot
        // have encrypted this blob, so if the former RSA key is present the blob
        // is unambiguously a scheme-2 blob — recover with it directly instead of
        // provisioning a throwaway policy keypair only to fail. (In steady state
        // the policy alias HAS a key, so this short-circuits without the second
        // Keystore probe.)
        if (!keystore.hasIdentityKeysKey(keystore.keysAlias) && keystore.hasLegacyRsaKeysKey()) {
            val recovered = keystore.decryptLegacyRsaKeysBlob(blob) ?: return null
            migrateToPolicyAlias(pubkeyHex, recovered)
            return recovered
        }
        // Otherwise try the current policy alias first; on a wrong-key crypto
        // failure (a scheme-2 blob lingering while newer keys already live at
        // the policy alias) fall back to the former RSA keypair and migrate.
        // UserNotAuthenticatedException is NOT a wrong-key signal — it must
        // propagate so KeystoreSigner can prompt and retry.
        return try {
            keystore.decrypt(blob, alias = keystore.keysAlias)
        } catch (e: UserNotAuthenticatedException) {
            throw e
        } catch (e: GeneralSecurityException) {
            val recovered = keystore.decryptLegacyRsaKeysBlob(blob) ?: throw e
            migrateToPolicyAlias(pubkeyHex, recovered)
            recovered
        }
    }

    /**
     * Best-effort re-encrypt [plain] under the current policy alias
     * ([KeystoreManager.keysAlias], a never-auth-gated public-key encrypt) and
     * rewrite the stored blob, migrating a recovered legacy value forward. A
     * rewrite failure must not lose the value the caller just recovered, so this
     * stays best-effort (migration retries on the next read).
     */
    private suspend fun migrateToPolicyAlias(pubkeyHex: String, plain: ByteArray) {
        runCatching {
            val migrated = keystore.encrypt(plain, alias = keystore.keysAlias)
            store.edit { it[privateKeyKey(pubkeyHex)] = encode(migrated) }
        }
    }

    suspend fun deletePrivateKey(pubkeyHex: String) {
        store.edit { it.remove(privateKeyKey(pubkeyHex)) }
    }

    suspend fun hasPrivateKey(pubkeyHex: String): Boolean =
        store.data.first().contains(privateKeyKey(pubkeyHex))

    /**
     * Whether the blob stored for [pubkeyHex] can actually be recovered — a
     * structural + Keystore-presence check (never decrypts, never prompts) that
     * reflects real decryptability, not blob shape alone:
     *  - **Legacy AES-GCM** blob (non-empty IV): recoverable iff the retained
     *    legacy AES key still exists ([KeystoreManager.hasLegacyKeysKey]).
     *  - **Empty-IV RSA** blob: recoverable iff SOME present RSA private key can
     *    open it — the current policy alias's key
     *    ([KeystoreManager.hasIdentityKeysKey]) or the retained former
     *    KEYS_ALIAS keypair used as the migration fallback
     *    ([KeystoreManager.hasLegacyRsaKeysKey], dashpay/platform#4060). A
     *    correctly-shaped RSA blob whose keys were all deleted by an older build
     *    is stranded, so shape is NOT sufficient.
     * An unrecoverable blob is treated by key-health as missing and offers a
     * re-derive.
     */
    suspend fun isPrivateKeyDecryptable(pubkeyHex: String): Boolean {
        val encoded = store.data.first()[privateKeyKey(pubkeyHex)] ?: return false
        val blob = decode(encoded)
        if (keystore.isLegacyKeysBlob(blob)) {
            return keystore.hasLegacyKeysKey()
        }
        return keystore.isKeysBlobDecryptable(blob) &&
            (keystore.hasIdentityKeysKey(keystore.keysAlias) || keystore.hasLegacyRsaKeysKey())
    }

    /** All entry names (masked listing for the Keystore Explorer screen). */
    suspend fun listEntryNames(): List<String> =
        store.data.first().asMap().keys.map { it.name }.sorted()

    suspend fun deleteAll() {
        store.edit { it.clear() }
    }

    private fun mnemonicKey(walletId: ByteArray) =
        stringPreferencesKey(MNEMONIC_PREFIX + walletId.toHex())

    private fun privateKeyKey(pubkeyHex: String) =
        stringPreferencesKey(PRIVKEY_PREFIX + pubkeyHex.lowercase())

    private fun encode(blob: KeystoreManager.EncryptedBlob): String =
        Base64.getEncoder().encodeToString(blob.encode())

    private fun decode(value: String): KeystoreManager.EncryptedBlob =
        KeystoreManager.EncryptedBlob.decode(Base64.getDecoder().decode(value))

    private companion object {
        const val MNEMONIC_PREFIX = "mnemonic."
        const val PRIVKEY_PREFIX = "privkey."

        fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
    }
}
