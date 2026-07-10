package org.dashfoundation.dashsdk.documents

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.dashfoundation.dashsdk.errors.mapNativeErrors
import org.dashfoundation.dashsdk.ffi.TransactionsNative

/**
 * Document purchase + set-price bridge — port of the document
 * state-transition slice of `ManagedPlatformWallet.swift`
 * (`purchaseDocument(...)`, driven by Swift `DocumentWithPriceView`). Thin
 * wrapper over [TransactionsNative]; no orchestration lives here (see
 * `packages/kotlin-sdk/CLAUDE.md`). Handles are supplied by the caller —
 * `PlatformWalletManager` owns the [signerHandle], `ManagedPlatformWallet`
 * owns the wallet handle.
 *
 * All ids are 32-byte canonical form; [contractId] / [documentId] /
 * [purchaserId] / [ownerId] must decode from base58 or hex before the call.
 */
class DocumentTransactions internal constructor() {

    /**
     * Purchase for-sale [documentId] on [contractId]'s [documentType] for
     * [price] credits, with [purchaserId] as the buyer (and new owner) —
     * signed via [signerHandle] with key [signingKeyId]. Mirrors Swift
     * `ManagedPlatformWallet.purchaseDocument`'s parameter order. Consensus
     * rejects a purchase where the buyer is the current owner — the caller's
     * UI gates against that self-buy case.
     *
     * @return the confirmed document's canonical JSON (now owned by the
     *   purchaser; its 32-byte id is the `$id` field).
     */
    suspend fun purchase(
        walletHandle: Long,
        purchaserId: ByteArray,
        contractId: ByteArray,
        documentType: String,
        documentId: ByteArray,
        price: Long,
        signingKeyId: Int,
        signerHandle: Long,
    ): String = withContext(Dispatchers.IO) {
        require(purchaserId.size == 32) { "purchaserId must be 32 bytes" }
        require(contractId.size == 32) { "contractId must be 32 bytes" }
        require(documentId.size == 32) { "documentId must be 32 bytes" }
        require(price > 0) { "price must be positive, got $price" }
        require(signingKeyId >= 0) { "signingKeyId must be non-negative, got $signingKeyId" }
        mapNativeErrors {
            TransactionsNative.documentPurchase(
                walletHandle,
                purchaserId,
                contractId,
                documentType,
                documentId,
                price,
                signingKeyId,
                signerHandle,
            )
        }
    }

    /**
     * Set (update) the trade price of [documentId] on [contractId]'s
     * [documentType], owned by [ownerId], to [price] credits — signed via
     * [signerHandle] with key [signingKeyId]. Mirrors the set-price flow
     * behind Swift `DocumentWithPriceView`.
     *
     * @return the confirmed document's canonical JSON (now carrying
     *   `$price`).
     */
    suspend fun setPrice(
        walletHandle: Long,
        ownerId: ByteArray,
        contractId: ByteArray,
        documentType: String,
        documentId: ByteArray,
        price: Long,
        signingKeyId: Int,
        signerHandle: Long,
    ): String = withContext(Dispatchers.IO) {
        require(ownerId.size == 32) { "ownerId must be 32 bytes" }
        require(contractId.size == 32) { "contractId must be 32 bytes" }
        require(documentId.size == 32) { "documentId must be 32 bytes" }
        require(price >= 0) { "price must be non-negative, got $price" }
        require(signingKeyId >= 0) { "signingKeyId must be non-negative, got $signingKeyId" }
        mapNativeErrors {
            TransactionsNative.documentSetPrice(
                walletHandle,
                ownerId,
                contractId,
                documentType,
                documentId,
                price,
                signingKeyId,
                signerHandle,
            )
        }
    }

    /**
     * Create + broadcast a new document on [contractId]'s [documentType],
     * owned by [ownerId] — signed via [signerHandle]. Mirrors Swift
     * `ManagedPlatformWallet.createDocument` (driven by `CreateDocumentView`).
     * Unlike [purchase] / [setPrice] there is no `signingKeyId`:
     * `create_document_with_signer` selects an AUTHENTICATION + ECDSA key
     * satisfying the document type's security level from the wallet's
     * `IdentityManager`, so the key never crosses the FFI boundary.
     *
     * @param propertiesJson JSON object keyed by property name (byte-array
     *   fields as hex, identifier fields as base58); `"{}"` for a document
     *   type with no required properties.
     * @return the confirmed document's canonical JSON (now owned by
     *   [ownerId]; its 32-byte id is the `$id` field).
     */
    suspend fun create(
        walletHandle: Long,
        ownerId: ByteArray,
        contractId: ByteArray,
        documentType: String,
        propertiesJson: String,
        signerHandle: Long,
    ): String = withContext(Dispatchers.IO) {
        require(ownerId.size == 32) { "ownerId must be 32 bytes" }
        require(contractId.size == 32) { "contractId must be 32 bytes" }
        mapNativeErrors {
            TransactionsNative.documentCreate(
                walletHandle,
                ownerId,
                contractId,
                documentType,
                propertiesJson,
                signerHandle,
            )
        }
    }

    /**
     * Create + broadcast an ENCRYPTED wallet-contract document (the wire-
     * compatible `txMetadata` shape) on [contractId]'s [documentType], owned by
     * [ownerId] — signed via [signerHandle]. Implements the create half of the
     * legacy `BlockchainIdentity.publishTxMetaData` retirement
     * (dashpay/platform#4086): the SDK derives the identity encryption key,
     * seals [payload] into the legacy `version ‖ IV ‖ AES-256-CBC` blob, and
     * writes `{keyIndex, encryptionKeyIndex, encryptedMetadata}`.
     *
     * Batching stays app-side: the caller serializes its items into [payload]
     * (a protobuf `TxMetadataBatch`) and supplies its own per-document
     * [encryptionKeyIndex] (dash-wallet's `1 + countAllRequests()` counter).
     * The identity encryption key id (the `keyIndex` field) is chosen SDK-side
     * to match the legacy stack, so the key never crosses the FFI boundary.
     *
     * @param encryptionKeyIndex per-document index; non-negative.
     * @param version payload version byte (`1` = protobuf, as the wallet writes).
     * @param payload already-serialized opaque plaintext; the SDK does not
     *   parse it.
     * @return the confirmed document's canonical JSON (its 32-byte id is the
     *   base58 `$id` field).
     */
    suspend fun createEncryptedDocument(
        walletHandle: Long,
        ownerId: ByteArray,
        contractId: ByteArray,
        documentType: String,
        encryptionKeyIndex: Int,
        version: Int,
        payload: ByteArray,
        signerHandle: Long,
    ): String = withContext(Dispatchers.IO) {
        require(ownerId.size == 32) { "ownerId must be 32 bytes" }
        require(contractId.size == 32) { "contractId must be 32 bytes" }
        require(encryptionKeyIndex >= 0) {
            "encryptionKeyIndex must be non-negative, got $encryptionKeyIndex"
        }
        require(version in 0..255) { "version must be in 0..255, got $version" }
        mapNativeErrors {
            TransactionsNative.documentCreateEncrypted(
                walletHandle,
                ownerId,
                contractId,
                documentType,
                encryptionKeyIndex,
                version,
                payload,
                signerHandle,
            )
        }
    }

    /**
     * Fetch + DECRYPT every encrypted wallet-contract document owned by
     * [ownerId] on [contractId]'s [documentType] updated at or after [sinceMs]
     * (epoch-millis). Implements the read half of the legacy
     * `BlockchainIdentity.getTxMetaData(since, key)` retirement
     * (dashpay/platform#4087): the SDK fetches the owner-scoped, since-timestamp
     * documents and decrypts each with the identity's derived key. Documents
     * that fail to decrypt are skipped Rust-side (a bad document never aborts
     * the fetch).
     *
     * @return a JSON array; each element is `{ "id", "ownerId" (base58),
     *   "keyIndex", "encryptionKeyIndex", "version", "updatedAt" (number|null),
     *   "payload" (base64 of the decrypted opaque plaintext) }`. The caller
     *   parses each `payload` itself (a protobuf `TxMetadataBatch` for
     *   `version == 1`) and reconciles memo / taxCategory / exchangeRate /
     *   service / giftCard fields into its local store.
     */
    suspend fun fetchEncryptedDocuments(
        walletHandle: Long,
        ownerId: ByteArray,
        contractId: ByteArray,
        documentType: String,
        sinceMs: Long,
    ): String = withContext(Dispatchers.IO) {
        require(ownerId.size == 32) { "ownerId must be 32 bytes" }
        require(contractId.size == 32) { "contractId must be 32 bytes" }
        require(sinceMs >= 0) { "sinceMs must be non-negative, got $sinceMs" }
        mapNativeErrors {
            TransactionsNative.documentFetchEncrypted(
                walletHandle,
                ownerId,
                contractId,
                documentType,
                sinceMs,
            )
        }
    }
}
