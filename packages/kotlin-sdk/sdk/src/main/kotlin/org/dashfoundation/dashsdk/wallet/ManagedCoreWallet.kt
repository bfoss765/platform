package org.dashfoundation.dashsdk.wallet

import org.dashfoundation.dashsdk.ffi.NativeCleaner
import org.dashfoundation.dashsdk.ffi.WalletManagerNative
import java.util.concurrent.atomic.AtomicLong

/**
 * Core wallet handle for transaction broadcasting — Android port of the
 * transaction surface of Swift's `ManagedCoreWallet`
 * (packages/swift-sdk/.../CoreWallet/ManagedCoreWallet.swift).
 *
 * Obtained via [ManagedPlatformWallet.coreWallet]. Owns the transient
 * core-wallet handle and destroys it (`core_wallet_destroy`) on [close] or a
 * [NativeCleaner] backstop, exactly like the Swift type's `deinit`. Balance /
 * address reads live on other Kotlin paths; this port carries only the
 * broadcast entry point the Core→Core send needs.
 */
class ManagedCoreWallet internal constructor(handle: Long) : AutoCloseable {

    private val handleRef = AtomicLong(handle)
    private val cleanable = NativeCleaner.register(this, HandleCleanup(handleRef))

    private val handle: Long
        get() = handleRef.get().also {
            check(it != 0L) { "ManagedCoreWallet has been closed" }
        }

    /**
     * Broadcast a transaction built by [CoreTransactionBuilder.buildSigned].
     * The funding account captured at build time is forwarded so a definitive
     * broadcast rejection releases the UTXO reservation `buildSigned` took.
     * Returns the txid as a lowercase hex string.
     */
    fun broadcastTransaction(tx: CoreTransaction): String =
        WalletManagerNative.coreWalletBroadcastTransaction(
            handle,
            tx.handle,
            tx.accountType.ffiValue,
            tx.accountIndex,
        )

    /**
     * Build + sign a standard L1 payment funded from the UNION of the wallet's
     * signable funds accounts, WITHOUT broadcasting. Returns the packed native
     * result (`u64 fee, u64 change,` then the signed tx bytes, big-endian) —
     * decoded by [ManagedPlatformWallet.buildSignedPayment]. See that method
     * for the full contract; drive this through it (it serializes concurrent
     * builds), not directly.
     */
    internal fun buildSignedPayment(
        outputsBlob: ByteArray,
        feePerKb: Long,
        coreSignerHandle: Long,
    ): ByteArray =
        WalletManagerNative.coreWalletBuildSignedPayment(
            handle,
            outputsBlob,
            feePerKb,
            coreSignerHandle,
        )

    override fun close() {
        cleanable.clean()
    }

    /** Destroys the transient core handle exactly once. */
    private class HandleCleanup(private val handleRef: AtomicLong) : Runnable {
        override fun run() {
            val handle = handleRef.getAndSet(0)
            if (handle != 0L) {
                WalletManagerNative.coreWalletDestroy(handle)
            }
        }
    }
}
