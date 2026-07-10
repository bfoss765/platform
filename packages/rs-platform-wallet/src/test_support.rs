//! Shared unit-test scaffolding: mock broadcasters, a seed-backed signer,
//! and a funded in-memory wallet manager.
//!
//! Used by the broadcast-failure regression tests in `wallet::core::broadcast`
//! and `wallet::asset_lock::build`.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use dashcore::hashes::Hash;
use dashcore::secp256k1::{ecdsa, Message, PublicKey, Secp256k1};
use dashcore::BlockHash;
use dashcore::{Network, OutPoint, Transaction, TxOut, Txid};
use key_wallet::account::account_type::StandardAccountType;
use key_wallet::bip32::ExtendedPubKey;
use key_wallet::signer::{ExtendedPubKeySigner, Signer, SignerMethod};
use key_wallet::test_utils::TestWalletContext;
use key_wallet::transaction_checking::{BlockInfo, TransactionContext};
use key_wallet::{DerivationPath, Utxo, Wallet};
use key_wallet_manager::WalletManager;
use tokio::sync::RwLock;

use crate::broadcaster::{BroadcastError, TransactionBroadcaster};
use crate::wallet::core::WalletBalance;
use crate::wallet::identity::IdentityManager;
use crate::wallet::platform_wallet::{PlatformWalletInfo, WalletId};

/// Broadcaster whose first call fails with a definitive pre-send rejection
/// and which succeeds afterwards, to model a transient broadcast error
/// followed by a user retry.
pub(crate) struct RejectFirstBroadcaster {
    failed_once: AtomicBool,
}

impl RejectFirstBroadcaster {
    pub(crate) fn new() -> Self {
        Self {
            failed_once: AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl TransactionBroadcaster for RejectFirstBroadcaster {
    async fn broadcast(&self, transaction: &Transaction) -> Result<Txid, BroadcastError> {
        if self.failed_once.swap(true, Ordering::SeqCst) {
            Ok(transaction.txid())
        } else {
            Err(BroadcastError::Rejected {
                reason: "simulated pre-send rejection".to_string(),
            })
        }
    }
}

/// Broadcaster that always fails with a definitive pre-send rejection.
pub(crate) struct AlwaysRejectedBroadcaster;

#[async_trait]
impl TransactionBroadcaster for AlwaysRejectedBroadcaster {
    async fn broadcast(&self, _transaction: &Transaction) -> Result<Txid, BroadcastError> {
        Err(BroadcastError::Rejected {
            reason: "simulated pre-send rejection".to_string(),
        })
    }
}

/// Broadcaster that always fails with an *ambiguous* result — the network
/// may already have accepted the transaction — so its inputs must NOT be
/// released on failure.
pub(crate) struct AlwaysMaybeSentBroadcaster;

#[async_trait]
impl TransactionBroadcaster for AlwaysMaybeSentBroadcaster {
    async fn broadcast(&self, _transaction: &Transaction) -> Result<Txid, BroadcastError> {
        Err(BroadcastError::MaybeSent {
            reason: "simulated ambiguous broadcast".to_string(),
        })
    }
}

/// Soft signer that derives keys straight from a test wallet's seed. Stands
/// in for the FFI keychain-backed signer used in production.
pub(crate) struct WalletSigner {
    wallet: Wallet,
}

#[async_trait]
impl Signer for WalletSigner {
    type Error = String;

    fn supported_methods(&self) -> &[SignerMethod] {
        &[SignerMethod::Digest]
    }

    async fn sign_ecdsa(
        &self,
        path: &DerivationPath,
        sighash: [u8; 32],
    ) -> Result<(ecdsa::Signature, PublicKey), Self::Error> {
        let secp = Secp256k1::new();
        let key = self
            .wallet
            .derive_private_key(path)
            .map_err(|e| e.to_string())?;
        let message = Message::from_digest(sighash);
        Ok((
            secp.sign_ecdsa(&message, &key),
            PublicKey::from_secret_key(&secp, &key),
        ))
    }

    async fn public_key(&self, path: &DerivationPath) -> Result<PublicKey, Self::Error> {
        let secp = Secp256k1::new();
        let key = self
            .wallet
            .derive_private_key(path)
            .map_err(|e| e.to_string())?;
        Ok(PublicKey::from_secret_key(&secp, &key))
    }
}

#[async_trait]
impl ExtendedPubKeySigner for WalletSigner {
    async fn extended_public_key(
        &self,
        path: &DerivationPath,
    ) -> Result<ExtendedPubKey, Self::Error> {
        // The test wallet is full-signable, so it can derive an extended
        // public key at a hardened path from its root xpriv — mirroring
        // what `MnemonicResolverCoreSigner` does via the Keychain mnemonic
        // in production.
        self.wallet
            .derive_extended_public_key(path)
            .map_err(|e| e.to_string())
    }
}

/// Builds a testnet wallet manager whose `account_type`/index-0 account
/// holds a single spendable UTXO (10_000_000 duffs) — the whole balance
/// rides on that one input, so a leaked reservation strands it. Returns
/// the manager, the wallet id, the shared balance handle, and a soft
/// signer over the wallet's seed.
pub(crate) async fn funded_wallet_manager(
    account_type: StandardAccountType,
) -> (
    Arc<RwLock<WalletManager<PlatformWalletInfo>>>,
    WalletId,
    Arc<WalletBalance>,
    WalletSigner,
) {
    let mut ctx = TestWalletContext::new_random();

    // `new_random()` already derives a BIP44 receive address; only the
    // BIP32 arm needs a hand-rolled derivation.
    let receive_address = match account_type {
        StandardAccountType::BIP44Account => ctx.receive_address.clone(),
        StandardAccountType::BIP32Account => {
            let xpub = ctx
                .wallet
                .accounts
                .standard_bip32_accounts
                .get(&0)
                .expect("bip32 account")
                .account_xpub;
            ctx.managed_wallet
                .first_bip32_managed_account_mut()
                .expect("bip32 managed account")
                .next_receive_address(Some(&xpub), true)
                .expect("bip32 receive address")
        }
    };

    let funding_tx = Transaction::dummy(&receive_address, 0..1, &[10_000_000]);
    // Chain-locked funding, not `Mempool`: asset-lock builders only
    // select final (confirmed / InstantSend-locked) inputs since
    // rust-dashcore#836, so a mempool-funded fixture leaves the
    // asset-lock tests with no eligible UTXO.
    let result = ctx
        .check_transaction(
            &funding_tx,
            TransactionContext::InChainLockedBlock(BlockInfo::new(
                1,
                BlockHash::all_zeros(),
                1_700_000_000,
            )),
        )
        .await;
    assert!(
        result.is_relevant,
        "funding tx should be relevant to {account_type:?}"
    );
    assert!(result.is_new_transaction);

    let signer = WalletSigner {
        wallet: ctx.wallet.clone(),
    };

    let balance = Arc::new(WalletBalance::new());
    let info = PlatformWalletInfo {
        core_wallet: ctx.managed_wallet,
        balance: Arc::clone(&balance),
        identity_manager: IdentityManager::new(),
        tracked_asset_locks: BTreeMap::new(),
    };

    let mut wm = WalletManager::<PlatformWalletInfo>::new(Network::Testnet);
    let wallet_id = wm.insert_wallet(ctx.wallet, info).expect("insert wallet");

    (Arc::new(RwLock::new(wm)), wallet_id, balance, signer)
}

/// Builds a testnet wallet manager whose balance is SPLIT across two
/// derivation accounts: BIP44 standard account 0 holds a single spendable
/// UTXO of `bip44_duffs`, and the DIP-9 CoinJoin account 0 holds a single
/// spendable UTXO of `coinjoin_duffs`. Mirrors the live S22/testnet wallet in
/// dashpay/platform#4073 whose ~1.44 DASH of previously-mixed coins sit on the
/// CoinJoin path while only ~0.09 DASH rides on BIP44 — the asset-lock coin
/// selector must span BOTH to shield the union.
///
/// Returns the manager, the wallet id, and a soft signer over the wallet's
/// seed (which can derive keys for BOTH accounts, so per-account signing of a
/// mixed-input asset lock can be exercised end-to-end).
pub(crate) async fn split_funded_wallet_manager(
    bip44_duffs: u64,
    coinjoin_duffs: u64,
) -> (
    Arc<RwLock<WalletManager<PlatformWalletInfo>>>,
    WalletId,
    WalletSigner,
) {
    use key_wallet::managed_account::managed_account_trait::ManagedAccountTrait;

    let mut ctx = TestWalletContext::new_random();

    // Fund BIP44 account 0 (the primary) at its pre-derived receive address.
    let bip44_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[bip44_duffs]);
    let bip44_result = ctx
        .check_transaction(
            &bip44_tx,
            TransactionContext::InChainLockedBlock(BlockInfo::new(
                1,
                BlockHash::all_zeros(),
                1_700_000_000,
            )),
        )
        .await;
    assert!(
        bip44_result.is_relevant && bip44_result.is_new_transaction,
        "BIP44 funding tx should be recognized"
    );

    // Derive a fresh CoinJoin receive address (registering it in the CoinJoin
    // pool so the checker recognizes the funding), then fund CoinJoin account 0.
    let coinjoin_xpub = ctx
        .wallet
        .get_coinjoin_account(0)
        .expect("default wallet has CoinJoin account 0")
        .account_xpub;
    // CoinJoin is a single-pool (non-standard) account, so it derives via
    // `next_address` rather than `next_receive_address`.
    let coinjoin_address = ctx
        .managed_wallet
        .first_coinjoin_managed_account_mut()
        .expect("default wallet has a managed CoinJoin account 0")
        .next_address(Some(&coinjoin_xpub), true)
        .expect("CoinJoin receive address");
    let coinjoin_tx = Transaction::dummy(&coinjoin_address, 0..1, &[coinjoin_duffs]);
    let coinjoin_result = ctx
        .check_transaction(
            &coinjoin_tx,
            TransactionContext::InChainLockedBlock(BlockInfo::new(
                2,
                BlockHash::all_zeros(),
                1_700_000_100,
            )),
        )
        .await;
    assert!(
        coinjoin_result.is_relevant && coinjoin_result.is_new_transaction,
        "CoinJoin funding tx should be recognized"
    );

    let signer = WalletSigner {
        wallet: ctx.wallet.clone(),
    };

    let balance = Arc::new(WalletBalance::new());
    let info = PlatformWalletInfo {
        core_wallet: ctx.managed_wallet,
        balance,
        identity_manager: IdentityManager::new(),
        tracked_asset_locks: BTreeMap::new(),
    };

    let mut wm = WalletManager::<PlatformWalletInfo>::new(Network::Testnet);
    let wallet_id = wm.insert_wallet(ctx.wallet, info).expect("insert wallet");

    (Arc::new(RwLock::new(wm)), wallet_id, signer)
}

/// Like [`split_funded_wallet_manager`] but seeds CoinJoin account 0 with
/// `coinjoin_values.len()` separate spendable UTXOs, each at its own derived
/// CoinJoin address (so the cross-account signer resolver can find a
/// derivation path for every one). Models the many-small-denomination shape a
/// real DIP-9 CoinJoin account carries (0.001 / 0.01 / 0.1 DASH mixing
/// outputs) — the shape that made the asset-lock coin selector blow up
/// on-device when it defaulted to the exponential BranchAndBound subset-sum.
pub(crate) async fn split_funded_wallet_manager_many_coinjoin(
    bip44_duffs: u64,
    coinjoin_values: &[u64],
) -> (
    Arc<RwLock<WalletManager<PlatformWalletInfo>>>,
    WalletId,
    WalletSigner,
) {
    use key_wallet::managed_account::managed_account_trait::ManagedAccountTrait;
    use key_wallet::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;

    let mut ctx = TestWalletContext::new_random();

    // Fund BIP44 account 0 (the primary) at its pre-derived receive address.
    let bip44_tx = Transaction::dummy(&ctx.receive_address, 0..1, &[bip44_duffs]);
    let bip44_result = ctx
        .check_transaction(
            &bip44_tx,
            TransactionContext::InChainLockedBlock(BlockInfo::new(
                1,
                BlockHash::all_zeros(),
                1_700_000_000,
            )),
        )
        .await;
    assert!(
        bip44_result.is_relevant && bip44_result.is_new_transaction,
        "BIP44 funding tx should be recognized"
    );

    // Seed CoinJoin account 0 with one UTXO per requested value, each at a
    // freshly-derived (and thus pool-registered) CoinJoin address so the
    // cross-account resolver can derive its signing key.
    let coinjoin_xpub = ctx
        .wallet
        .get_coinjoin_account(0)
        .expect("default wallet has CoinJoin account 0")
        .account_xpub;
    for (i, &value) in coinjoin_values.iter().enumerate() {
        let address = ctx
            .managed_wallet
            .first_coinjoin_managed_account_mut()
            .expect("default wallet has a managed CoinJoin account 0")
            .next_address(Some(&coinjoin_xpub), true)
            .expect("CoinJoin address");
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([(i as u8).wrapping_add(1); 32]),
            vout: 0,
        };
        let utxo = Utxo {
            outpoint,
            txout: TxOut {
                value,
                script_pubkey: address.script_pubkey(),
            },
            address,
            height: 1,
            is_coinbase: false,
            is_confirmed: true,
            is_instantlocked: false,
            is_locked: false,
            is_trusted: false,
        };
        ctx.managed_wallet
            .accounts
            .coinjoin_accounts
            .get_mut(&0)
            .expect("managed CoinJoin account 0")
            .utxos
            .insert(outpoint, utxo);
    }
    ctx.managed_wallet.update_last_processed_height(1000);

    let signer = WalletSigner {
        wallet: ctx.wallet.clone(),
    };

    let balance = Arc::new(WalletBalance::new());
    let info = PlatformWalletInfo {
        core_wallet: ctx.managed_wallet,
        balance,
        identity_manager: IdentityManager::new(),
        tracked_asset_locks: BTreeMap::new(),
    };

    let mut wm = WalletManager::<PlatformWalletInfo>::new(Network::Testnet);
    let wallet_id = wm.insert_wallet(ctx.wallet, info).expect("insert wallet");

    (Arc::new(RwLock::new(wm)), wallet_id, signer)
}
