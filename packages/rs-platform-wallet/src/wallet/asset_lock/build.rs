//! Asset lock transaction building.
//!
//! Contains methods for building asset lock transactions, peeking at funding
//! addresses, and the unified `create_funded_asset_lock_proof` entry point.

use crate::broadcaster::TransactionBroadcaster;
use std::time::Duration;

use dashcore::blockdata::transaction::special_transaction::asset_lock::AssetLockPayload;
use dashcore::blockdata::transaction::special_transaction::TransactionPayload;
use dashcore::Address as DashAddress;
use dashcore::{OutPoint, Transaction, TxOut};
use key_wallet::account::AccountType;
use key_wallet::bip32::DerivationPath;
use key_wallet::managed_account::managed_account_trait::ManagedAccountTrait;
use key_wallet::signer::ExtendedPubKeySigner;
use key_wallet::wallet::managed_wallet_info::asset_lock_builder::{
    AssetLockFundingType, CreditOutputFunding,
};
use key_wallet::wallet::managed_wallet_info::coin_selection::{SelectionError, SelectionStrategy};
use key_wallet::wallet::managed_wallet_info::fee::FeeRate;
use key_wallet::wallet::managed_wallet_info::managed_account_operations::ManagedAccountOperations;
use key_wallet::wallet::managed_wallet_info::transaction_builder::{BuilderError, TransactionBuilder};
use key_wallet::wallet::managed_wallet_info::wallet_info_interface::WalletInfoInterface;
use key_wallet::wallet::managed_wallet_info::ManagedWalletInfo;
use key_wallet::wallet::Wallet;
use key_wallet::Utxo;

use crate::changeset::{
    AccountAddressPoolEntry, AccountRegistrationEntry, PlatformWalletChangeSet,
};
use crate::error::PlatformWalletError;
use crate::wallet::platform_wallet::PlatformWalletInfo;

use super::manager::{AssetLockManager, DEFAULT_FEE_PER_KB};
use super::tracked::{AssetLockStatus, TrackedAssetLock};

// ---------------------------------------------------------------------------
// Asset lock transaction building
// ---------------------------------------------------------------------------

impl<B: TransactionBroadcaster + ?Sized> AssetLockManager<B> {
    /// Build an asset lock transaction using the key-wallet builder.
    ///
    /// Delegates UTXO selection, fee calculation, and signing to
    /// `ManagedWalletInfo::build_asset_lock_with_signer`. The host
    /// never sees a raw credit-output private key — the returned
    /// `DerivationPath` is what the caller hands back to the same
    /// `signer` when the credit output is later consumed on Platform.
    ///
    /// # Arguments
    ///
    /// * `amount_duffs` — Amount to lock in duffs.
    /// * `account_index` — BIP44 account index to select UTXOs from.
    /// * `funding_type` — Which account to derive the one-time key from
    ///   (e.g., `IdentityRegistration`, `IdentityTopUp`).
    /// * `identity_index` — Identity index (used by `IdentityTopUp`, ignored by others).
    /// * `signer` — External signer that produces both the funding-input
    ///   P2PKH signatures and the credit-output public key. For Swift,
    ///   this is typically a
    ///   [`MnemonicResolverCoreSigner`](crate::wallet::asset_lock::build)
    ///   from `platform-wallet-ffi` — built on top of the
    ///   Keychain-resolver vtable so private keys never cross the FFI
    ///   boundary.
    pub async fn build_asset_lock_transaction<S: ExtendedPubKeySigner>(
        &self,
        amount_duffs: u64,
        account_index: u32,
        funding_type: AssetLockFundingType,
        identity_index: u32,
        signer: &S,
    ) -> Result<(Transaction, DerivationPath), PlatformWalletError> {
        if amount_duffs == 0 {
            return Err(PlatformWalletError::AssetLockTransaction(
                "Amount must be greater than zero".to_string(),
            ));
        }

        let mut wm = self.wallet_manager.write().await;
        let (wallet, info) = wm
            .get_wallet_mut_and_info_mut(&self.wallet_id)
            .ok_or_else(|| PlatformWalletError::WalletNotFound(hex::encode(self.wallet_id)))?;

        // 0. For a per-index identity top-up, lazily derive + insert the
        //    `IdentityTopUp { registration_index }` account (both the
        //    xpub-bearing `Wallet.accounts` side and the managed
        //    `ManagedWalletInfo.accounts` side) if it isn't there yet.
        //    Wallet setup only derives the *singleton* special accounts
        //    (identity_registration, etc.); per-index topup accounts are
        //    keyed by the identity's registration index and can't be
        //    enumerated ahead of time, so we derive one on demand here.
        if funding_type == AssetLockFundingType::IdentityTopUp {
            self.ensure_identity_topup_account(wallet, info, identity_index, signer)
                .await?;
        }

        // 1. Peek at the next unused address from the funding account to
        //    build the credit output P2PKH script.
        let funding_address = Self::peek_next_funding_address(
            &mut info.core_wallet,
            wallet,
            funding_type,
            identity_index,
        )?;

        // 2. Build the credit output for the asset lock payload.
        let credit_output = TxOut {
            value: amount_duffs,
            script_pubkey: funding_address.script_pubkey(),
        };

        let funding = CreditOutputFunding {
            output: credit_output,
            funding_type,
            identity_index,
        };

        // 3. Fund the asset lock.
        //
        // Shielded funding (`AssetLockShieldedAddressTopUp`) must be able to
        // draw on previously-mixed CoinJoin coins, which live on the DIP-9
        // CoinJoin derivation account — the pinned key-wallet
        // `build_asset_lock_with_signer` funds from a SINGLE BIP44 account
        // only, so those coins counted in the balance but could not be
        // shielded (dashpay/platform#4073). Route shielded funding through the
        // union-of-accounts builder; every other funding type keeps the
        // single-BIP44-account path (spending mixed CoinJoin coins into an
        // identity registration would de-anonymize them — a deliberate
        // privacy choice left out of scope here).
        if funding_type == AssetLockFundingType::AssetLockShieldedAddressTopUp {
            return self
                .build_asset_lock_tx_from_all_funding_accounts(
                    wallet,
                    info,
                    account_index,
                    vec![funding],
                    DEFAULT_FEE_PER_KB,
                    signer,
                )
                .await;
        }

        // Delegate to the key-wallet signer-driven builder (single BIP44 account).
        let result = info
            .core_wallet
            .build_asset_lock_with_signer(
                wallet,
                account_index,
                vec![funding],
                DEFAULT_FEE_PER_KB,
                signer,
            )
            .await
            .map_err(|e| {
                PlatformWalletError::AssetLockTransaction(format!(
                    "Asset lock builder failed: {}",
                    e
                ))
            })?;

        // 4. Pull the (pubkey, path) for our single credit output.
        //
        // `build_asset_lock_with_signer` always returns the `Public`
        // variant. The `Private` arm would only come from the soft-
        // wallet `build_asset_lock` path which we no longer call from
        // platform-wallet — defensively bail if it appears.
        use key_wallet::wallet::managed_wallet_info::asset_lock_builder::AssetLockCreditKeys;
        let path = match result.keys {
            AssetLockCreditKeys::Public(mut keys) => {
                let (_pubkey, path) = keys.drain(..).next().ok_or_else(|| {
                    PlatformWalletError::AssetLockTransaction(
                        "Builder returned no credit-output keys".to_string(),
                    )
                })?;
                path
            }
            AssetLockCreditKeys::Private(_) => {
                return Err(PlatformWalletError::AssetLockTransaction(
                    "Builder returned Private keys; signer-driven path expected Public".to_string(),
                ));
            }
        };

        Ok((result.transaction, path))
    }

    /// Build + sign an asset-lock transaction whose funding inputs are drawn
    /// from the UNION of every spendable Core funds account (BIP44 + BIP32 +
    /// CoinJoin + DashPay), not just the single BIP44 account at
    /// `account_index`.
    ///
    /// ## Why this exists (dashpay/platform#4073)
    ///
    /// The pinned key-wallet `ManagedWalletInfo::build_asset_lock_with_signer`
    /// funds an asset lock from exactly ONE BIP44 standard account: it calls
    /// `TransactionBuilder::set_funding` on
    /// `standard_bip44_accounts[account_index]` and signs with a
    /// single-account path resolver (`funds_acc.address_derivation_path`).
    /// Previously-mixed CoinJoin coins live on the DIP-9 CoinJoin derivation
    /// account (`coinjoin_accounts`), so they are counted in the wallet
    /// balance (which sums `all_funding_accounts`) yet were invisible to the
    /// asset-lock coin selector — shielding failed with a coin-selection
    /// "Insufficient funds" even though the wallet-wide balance covered the
    /// amount.
    ///
    /// This method keeps `account_index` as the PRIMARY account (its
    /// reservation ledger gates concurrent primary-account builds, and change
    /// flows back to it via `set_funding`'s change address) but ADDS the
    /// spendable UTXOs of every other funds account as explicit builder
    /// inputs (`add_inputs`), and signs with a resolver that spans all funds
    /// accounts. The credit-output key is still derived from the
    /// shielded-topup account exactly as the single-account builder does
    /// (peek path → signer pubkey → mark used), so the returned
    /// `DerivationPath` lines up with the credit-output script the caller
    /// already peeked.
    ///
    /// ## Interim caveat (superseded by the upstream fix)
    ///
    /// The clean long-term fix belongs upstream in key-wallet
    /// (`build_asset_lock_with_signer` gathering inputs + reservations across
    /// accounts). Until that pin bump lands, this workspace composition makes
    /// CoinJoin funds shieldable today. `TransactionBuilder::set_funding`
    /// captures only the PRIMARY account's `ReservationSet` (the type is
    /// `pub(crate)` in key-wallet, so this crate cannot reserve per-account),
    /// so inputs selected from non-primary accounts are recorded in the
    /// primary account's reservation ledger rather than their own. They are
    /// therefore not protected against a concurrent build on their own
    /// account for the brief window before the broadcast tx is processed back
    /// into the wallet (which releases the outpoints from every account's
    /// ledger). Shielded funding is single-flighted under `shield_guard` and
    /// the whole build runs under the wallet write lock, and the app issues no
    /// concurrent non-shielded spend on the CoinJoin/BIP32 accounts, so the
    /// race window is not reachable in practice.
    async fn build_asset_lock_tx_from_all_funding_accounts<S: ExtendedPubKeySigner>(
        &self,
        wallet: &Wallet,
        info: &mut PlatformWalletInfo,
        account_index: u32,
        credit_output_fundings: Vec<CreditOutputFunding>,
        fee_per_kb: u64,
        signer: &S,
    ) -> Result<(Transaction, DerivationPath), PlatformWalletError> {
        use std::collections::{HashMap, HashSet};

        let target_duffs: u64 = credit_output_fundings.iter().map(|f| f.output.value).sum();
        let height = info.core_wallet.last_processed_height();
        tracing::debug!(
            target_duffs,
            height,
            primary_account_index = account_index,
            funding_accounts = info.core_wallet.accounts.all_funding_accounts().len(),
            "multi-account asset-lock funding: enumerating spendable funds accounts"
        );

        // Snapshot the primary account's spendable outpoints so the union
        // sweep below does not add them twice: `set_funding` already seeds
        // them, and `add_inputs` must contribute only the OTHER accounts.
        let primary_outpoints: HashSet<OutPoint> = info
            .core_wallet
            .accounts
            .standard_bip44_accounts
            .get(&account_index)
            .map(|a| {
                a.spendable_utxos(height)
                    .into_iter()
                    .map(|u| u.outpoint)
                    .collect()
            })
            .unwrap_or_default();

        // Build, from an immutable borrow of every funds account:
        //   (a) an owned `Address -> DerivationPath` resolver covering every
        //       spendable input across ALL accounts, so signing can resolve a
        //       key for an input selected from any account; and
        //   (b) the explicit extra inputs (all non-primary accounts).
        let mut path_map: HashMap<DashAddress, DerivationPath> = HashMap::new();
        let mut extra_inputs: Vec<Utxo> = Vec::new();
        let mut union_value: u64 = 0;
        let mut union_count: usize = 0;
        for acc in info.core_wallet.accounts.all_funding_accounts() {
            for utxo in acc.spendable_utxos(height) {
                union_value = union_value.saturating_add(utxo.value());
                union_count += 1;
                if let Some(path) = acc.address_derivation_path(&utxo.address) {
                    path_map.insert(utxo.address.clone(), path);
                }
                if !primary_outpoints.contains(&utxo.outpoint) {
                    extra_inputs.push(utxo.clone());
                }
            }
        }
        tracing::debug!(
            union_count,
            union_value,
            primary_count = primary_outpoints.len(),
            extra_count = extra_inputs.len(),
            resolver_entries = path_map.len(),
            "multi-account asset-lock funding: union UTXO set assembled"
        );

        let acc = wallet
            .get_bip44_account(account_index)
            .ok_or_else(|| {
                PlatformWalletError::AssetLockTransaction(format!(
                    "BIP44 account {account_index} not found for asset-lock funding"
                ))
            })?
            .clone();
        let credit_outputs: Vec<TxOut> =
            credit_output_fundings.iter().map(|f| f.output.clone()).collect();

        // Seed the primary account (inputs + change address + reservations),
        // then append the union of the other accounts' spendable inputs. The
        // `&mut` borrow of the primary account is scoped to this block; the
        // returned builder owns cloned inputs / reservations / change address,
        // so no account borrow is held across the signer await below.
        let builder = {
            let primary_funds = info
                .core_wallet
                .accounts
                .standard_bip44_accounts
                .get_mut(&account_index)
                .ok_or_else(|| {
                    PlatformWalletError::AssetLockTransaction(format!(
                        "managed BIP44 account {account_index} not found for asset-lock funding"
                    ))
                })?;
            TransactionBuilder::new()
                .set_fee_rate(FeeRate::new(fee_per_kb))
                .set_current_height(height)
                // LargestFirst, NOT the `TransactionBuilder::new()` default
                // `BranchAndBound`. This is load-bearing, not an optimization:
                // BranchAndBound routes to a recursive exact-match subset-sum
                // (`CoinSelector::find_exact_match`) whose search space is
                // EXPONENTIAL in the number of sub-target UTXOs. The
                // single-BIP44-account path tolerates it (a handful of UTXOs),
                // but a CoinJoin account holds many small mixed denominations
                // (0.001 / 0.01 / 0.1 DASH ...); feeding that whole set to
                // BranchAndBound hangs the FFI call for minutes with no logs and
                // no broadcast (observed on-device, dashpay/platform#4073
                // follow-up). LargestFirst uses the linear greedy accumulator
                // (`accumulate_coins_with_size`), which also minimizes the input
                // count — fewer signer round-trips (each input is one resolver
                // upcall) and a smaller tx/fee.
                .set_selection_strategy(SelectionStrategy::LargestFirst)
                .set_special_payload(TransactionPayload::AssetLockPayloadType(
                    AssetLockPayload::new(credit_outputs),
                ))
                .set_funding(primary_funds, &acc)
                .add_inputs(extra_inputs)
                .require_final_inputs()
        };

        tracing::debug!(
            target_duffs,
            "multi-account asset-lock funding: selecting + signing (LargestFirst)"
        );
        let (transaction, fee) = builder
            .build_signed(signer, move |addr| path_map.get(&addr).cloned())
            .await
            .map_err(map_builder_error)?;
        tracing::debug!(
            selected_inputs = transaction.input.len(),
            fee,
            txid = %transaction.txid(),
            "multi-account asset-lock funding: transaction built + signed"
        );

        // Derive the single credit-output key from the shielded-topup account,
        // mirroring the pinned single-account builder's phase-1/2/3 sequence
        // (peek without marking → signer round-trip → commit the index) so a
        // signer failure never irreversibly consumes a pool index.
        let (path, index) = {
            let credit_account = info
                .core_wallet
                .accounts
                .asset_lock_shielded_address_topup
                .as_mut()
                .ok_or_else(|| {
                    PlatformWalletError::AssetLockTransaction(
                        "Asset lock shielded address top-up account not found".to_string(),
                    )
                })?;
            credit_account
                .peek_next_path()
                .map_err(|e| PlatformWalletError::AssetLockTransaction(e.to_string()))?
        };
        signer.public_key(&path).await.map_err(|e| {
            PlatformWalletError::AssetLockTransaction(format!("signer public_key failed: {e}"))
        })?;
        {
            let credit_account = info
                .core_wallet
                .accounts
                .asset_lock_shielded_address_topup
                .as_mut()
                .ok_or_else(|| {
                    PlatformWalletError::AssetLockTransaction(
                        "Asset lock shielded address top-up account not found".to_string(),
                    )
                })?;
            credit_account
                .mark_first_pool_index_used(index)
                .map_err(|e| PlatformWalletError::AssetLockTransaction(e.to_string()))?;
        }

        tracing::debug!(
            selected_inputs = transaction.input.len(),
            "multi-account asset-lock funding: credit-output key derived; returning built tx"
        );
        Ok((transaction, path))
    }

    /// Peek at the next unused address from a funding account without
    /// consuming it (i.e. without marking it as used).
    ///
    /// The key-wallet builder's `next_private_key` will later find the same
    /// address, derive the private key, and mark it as used.
    fn peek_next_funding_address(
        wallet_info: &mut ManagedWalletInfo,
        wallet: &Wallet,
        funding_type: AssetLockFundingType,
        identity_index: u32,
    ) -> Result<DashAddress, PlatformWalletError> {
        let (managed_account, account_xpub) = match funding_type {
            AssetLockFundingType::IdentityRegistration => {
                let xpub = wallet
                    .accounts
                    .identity_registration
                    .as_ref()
                    .map(|a| a.account_xpub);
                let account = wallet_info
                    .accounts
                    .identity_registration
                    .as_mut()
                    .ok_or_else(|| {
                        PlatformWalletError::AssetLockTransaction(
                            "Identity registration account not found".to_string(),
                        )
                    })?;
                (account, xpub)
            }
            AssetLockFundingType::IdentityTopUp => {
                let xpub = wallet
                    .accounts
                    .identity_topup
                    .get(&identity_index)
                    .map(|a| a.account_xpub);
                let account = wallet_info
                    .accounts
                    .identity_topup
                    .get_mut(&identity_index)
                    .ok_or_else(|| {
                        PlatformWalletError::AssetLockTransaction(format!(
                            "Identity top-up account for index {} not found",
                            identity_index
                        ))
                    })?;
                (account, xpub)
            }
            AssetLockFundingType::IdentityTopUpNotBound => {
                let xpub = wallet
                    .accounts
                    .identity_topup_not_bound
                    .as_ref()
                    .map(|a| a.account_xpub);
                let account = wallet_info
                    .accounts
                    .identity_topup_not_bound
                    .as_mut()
                    .ok_or_else(|| {
                        PlatformWalletError::AssetLockTransaction(
                            "Identity top-up (unbound) account not found".to_string(),
                        )
                    })?;
                (account, xpub)
            }
            AssetLockFundingType::IdentityInvitation => {
                let xpub = wallet
                    .accounts
                    .identity_invitation
                    .as_ref()
                    .map(|a| a.account_xpub);
                let account = wallet_info
                    .accounts
                    .identity_invitation
                    .as_mut()
                    .ok_or_else(|| {
                        PlatformWalletError::AssetLockTransaction(
                            "Identity invitation account not found".to_string(),
                        )
                    })?;
                (account, xpub)
            }
            AssetLockFundingType::AssetLockAddressTopUp => {
                let xpub = wallet
                    .accounts
                    .asset_lock_address_topup
                    .as_ref()
                    .map(|a| a.account_xpub);
                let account = wallet_info
                    .accounts
                    .asset_lock_address_topup
                    .as_mut()
                    .ok_or_else(|| {
                        PlatformWalletError::AssetLockTransaction(
                            "Asset lock address top-up account not found".to_string(),
                        )
                    })?;
                (account, xpub)
            }
            AssetLockFundingType::AssetLockShieldedAddressTopUp => {
                let xpub = wallet
                    .accounts
                    .asset_lock_shielded_address_topup
                    .as_ref()
                    .map(|a| a.account_xpub);
                let account = wallet_info
                    .accounts
                    .asset_lock_shielded_address_topup
                    .as_mut()
                    .ok_or_else(|| {
                        PlatformWalletError::AssetLockTransaction(
                            "Asset lock shielded address top-up account not found".to_string(),
                        )
                    })?;
                (account, xpub)
            }
        };

        // Get the next unused address from the pool. `next_address`
        // always persists the newly-generated address into the pool's
        // state so the builder's `next_private_key` can find it. The
        // address is NOT marked as used yet — that happens inside the
        // builder after a successful transaction build.
        managed_account
            .next_address(account_xpub.as_ref(), false)
            .map_err(|e| {
                PlatformWalletError::AssetLockTransaction(format!(
                    "Failed to get next funding address: {}",
                    e
                ))
            })
    }

    /// Idempotently derive + insert the per-index `IdentityTopUp`
    /// derivation account into BOTH the xpub-bearing `Wallet.accounts`
    /// and the managed `ManagedWalletInfo.accounts`, and persist its
    /// registration.
    ///
    /// Wallet setup (`create_special_purpose_accounts`) only derives the
    /// *singleton* special accounts (`identity_registration`, etc.);
    /// per-index topup accounts are keyed by the identity's registration
    /// index, so we derive one on demand the first time a given identity
    /// is topped up. Safe to call on every build / retry: existing
    /// accounts are left untouched by the `contains_*` guards.
    ///
    /// ## Persistence
    ///
    /// A newly created account is persisted as an
    /// [`AccountRegistrationEntry`] plus its initial address-pool
    /// snapshot(s) — the same round shape `manager::wallet_lifecycle`
    /// emits at wallet registration — before this method returns. This
    /// is load-bearing for crash recovery: the load path rebuilds
    /// `Wallet.accounts` from persisted registrations only (the
    /// `account_registrations` / `account_address_pools` changeset
    /// fields are not replayed by `apply_changeset`), so without this
    /// round a restart between broadcast and consumption leaves
    /// `resume_asset_lock` unable to re-derive the credit-output path
    /// ("Funding account IdentityTopUp not found for re-derivation")
    /// and the already-broadcast top-up stranded. Re-deriving the
    /// account at resume time instead is not an option: the hardened
    /// topup xpub needs the external signer on production wallets, and
    /// `resume_asset_lock` (and the FFI launch-time catch-up that
    /// drives it) runs without one.
    ///
    /// A failed store rolls back the in-memory inserts, so a later
    /// retry re-creates AND re-persists the account instead of the
    /// `contains_*` guards skipping a persist that never happened.
    ///
    /// ## Two derivation paths
    ///
    /// The production platform wallet is **external-signable**: at
    /// registration it is `downgrade_to_external_signable()`'d and holds
    /// only account xpubs — no root xpriv/seed (that lives behind the
    /// Swift Keychain, reachable only through the `signer`). The
    /// `IdentityTopUp` derivation path is HARDENED, so the seedless
    /// `Wallet::add_account(_, None)` "derive from root xpriv" path fails
    /// for such wallets. We therefore derive the account xpub through the
    /// `signer` (`ExtendedPubKeySigner::extended_public_key`, which the
    /// `MnemonicResolverCoreSigner` resolves via the Keychain mnemonic) and
    /// insert the resulting xpub explicitly.
    ///
    /// Full-signable wallets (unit tests, in-memory soft wallets) keep the
    /// cheaper local `add_account(_, None)` path — no signer round-trip.
    async fn ensure_identity_topup_account<S: ExtendedPubKeySigner>(
        &self,
        wallet: &mut Wallet,
        info: &mut PlatformWalletInfo,
        identity_index: u32,
        signer: &S,
    ) -> Result<(), PlatformWalletError> {
        let account_type = AccountType::IdentityTopUp {
            registration_index: identity_index,
        };

        // (a) xpub side — insert the account into `Wallet.accounts` if it
        //     isn't there yet.
        let created_xpub_side = !wallet.accounts.contains_account_type(&account_type);
        if created_xpub_side {
            // NOTE: gate on `is_external_signable()`, NOT `can_sign()` —
            // `can_sign()` is `!watch_only`, so it's TRUE for external-signable
            // wallets (they CAN sign, just via the external signer), which
            // would wrongly take the local `add_account(_, None)` path and fail
            // with "External signable wallet has no private key".
            if !wallet.is_external_signable() {
                // Full-signable wallet (tests / soft wallets): derive the
                // account xpub locally from the wallet's root xpriv.
                wallet.add_account(account_type, None).map_err(|e| {
                    PlatformWalletError::AssetLockTransaction(format!(
                        "Failed to derive identity top-up account for index {}: {}",
                        identity_index, e
                    ))
                })?;
            } else {
                // External-signable wallet (production): no root key at
                // rest — derive the hardened account xpub through the
                // external signer, then insert it explicitly.
                let path = account_type.derivation_path(wallet.network).map_err(|e| {
                    PlatformWalletError::AssetLockTransaction(format!(
                        "Failed to compute identity top-up derivation path for index {}: {}",
                        identity_index, e
                    ))
                })?;
                let account_xpub = signer.extended_public_key(&path).await.map_err(|e| {
                    PlatformWalletError::AssetLockTransaction(format!(
                        "Failed to derive identity top-up account xpub for index {} via signer: {}",
                        identity_index, e
                    ))
                })?;
                wallet
                    .add_account(account_type, Some(account_xpub))
                    .map_err(|e| {
                        PlatformWalletError::AssetLockTransaction(format!(
                            "Failed to add identity top-up account for index {}: {}",
                            identity_index, e
                        ))
                    })?;
            }
        }

        // (b) managed side — mirror the account (keys-bearing, with its
        //     address pool initialized from the xpub) into
        //     `ManagedWalletInfo.accounts.identity_topup`.
        let created_managed_side = !info
            .core_wallet
            .accounts
            .identity_topup
            .contains_key(&identity_index);
        if created_managed_side {
            info.add_managed_account(wallet, account_type)
                .map_err(|e| {
                    PlatformWalletError::AssetLockTransaction(format!(
                        "Failed to register managed identity top-up account for index {}: {}",
                        identity_index, e
                    ))
                })?;
        }

        if !(created_xpub_side || created_managed_side) {
            return Ok(());
        }

        // (c) persist the new account as an `AccountRegistrationEntry`
        //     + initial pool snapshot(s) — the only record the load
        //     path can rebuild the account from (see the method docs).
        let account_xpub = wallet
            .accounts
            .identity_topup
            .get(&identity_index)
            .map(|a| a.account_xpub)
            .ok_or_else(|| {
                PlatformWalletError::AssetLockTransaction(format!(
                    "Identity top-up account for index {} missing after insert",
                    identity_index
                ))
            })?;
        let mut cs = PlatformWalletChangeSet {
            account_registrations: vec![AccountRegistrationEntry {
                account_type,
                account_xpub,
            }],
            ..Default::default()
        };
        if let Some(managed) = info
            .core_wallet
            .accounts
            .identity_topup
            .get(&identity_index)
        {
            for pool in managed.managed_account_type().address_pools() {
                let addresses: Vec<key_wallet::AddressInfo> =
                    pool.addresses.values().cloned().collect();
                if addresses.is_empty() {
                    continue;
                }
                cs.account_address_pools.push(AccountAddressPoolEntry {
                    account_type,
                    pool_type: pool.pool_type,
                    addresses,
                });
            }
        }
        if let Err(e) = self.persister.store(cs) {
            // Roll back whichever sides this call inserted: a resident
            // but unpersisted account would make every retry hit the
            // `contains_*` guards above and skip the persist forever.
            if created_xpub_side {
                wallet.accounts.identity_topup.remove(&identity_index);
            }
            if created_managed_side {
                info.core_wallet
                    .accounts
                    .identity_topup
                    .remove(&identity_index);
            }
            return Err(PlatformWalletError::Persistence(format!(
                "Failed to persist identity top-up account registration for index {}: {}",
                identity_index, e
            )));
        }

        Ok(())
    }

    /// Build, broadcast, and wait for an asset lock proof.
    ///
    /// This is the **unified** entry point for obtaining a funded asset lock
    /// proof, replacing the earlier `create_registration_asset_lock_proof` and
    /// `create_topup_asset_lock_proof` methods.
    ///
    /// ## Flow
    ///
    /// 1. Build the asset lock transaction via the key-wallet
    ///    signer-driven builder.
    /// 2. Track the lifecycle as `Built` (in-memory).
    /// 3. Broadcast the transaction.
    /// 4. Wait for an InstantLock or ChainLock proof via the event channel.
    /// 5. Track the lifecycle as `InstantSendLocked` or `ChainLocked`.
    /// 6. Return `(proof, credit_output_derivation_path, txid)` — the
    ///    caller hands the path back to the same `signer` when
    ///    consuming the credit on Platform.
    ///
    /// ## Persistence
    ///
    /// This method tracks the asset lock in memory before broadcasting, so
    /// the lock is recoverable even if the proof wait is interrupted. However,
    /// the `AssetLockManager` does not persist state directly — **callers MUST
    /// persist the wallet state** after this method returns (or after broadcast
    /// if crash-safety before finality is required). The changeset system
    /// (`AssetLockChangeSet`) will capture the tracked lock state when the
    /// persister flushes.
    ///
    /// ## Parameters
    ///
    /// * `amount_duffs` — Amount to lock.
    /// * `account_index` — BIP44 account index to select UTXOs from.
    /// * `funding_type` — Which account to derive the one-time key from.
    /// * `identity_index` — HD identity index (for `IdentityTopUp`, this is
    ///   the registration index identifying which identity is being topped up).
    /// * `signer` — External ECDSA signer (Swift Keychain-backed in
    ///   production via `MnemonicResolverCoreSigner`).
    pub async fn create_funded_asset_lock_proof<S: ExtendedPubKeySigner>(
        &self,
        amount_duffs: u64,
        account_index: u32,
        funding_type: AssetLockFundingType,
        identity_index: u32,
        signer: &S,
    ) -> Result<(dpp::prelude::AssetLockProof, DerivationPath, OutPoint), PlatformWalletError> {
        // 1. Build the asset lock transaction.
        let (tx, path) = self
            .build_asset_lock_transaction(
                amount_duffs,
                account_index,
                funding_type,
                identity_index,
                signer,
            )
            .await?;

        let txid = tx.txid();
        let out_point = OutPoint::new(txid, 0);

        // 2. Track as Built and queue the changeset onto the persister
        //    so a crash after broadcast leaves a row we can recover from.
        let cs_built = self
            .track_asset_lock(TrackedAssetLock {
                out_point,
                transaction: tx.clone(),
                account_index,
                funding_type,
                identity_index,
                amount: amount_duffs,
                status: AssetLockStatus::Built,
                proof: None,
            })
            .await;
        self.queue_asset_lock_changeset(cs_built);

        tracing::debug!(
            %txid,
            "Asset lock tracked as Built and queued for persistence; broadcasting."
        );

        // 3. Broadcast. On a definitive pre-send rejection, untrack the
        //    `Built` row BEFORE releasing the funding reservation (the
        //    asset-lock builder funds from the BIP44 account at
        //    `account_index`): while the reservation is held the inputs
        //    cannot be re-selected by a new build, and once the row is gone
        //    `resume_asset_lock` can no longer re-drive the rejected
        //    transaction — so at no point is the row resumable while its
        //    inputs are re-spendable. A `MaybeSent` failure keeps both the
        //    reservation and the resumable row.
        if let Err(e) = self.broadcaster.broadcast(&tx).await {
            if matches!(e, crate::broadcaster::BroadcastError::Rejected { .. }) {
                let cs_untrack = self.untrack_asset_lock(&out_point).await;
                // Release only when the Built row was actually removed. If
                // the untrack guard fired instead — a concurrent
                // `resume_asset_lock` advanced the row past `Built`, positive
                // evidence the transaction reached the network after all —
                // the inputs must stay reserved exactly like a `MaybeSent`
                // outcome, or the still-tracked row would be resumable while
                // its inputs are re-spendable.
                let removed_built_row = cs_untrack.removed.contains(&out_point);
                self.queue_asset_lock_changeset(cs_untrack);
                if removed_built_row {
                    crate::wallet::reservations::release_reservation_after_rejected_broadcast(
                        &self.wallet_manager,
                        &self.wallet_id,
                        key_wallet::account::account_type::StandardAccountType::BIP44Account,
                        account_index,
                        &tx,
                    )
                    .await;
                }
            }
            return Err(e.into());
        }

        // 4. Transition to Broadcast and queue the changeset.
        let cs_broadcast = self
            .advance_asset_lock_status(&out_point, AssetLockStatus::Broadcast, None)
            .await?;
        self.queue_asset_lock_changeset(cs_broadcast);

        // 5. Wait for proof via SPV events. The 300s bound is an
        //    InstantSend-preference window, NOT a finality timeout: on
        //    expiry the resolver falls back to an unbounded ChainLock wait
        //    (`upgrade_to_chain_lock_proof(None)`), so a broadcast lock is
        //    never surfaced as "failed" just because IS was slow.
        let proof = self
            .wait_for_proof(&out_point, Some(Duration::from_secs(300)))
            .await?;

        // 5b. If we got an IS-lock proof, check whether the transaction is
        // old enough that Platform might reject it. If so, upgrade to a
        // ChainLock proof proactively.
        let proof = self
            .validate_or_upgrade_proof(proof, account_index, &out_point)
            .await?;

        // 6. Attach proof — status matches the proof type received —
        //    and queue the final changeset.
        let status = match &proof {
            dpp::prelude::AssetLockProof::Instant(_) => AssetLockStatus::InstantSendLocked,
            dpp::prelude::AssetLockProof::Chain(_) => AssetLockStatus::ChainLocked,
        };
        let cs_final = self
            .advance_asset_lock_status(&out_point, status, Some(proof.clone()))
            .await?;
        self.queue_asset_lock_changeset(cs_final);

        Ok((proof, path, out_point))
    }
}

/// Map a key-wallet [`BuilderError`] to a [`PlatformWalletError`], promoting
/// the two shortfall shapes (`BuilderError::InsufficientFunds` and a
/// coin-selection `SelectionError::InsufficientFunds`) to the typed
/// [`PlatformWalletError::AssetLockInsufficientFunds`] so the exact
/// `available`/`required` duff amounts survive instead of being flattened into
/// a string (dashpay/platform#4073's typed-error ask). Every other builder
/// error keeps the generic `AssetLockTransaction` string form.
fn map_builder_error(e: BuilderError) -> PlatformWalletError {
    match e {
        BuilderError::InsufficientFunds {
            available,
            required,
        }
        | BuilderError::CoinSelection(SelectionError::InsufficientFunds {
            available,
            required,
        }) => PlatformWalletError::AssetLockInsufficientFunds {
            available,
            required,
        },
        other => {
            PlatformWalletError::AssetLockTransaction(format!("Asset lock builder failed: {other}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use dashcore::OutPoint;
    use key_wallet::account::account_type::StandardAccountType;
    use tokio::sync::Notify;

    use async_trait::async_trait;
    use dashcore::{Transaction, Txid};
    use key_wallet_manager::WalletManager;
    use tokio::sync::RwLock;

    use crate::broadcaster::{BroadcastError, TransactionBroadcaster};
    use crate::changeset::{
        ClientStartState, PersistenceError, PlatformWalletChangeSet, PlatformWalletPersistence,
    };
    use crate::test_support::{
        funded_wallet_manager, AlwaysMaybeSentBroadcaster, AlwaysRejectedBroadcaster, WalletSigner,
    };
    use crate::wallet::asset_lock::manager::AssetLockManager;
    use crate::wallet::asset_lock::tracked::AssetLockStatus;
    use crate::wallet::persister::WalletPersister;
    use crate::wallet::platform_wallet::PlatformWalletInfo;
    use crate::wallet::platform_wallet::WalletId;
    use crate::{AssetLockFundingType, PlatformWalletError};

    /// Persistence stub that records every stored changeset so tests can
    /// assert what the asset-lock flow queued.
    #[derive(Default)]
    struct CapturingPersistence {
        stored: Mutex<Vec<PlatformWalletChangeSet>>,
    }

    impl CapturingPersistence {
        /// Outpoints queued for persisted-row deletion across all stored
        /// changesets.
        fn removed_outpoints(&self) -> Vec<OutPoint> {
            self.stored
                .lock()
                .expect("capturing persistence mutex")
                .iter()
                .filter_map(|cs| cs.asset_locks.as_ref())
                .flat_map(|al| al.removed.iter().copied())
                .collect()
        }
    }

    impl PlatformWalletPersistence for CapturingPersistence {
        fn store(
            &self,
            _wallet_id: WalletId,
            changeset: PlatformWalletChangeSet,
        ) -> Result<(), PersistenceError> {
            self.stored
                .lock()
                .expect("capturing persistence mutex")
                .push(changeset);
            Ok(())
        }

        fn flush(&self, _wallet_id: WalletId) -> Result<(), PersistenceError> {
            Ok(())
        }

        fn load(&self) -> Result<ClientStartState, PersistenceError> {
            Ok(ClientStartState::default())
        }
    }

    /// Builds an `AssetLockManager` over the shared BIP44-funded fixture.
    async fn funded_asset_lock_manager<B: TransactionBroadcaster>(
        broadcaster: Arc<B>,
    ) -> (
        Arc<AssetLockManager<B>>,
        WalletSigner,
        Arc<CapturingPersistence>,
    ) {
        let (wallet_manager, wallet_id, _balance, signer) =
            funded_wallet_manager(StandardAccountType::BIP44Account).await;

        let persistence = Arc::new(CapturingPersistence::default());
        let sdk = Arc::new(dash_sdk::SdkBuilder::new_mock().build().expect("mock sdk"));
        let manager = Arc::new(AssetLockManager::new(
            sdk,
            wallet_manager,
            wallet_id,
            Arc::new(Notify::new()),
            broadcaster,
            WalletPersister::new(
                wallet_id,
                Arc::clone(&persistence) as Arc<dyn PlatformWalletPersistence>,
            ),
        ));

        (manager, signer, persistence)
    }

    /// A definitively rejected asset-lock broadcast must untrack the `Built`
    /// row (in-memory and via the changeset's `removed` set) and release the
    /// funding reservation, so nothing can resume the dead transaction and a
    /// fresh funding attempt can reselect the inputs immediately.
    #[tokio::test]
    async fn rejected_asset_lock_broadcast_untracks_row_and_releases_reservation() {
        let (manager, signer, persistence) =
            funded_asset_lock_manager(Arc::new(AlwaysRejectedBroadcaster)).await;

        let result = manager
            .create_funded_asset_lock_proof(
                1_000_000,
                0,
                AssetLockFundingType::IdentityRegistration,
                0,
                &signer,
            )
            .await;
        assert!(
            matches!(result, Err(PlatformWalletError::TransactionBroadcast(_))),
            "rejected broadcast should surface as TransactionBroadcast, got {result:?}"
        );

        // The Built row is gone in memory…
        {
            let wm = manager.wallet_manager.read().await;
            let (_, info) = wm
                .get_wallet_and_info(&manager.wallet_id)
                .expect("wallet still present");
            assert!(
                info.tracked_asset_locks.is_empty(),
                "rejected lock must be untracked, got {:?}",
                info.tracked_asset_locks
            );
        }
        // …and its persisted row was queued for deletion.
        assert_eq!(
            persistence.removed_outpoints().len(),
            1,
            "exactly the rejected lock's outpoint should be queued as removed"
        );

        // The funding reservation was released: a fresh build over the same
        // single-UTXO wallet can reselect the inputs immediately.
        let rebuild = manager
            .build_asset_lock_transaction(
                1_000_000,
                0,
                AssetLockFundingType::IdentityRegistration,
                0,
                &signer,
            )
            .await;
        assert!(
            rebuild.is_ok(),
            "rebuild after a rejected broadcast should reselect the released \
             inputs, got {rebuild:?}"
        );
    }

    /// An *ambiguous* asset-lock broadcast failure must keep both the funding
    /// reservation and the resumable `Built` row: the transaction may already
    /// be propagating, so a retry must not double-spend and a resume must
    /// stay possible.
    #[tokio::test]
    async fn ambiguous_asset_lock_broadcast_keeps_reservation_and_built_row() {
        let (manager, signer, persistence) =
            funded_asset_lock_manager(Arc::new(AlwaysMaybeSentBroadcaster)).await;

        let result = manager
            .create_funded_asset_lock_proof(
                1_000_000,
                0,
                AssetLockFundingType::IdentityRegistration,
                0,
                &signer,
            )
            .await;
        assert!(
            matches!(
                result,
                Err(PlatformWalletError::TransactionBroadcastUnconfirmed(_))
            ),
            "ambiguous broadcast should surface as TransactionBroadcastUnconfirmed, got {result:?}"
        );

        // The Built row survives for a later resume…
        {
            let wm = manager.wallet_manager.read().await;
            let (_, info) = wm
                .get_wallet_and_info(&manager.wallet_id)
                .expect("wallet still present");
            assert_eq!(info.tracked_asset_locks.len(), 1);
            let lock = info.tracked_asset_locks.values().next().expect("built row");
            assert_eq!(lock.status, AssetLockStatus::Built);
        }
        // …no persisted-row deletion was queued…
        assert!(
            persistence.removed_outpoints().is_empty(),
            "ambiguous failure must not queue a row deletion"
        );

        // …and the reservation is kept: a fresh build cannot reselect the
        // single reserved UTXO and fails at input selection.
        let rebuild = manager
            .build_asset_lock_transaction(
                1_000_000,
                0,
                AssetLockFundingType::IdentityRegistration,
                0,
                &signer,
            )
            .await;
        assert!(
            matches!(rebuild, Err(PlatformWalletError::AssetLockTransaction(_))),
            "rebuild must fail at input selection while the reservation is \
             kept, got {rebuild:?}"
        );
    }

    /// Broadcaster that simulates the racing interleave the release gate
    /// exists for: "during" the broadcast a concurrent `resume_asset_lock`
    /// advances the tracked row to `Broadcast`, then the original call still
    /// comes back `Rejected`. The advanced row is positive evidence the
    /// transaction reached the network, so the cleanup must keep it AND keep
    /// the funding reservation.
    struct RejectAfterConcurrentResumeBroadcaster {
        wallet_manager: Arc<RwLock<WalletManager<PlatformWalletInfo>>>,
        wallet_id: WalletId,
    }

    #[async_trait]
    impl TransactionBroadcaster for RejectAfterConcurrentResumeBroadcaster {
        async fn broadcast(&self, _transaction: &Transaction) -> Result<Txid, BroadcastError> {
            let mut wm = self.wallet_manager.write().await;
            let info = wm
                .get_wallet_info_mut(&self.wallet_id)
                .expect("wallet present");
            let lock = info
                .tracked_asset_locks
                .values_mut()
                .next()
                .expect("Built row tracked before broadcast");
            lock.status = AssetLockStatus::Broadcast;
            drop(wm);
            Err(BroadcastError::Rejected {
                reason: "simulated rejection racing a concurrent resume".to_string(),
            })
        }
    }

    /// If a concurrent resume advanced the row past `Built` in the rejection
    /// window, the cleanup must keep the row (guard) AND keep the funding
    /// reservation (release gate) — otherwise the still-tracked transaction
    /// would be resumable while its inputs are re-spendable.
    #[tokio::test]
    async fn rejected_broadcast_racing_concurrent_resume_keeps_row_and_reservation() {
        let (wallet_manager, wallet_id, _balance, signer) =
            funded_wallet_manager(StandardAccountType::BIP44Account).await;

        let broadcaster = Arc::new(RejectAfterConcurrentResumeBroadcaster {
            wallet_manager: Arc::clone(&wallet_manager),
            wallet_id,
        });
        let persistence = Arc::new(CapturingPersistence::default());
        let sdk = Arc::new(dash_sdk::SdkBuilder::new_mock().build().expect("mock sdk"));
        let manager = Arc::new(AssetLockManager::new(
            sdk,
            Arc::clone(&wallet_manager),
            wallet_id,
            Arc::new(Notify::new()),
            broadcaster,
            WalletPersister::new(
                wallet_id,
                Arc::clone(&persistence) as Arc<dyn PlatformWalletPersistence>,
            ),
        ));

        let result = manager
            .create_funded_asset_lock_proof(
                1_000_000,
                0,
                AssetLockFundingType::IdentityRegistration,
                0,
                &signer,
            )
            .await;
        assert!(
            matches!(result, Err(PlatformWalletError::TransactionBroadcast(_))),
            "rejection should still surface, got {result:?}"
        );

        // The concurrently-advanced row survives the cleanup…
        {
            let wm = wallet_manager.read().await;
            let (_, info) = wm
                .get_wallet_and_info(&manager.wallet_id)
                .expect("wallet still present");
            assert_eq!(info.tracked_asset_locks.len(), 1);
            let lock = info.tracked_asset_locks.values().next().expect("row kept");
            assert_eq!(lock.status, AssetLockStatus::Broadcast);
        }
        // …no persisted-row deletion was queued…
        assert!(
            persistence.removed_outpoints().is_empty(),
            "advanced row must not be queued for deletion"
        );

        // …and the reservation was NOT released: a fresh build cannot
        // reselect the single reserved UTXO.
        let rebuild = manager
            .build_asset_lock_transaction(
                1_000_000,
                0,
                AssetLockFundingType::IdentityRegistration,
                0,
                &signer,
            )
            .await;
        assert!(
            matches!(rebuild, Err(PlatformWalletError::AssetLockTransaction(_))),
            "rebuild must fail at input selection while the reservation is \
             kept for the advanced row, got {rebuild:?}"
        );
    }

    // -- Multi-account asset-lock funding (dashpay/platform#4073) --

    /// Wraps the split BIP44 + CoinJoin fixture in an `AssetLockManager`.
    /// `build_asset_lock_transaction` never broadcasts, so the broadcaster is
    /// irrelevant here.
    async fn split_asset_lock_manager(
        bip44_duffs: u64,
        coinjoin_duffs: u64,
    ) -> (Arc<AssetLockManager<AlwaysRejectedBroadcaster>>, WalletSigner) {
        let (wallet_manager, wallet_id, signer) =
            crate::test_support::split_funded_wallet_manager(bip44_duffs, coinjoin_duffs).await;
        let persistence = Arc::new(CapturingPersistence::default());
        let sdk = Arc::new(dash_sdk::SdkBuilder::new_mock().build().expect("mock sdk"));
        let manager = Arc::new(AssetLockManager::new(
            sdk,
            wallet_manager,
            wallet_id,
            Arc::new(Notify::new()),
            Arc::new(AlwaysRejectedBroadcaster),
            WalletPersister::new(
                wallet_id,
                Arc::clone(&persistence) as Arc<dyn PlatformWalletPersistence>,
            ),
        ));
        (manager, signer)
    }

    /// Wraps the many-CoinJoin-UTXO fixture in an `AssetLockManager`.
    async fn split_asset_lock_manager_many_coinjoin(
        bip44_duffs: u64,
        coinjoin_values: &[u64],
    ) -> (Arc<AssetLockManager<AlwaysRejectedBroadcaster>>, WalletSigner) {
        let (wallet_manager, wallet_id, signer) =
            crate::test_support::split_funded_wallet_manager_many_coinjoin(
                bip44_duffs,
                coinjoin_values,
            )
            .await;
        let persistence = Arc::new(CapturingPersistence::default());
        let sdk = Arc::new(dash_sdk::SdkBuilder::new_mock().build().expect("mock sdk"));
        let manager = Arc::new(AssetLockManager::new(
            sdk,
            wallet_manager,
            wallet_id,
            Arc::new(Notify::new()),
            Arc::new(AlwaysRejectedBroadcaster),
            WalletPersister::new(
                wallet_id,
                Arc::clone(&persistence) as Arc<dyn PlatformWalletPersistence>,
            ),
        ));
        (manager, signer)
    }

    /// The `(BIP44 account 0, CoinJoin account 0)` UTXO outpoint sets, so a
    /// test can prove a built transaction drew inputs from both accounts.
    async fn account_outpoints(
        manager: &AssetLockManager<AlwaysRejectedBroadcaster>,
    ) -> (
        std::collections::HashSet<OutPoint>,
        std::collections::HashSet<OutPoint>,
    ) {
        let wm = manager.wallet_manager.read().await;
        let (_, info) = wm
            .get_wallet_and_info(&manager.wallet_id)
            .expect("wallet present");
        let bip44 = info
            .core_wallet
            .accounts
            .standard_bip44_accounts
            .get(&0)
            .map(|a| a.utxos.keys().copied().collect())
            .unwrap_or_default();
        let coinjoin = info
            .core_wallet
            .accounts
            .coinjoin_accounts
            .get(&0)
            .map(|a| a.utxos.keys().copied().collect())
            .unwrap_or_default();
        (bip44, coinjoin)
    }

    /// The bug: shielded asset-lock funding must be able to spend
    /// previously-mixed CoinJoin coins, not just the BIP44 slice. Split the
    /// balance so NEITHER account alone can fund the lock (0.09 DASH each) and
    /// require 0.15 DASH — coin selection must reach across both the BIP44 and
    /// the DIP-9 CoinJoin account, and the mixed inputs must each be signed
    /// under their own account's derivation path.
    #[tokio::test]
    async fn shielded_asset_lock_funds_from_bip44_and_coinjoin_union() {
        // 0.09 DASH on BIP44, 0.09 DASH on CoinJoin; require 0.15 DASH.
        let (manager, signer) = split_asset_lock_manager(9_000_000, 9_000_000).await;
        let (bip44_outpoints, coinjoin_outpoints) = account_outpoints(&manager).await;

        let (tx, _path) = manager
            .build_asset_lock_transaction(
                15_000_000,
                0,
                AssetLockFundingType::AssetLockShieldedAddressTopUp,
                0,
                &signer,
            )
            .await
            .expect("shielded asset lock must fund from the BIP44 + CoinJoin union");

        // Neither account alone covers 0.15 DASH, so both must be selected.
        let spent: std::collections::HashSet<OutPoint> =
            tx.input.iter().map(|i| i.previous_output).collect();
        assert!(
            spent.iter().any(|o| bip44_outpoints.contains(o)),
            "expected at least one BIP44 input, tx spent {spent:?}"
        );
        assert!(
            spent.iter().any(|o| coinjoin_outpoints.contains(o)),
            "expected at least one CoinJoin input (the #4073 fix), tx spent {spent:?}"
        );

        // Per-account signing: every selected input, regardless of which
        // account's derivation path it needed, must carry a signature.
        assert!(!tx.input.is_empty(), "asset lock must have selected inputs");
        for (i, txin) in tx.input.iter().enumerate() {
            assert!(
                !txin.script_sig.is_empty(),
                "input {i} ({}) has an empty script_sig — the cross-account \
                 resolver failed to derive/sign its key",
                txin.previous_output
            );
        }
    }

    /// The widening is deliberately scoped to shielded funding: spending mixed
    /// CoinJoin coins into an identity registration would de-anonymize them.
    /// With the balance split 0.09/0.09, an identity-registration lock for
    /// 0.15 DASH must still fail (BIP44 alone is short) while the shielded lock
    /// for the same amount succeeds from the union.
    #[tokio::test]
    async fn non_shielded_asset_lock_stays_single_bip44_account() {
        let (manager, signer) = split_asset_lock_manager(9_000_000, 9_000_000).await;

        let identity = manager
            .build_asset_lock_transaction(
                15_000_000,
                0,
                AssetLockFundingType::IdentityRegistration,
                0,
                &signer,
            )
            .await;
        assert!(
            identity.is_err(),
            "identity registration must NOT reach CoinJoin coins — BIP44 alone \
             is short of 0.15 DASH, got {identity:?}"
        );

        let shielded = manager
            .build_asset_lock_transaction(
                15_000_000,
                0,
                AssetLockFundingType::AssetLockShieldedAddressTopUp,
                0,
                &signer,
            )
            .await;
        assert!(
            shielded.is_ok(),
            "shielded funding must reach the union, got {shielded:?}"
        );
    }

    /// A shielded lock exceeding even the UNION balance surfaces the typed
    /// [`PlatformWalletError::AssetLockInsufficientFunds`], and its `available`
    /// reflects the whole spendable balance (both accounts), not the BIP44
    /// slice — the pre-#4073 symptom was `available` reporting only the BIP44
    /// portion.
    #[tokio::test]
    async fn shielded_asset_lock_union_shortfall_is_typed() {
        // Union spendable is 0.18 DASH; ask for 1.0 DASH.
        let (manager, signer) = split_asset_lock_manager(9_000_000, 9_000_000).await;

        let result = manager
            .build_asset_lock_transaction(
                100_000_000,
                0,
                AssetLockFundingType::AssetLockShieldedAddressTopUp,
                0,
                &signer,
            )
            .await;

        match result {
            Err(PlatformWalletError::AssetLockInsufficientFunds {
                available,
                required,
            }) => {
                // `available` must reflect the union (both 0.09 UTXOs), i.e.
                // strictly more than the BIP44-only slice the old path saw.
                assert!(
                    available > 9_000_000,
                    "available ({available}) should reflect the BIP44 + CoinJoin \
                     union (> the 9_000_000 BIP44 slice)"
                );
                assert!(
                    available <= 18_000_000,
                    "available ({available}) cannot exceed the 18_000_000 union"
                );
                assert!(
                    required >= 100_000_000,
                    "required ({required}) should be at least the requested amount"
                );
            }
            other => panic!(
                "expected typed AssetLockInsufficientFunds carrying the union \
                 available/required, got {other:?}"
            ),
        }
    }

    /// On-device regression: a real CoinJoin account holds many small mixed
    /// denominations. The first version of the multi-account builder inherited
    /// `TransactionBuilder`'s default `BranchAndBound`, whose recursive
    /// exact-match subset-sum (`CoinSelector::find_exact_match`) is EXPONENTIAL
    /// in the count of sub-target UTXOs — feeding it a large CoinJoin set hung
    /// the whole FFI call for minutes with no logs and no broadcast. The builder
    /// now pins `LargestFirst` (linear greedy).
    ///
    /// The blowup is SYNCHRONOUS CPU work with no `.await` points, so it cannot
    /// be interrupted by `tokio::time::timeout` (that is exactly why on-device
    /// it hangs RUNNABLE-in-native and the enclosing coroutine never yields).
    /// The build therefore runs on a **detached OS thread**, and the test body
    /// waits on a channel with a wall-clock deadline: a regression to an
    /// exponential strategy makes `recv_timeout` fire and the test FAIL (rather
    /// than hang the whole suite). The detached thread is reclaimed at process
    /// exit; on the happy path (LargestFirst) it finishes in well under a
    /// millisecond and the channel delivers immediately.
    #[test]
    fn shielded_asset_lock_over_many_coinjoin_utxos_does_not_hang() {
        use std::sync::mpsc;
        use std::time::Duration;

        // 40 x 0.02 DASH CoinJoin UTXOs (0.8 DASH), 0.09 DASH on BIP44; shield
        // 0.2 DASH. BranchAndBound would explore ~sum_k C(40, k<=10) subsets —
        // empirically minutes+; LargestFirst returns instantly.
        let coinjoin: Vec<u64> = vec![2_000_000; 40];

        // Fixture build is async; drive it on a throwaway current-thread runtime.
        let setup_rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("setup runtime");
        let (manager, signer) =
            setup_rt.block_on(split_asset_lock_manager_many_coinjoin(9_000_000, &coinjoin));

        let (result_tx, result_rx) = mpsc::channel();
        // Detached: NOT joined anywhere, so a hung build can't wedge runtime
        // teardown; libtest reclaims it at process exit.
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("worker runtime");
            let outcome = rt
                .block_on(manager.build_asset_lock_transaction(
                    20_000_000,
                    0,
                    AssetLockFundingType::AssetLockShieldedAddressTopUp,
                    0,
                    &signer,
                ))
                .map(|(tx, _path)| tx);
            let _ = result_tx.send(outcome);
        });

        // LargestFirst completes in ~25ms; a 30s deadline is a ~1000x margin
        // against CI contention while still bounding a regression to an
        // exponential strategy (which never returns) to a prompt failure.
        match result_rx.recv_timeout(Duration::from_secs(30)) {
            Ok(Ok(tx)) => {
                // LargestFirst minimizes the input count; every selected input
                // must be signed under its own account's derivation path.
                assert!(!tx.input.is_empty(), "must select inputs");
                for txin in &tx.input {
                    assert!(
                        !txin.script_sig.is_empty(),
                        "input {} is unsigned",
                        txin.previous_output
                    );
                }
            }
            Ok(Err(e)) => panic!("funding must succeed from the CoinJoin union, got {e:?}"),
            Err(_) => panic!(
                "multi-account asset-lock funding did not return within 30s — \
                 regression to an exponential coin-selection strategy over the \
                 CoinJoin UTXO set (dashpay/platform#4073 on-device hang)"
            ),
        }
    }
}
