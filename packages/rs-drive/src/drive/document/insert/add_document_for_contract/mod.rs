mod v0;

use crate::drive::Drive;
use crate::util::object_size_info::DocumentAndContractInfo;

use crate::error::drive::DriveError;
use crate::error::Error;

use dpp::block::block_info::BlockInfo;
use dpp::fee::fee_result::FeeResult;

use dpp::fee::default_costs::CachedEpochIndexFeeVersions;
use dpp::version::PlatformVersion;
use grovedb::TransactionArg;

impl Drive {
    /// Adds a document to a contract.
    ///
    /// # Parameters
    /// * `document_and_contract_info`: Information about the document and contract.
    /// * `override_document`: Whether to override the document.
    /// * `block_info`: The block info.
    /// * `apply`: Whether to apply the operation.
    /// * `transaction`: The transaction argument.
    /// * `drive_version`: The drive version to select the correct function version to run.
    ///
    /// # Returns
    /// * `Ok(FeeResult)` if the operation was successful.
    /// * `Err(DriveError::UnknownVersionMismatch)` if the drive version does not match known versions.
    #[allow(clippy::too_many_arguments)]
    pub fn add_document_for_contract(
        &self,
        document_and_contract_info: DocumentAndContractInfo,
        override_document: bool,
        block_info: BlockInfo,
        apply: bool,
        transaction: TransactionArg,
        platform_version: &PlatformVersion,
        previous_fee_versions: Option<&CachedEpochIndexFeeVersions>,
    ) -> Result<FeeResult, Error> {
        match platform_version
            .drive
            .methods
            .document
            .insert
            .add_document_for_contract
        {
            0 => self.add_document_for_contract_v0(
                document_and_contract_info,
                override_document,
                block_info,
                apply,
                transaction,
                platform_version,
                previous_fee_versions,
            ),
            version => Err(Error::Drive(DriveError::UnknownVersionMismatch {
                method: "add_document_for_contract".to_string(),
                known_versions: vec![0],
                received: version,
            })),
        }
    }
}

#[cfg(test)]
mod time_range_index_e2e_tests {
    //! End-to-end coverage for time-range index fan-out: a single document is
    //! indexed under every overlapping range bucket its `$createdAt` falls
    //! into, those buckets are queryable by exact bucket start, and deletion
    //! removes every entry.
    use crate::config::DriveConfig;
    use crate::drive::Drive;
    use crate::query::DriveDocumentQuery;
    use crate::util::object_size_info::DocumentInfo::DocumentRefInfo;
    use crate::util::object_size_info::{DocumentAndContractInfo, OwnedDocumentInfo};
    use crate::util::storage_flags::StorageFlags;
    use crate::util::test_helpers::setup::setup_drive_with_initial_state_structure;
    use dpp::block::block_info::BlockInfo;
    use dpp::data_contract::accessors::v0::DataContractV0Getters;
    use dpp::data_contract::document_type::accessors::DocumentTypeV0Getters;
    use dpp::data_contract::DataContractFactory;
    use dpp::document::{Document, DocumentV0, DocumentV0Getters};
    use dpp::platform_value::{platform_value, Identifier, Value};
    use dpp::prelude::DataContract;
    use dpp::tests::utils::generate_random_identifier_struct;
    use dpp::version::PlatformVersion;
    use std::collections::BTreeMap;

    const HOUR_MS: u64 = 3_600_000;

    /// A v12 `post` document type with a `(timeRange($createdAt, range=6h,
    /// step=2h), hashtag)` countable index — i.e. trending hashtags over a
    /// 6-hour window refreshed every 2 hours (overlap factor 3).
    fn build_trending_contract() -> DataContract {
        let factory = DataContractFactory::new(12).expect("factory");
        let index_map = vec![
            (
                Value::Text("name".to_string()),
                Value::Text("trending".to_string()),
            ),
            (
                Value::Text("properties".to_string()),
                Value::Array(vec![
                    platform_value!({"$createdAt": "asc"}),
                    platform_value!({"hashtag": "asc"}),
                ]),
            ),
            (
                Value::Text("timeRange".to_string()),
                Value::Map(vec![
                    (
                        Value::Text("on".to_string()),
                        Value::Text("$createdAt".to_string()),
                    ),
                    (Value::Text("range".to_string()), Value::U64(6 * HOUR_MS)),
                    (Value::Text("step".to_string()), Value::U64(2 * HOUR_MS)),
                ]),
            ),
            (
                Value::Text("countable".to_string()),
                Value::Text("countable".to_string()),
            ),
        ];

        let document_schema = platform_value!({
            "type": "object",
            "properties": {
                "hashtag": {"type": "string", "maxLength": 63, "position": 0},
            },
            "required": ["hashtag"],
            "indices": Value::Array(vec![Value::Map(index_map)]),
            "additionalProperties": false,
        });
        let schemas = platform_value!({ "post": document_schema });
        let owner_id = generate_random_identifier_struct();
        factory
            .create_with_value_config(owner_id, 0, schemas, None, None)
            .expect("create contract")
            .data_contract_owned()
    }

    /// Number of documents the `trending` index returns for an exact
    /// `$createdAt == bucket` lookup.
    fn count_in_bucket(
        drive: &Drive,
        contract: &DataContract,
        bucket: u64,
        platform_version: &PlatformVersion,
    ) -> usize {
        let document_type = contract.document_type_for_name("post").expect("post");
        let query_value = Value::Map(vec![(
            Value::Text("where".to_string()),
            Value::Array(vec![Value::Array(vec![
                Value::Text("$createdAt".to_string()),
                Value::Text("==".to_string()),
                Value::U64(bucket),
            ])]),
        )]);
        let query = DriveDocumentQuery::from_value(
            query_value,
            contract,
            document_type,
            &DriveConfig::default(),
        )
        .expect("build query");
        query
            .execute_raw_results_no_proof(drive, None, None, platform_version)
            .expect("query")
            .0
            .len()
    }

    #[test]
    fn time_range_insert_fans_out_to_overlapping_buckets_and_delete_removes_them() {
        let platform_version = PlatformVersion::latest();
        let drive = setup_drive_with_initial_state_structure(Some(platform_version));
        let contract = build_trending_contract();

        drive
            .apply_contract(
                &contract,
                BlockInfo::default(),
                true,
                StorageFlags::optional_default_as_cow(),
                None,
                platform_version,
            )
            .expect("apply contract");

        let document_type = contract.document_type_for_name("post").expect("post");
        let transform = document_type
            .indexes()
            .get("trending")
            .expect("trending index")
            .time_range
            .clone()
            .expect("time range transform");
        assert_eq!(transform.overlap_factor(), 3);

        // A document created at 7h+ falls into the ranges starting at 6h, 4h, 2h.
        let created_at = 7 * HOUR_MS + 123_456;
        let expected_buckets = transform.containing_buckets(created_at);
        assert_eq!(
            expected_buckets,
            vec![6 * HOUR_MS, 4 * HOUR_MS, 2 * HOUR_MS]
        );

        let owner_bytes = rand::random::<[u8; 32]>();
        let document = Document::V0(DocumentV0 {
            id: Identifier::from(rand::random::<[u8; 32]>()),
            owner_id: Identifier::from(owner_bytes),
            properties: BTreeMap::from([("hashtag".to_string(), Value::Text("ibiza".to_string()))]),
            created_at: Some(created_at),
            ..Default::default()
        });
        let document_id = document.id();

        drive
            .add_document_for_contract(
                DocumentAndContractInfo {
                    owned_document_info: OwnedDocumentInfo {
                        document_info: DocumentRefInfo((
                            &document,
                            StorageFlags::optional_default_as_cow(),
                        )),
                        owner_id: Some(owner_bytes),
                    },
                    contract: &contract,
                    document_type,
                },
                false,
                BlockInfo::default(),
                true,
                None,
                platform_version,
                None,
            )
            .expect("add document");

        // The document is queryable under each of its 3 overlapping buckets.
        for bucket in &expected_buckets {
            assert_eq!(
                count_in_bucket(&drive, &contract, *bucket, platform_version),
                1,
                "document should be indexed under bucket {bucket}"
            );
        }
        // It is NOT stored under the raw timestamp (only under bucket starts)…
        assert_eq!(
            count_in_bucket(&drive, &contract, created_at, platform_version),
            0,
            "document must be indexed under bucket starts, not the raw timestamp"
        );
        // …nor under a range that does not contain it.
        assert_eq!(
            count_in_bucket(&drive, &contract, 0, platform_version),
            0,
            "an unrelated bucket must be empty"
        );

        // Deleting the document removes every bucket entry.
        drive
            .delete_document_for_contract(
                document_id,
                &contract,
                "post",
                BlockInfo::default(),
                true,
                None,
                platform_version,
                None,
            )
            .expect("delete document");

        for bucket in &expected_buckets {
            assert_eq!(
                count_in_bucket(&drive, &contract, *bucket, platform_version),
                0,
                "bucket {bucket} should be empty after deletion"
            );
        }
    }
}
