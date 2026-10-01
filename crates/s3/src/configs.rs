//! Requester Pays and a bucket's inventory, analytics, metrics and Intelligent-Tiering
//! configurations: read from S3's XML with S3's checks, kept as given, and listed a
//! page of 100 at a time.

use std::collections::{BTreeMap, BTreeSet};

use s3s::{S3Error, S3ErrorCode, S3Result, dto, s3_error};
use teifs_store::Store;
use teifs_types::{
    check_bucket,
    configs::{
        AnalyticsConfig, AnalyticsExport, ArchiveTier, Configurations, Filter, Frequency,
        InventoryConfig, InventoryDestination, InventoryField, InventoryFormat, Kind, LIST_PAGE,
        MetricsConfig, ReportEncryption, TagFilter, Tiering, TieringConfig, id_problem,
    },
};

use crate::errors::from_store;

/// Where a kind's configurations are kept in a bucket's.
pub(crate) type Field<T> = fn(&mut Configurations) -> &mut BTreeMap<String, T>;

/// Adds or replaces the configuration `PUT ?KIND&id=ID` gives.
pub(crate) async fn put<T: Send + 'static>(
    store: &Store,
    (bucket, query_id): (&str, &str),
    kind: Kind,
    (id, config): (String, T),
    field: Field<T>,
) -> S3Result<()> {
    check_id(query_id, &id)?;
    store
        .put_configuration(bucket, kind, query_id, move |configurations| {
            field(configurations).insert(id, config);
        })
        .await
        .map_err(from_store)
}

/// The configuration `GET ?KIND&id=ID` answers.
pub(crate) async fn get<T: Clone>(
    store: &Store,
    bucket: &str,
    id: &str,
    field: Field<T>,
) -> S3Result<T> {
    check_query_id(id)?;
    let mut configurations = (*store
        .bucket_configurations(bucket)
        .await
        .map_err(from_store)?)
    .clone();
    field(&mut configurations)
        .remove(id)
        .ok_or_else(no_such_configuration)
}

/// Removes the configuration `DELETE ?KIND&id=ID` names.
pub(crate) async fn delete(store: &Store, bucket: &str, kind: Kind, id: &str) -> S3Result<()> {
    check_query_id(id)?;
    if store
        .delete_configuration(bucket, kind, id)
        .await
        .map_err(from_store)?
    {
        Ok(())
    } else {
        Err(no_such_configuration())
    }
}

/// A page of `GET ?KIND`: the configurations, whether more follow, and the token for them.
pub(crate) async fn list<T, D>(
    store: &Store,
    bucket: &str,
    token: Option<&str>,
    field: Field<T>,
    to_dto: fn(&str, &T) -> D,
) -> S3Result<(Vec<D>, bool, Option<String>)> {
    let mut configurations = (*store
        .bucket_configurations(bucket)
        .await
        .map_err(from_store)?)
    .clone();
    let items = field(&mut configurations);
    let (found, next) = page(items, token);
    let found = found
        .into_iter()
        .map(|(id, config)| to_dto(id, config))
        .collect();
    Ok((found, next.is_some(), next))
}

/// Every configuration checked as its Put checks it (an import's).
pub(crate) fn check_all(given: &Configurations) -> S3Result<Configurations> {
    fn each<T, D>(
        items: &BTreeMap<String, T>,
        to_dto: fn(&str, &T) -> D,
        from_dto: fn(D) -> S3Result<(String, T)>,
    ) -> S3Result<BTreeMap<String, T>> {
        items
            .iter()
            .map(|(id, config)| {
                let (checked_id, checked) = from_dto(to_dto(id, config))?;
                check_id(id, &checked_id)?;
                Ok((checked_id, checked))
            })
            .collect()
    }
    for count in [
        given.inventory.len(),
        given.analytics.len(),
        given.metrics.len(),
        given.intelligent_tiering.len(),
    ] {
        if count > teifs_types::configs::MAX_CONFIGURATIONS {
            return Err(from_store(teifs_store::StoreError::TooManyConfigurations));
        }
    }
    Ok(Configurations {
        requester_pays: given.requester_pays,
        inventory: each(&given.inventory, inventory_to_dto, inventory_from_dto)?,
        analytics: each(&given.analytics, analytics_to_dto, analytics_from_dto)?,
        metrics: each(&given.metrics, metrics_to_dto, metrics_from_dto)?,
        intelligent_tiering: each(&given.intelligent_tiering, tiering_to_dto, tiering_from_dto)?,
    })
}

/// The ARN prefix of a bucket given as a destination.
const BUCKET_ARN: &str = "arn:aws:s3:::";

/// `NoSuchConfiguration`: a Get or Delete of an id the bucket doesn't have.
pub(crate) fn no_such_configuration() -> S3Error {
    let mut err = S3Error::with_message(
        S3ErrorCode::Custom("NoSuchConfiguration".into()),
        "The specified configuration does not exist.",
    );
    err.set_status_code(http::StatusCode::NOT_FOUND);
    err
}

/// The id in the URL, checked, and the same as the one in the body.
pub(crate) fn check_id(query: &str, body: &str) -> S3Result<()> {
    if let Some(problem) = id_problem(query) {
        return Err(s3_error!(InvalidArgument, "{problem}"));
    }
    if query != body {
        return Err(s3_error!(
            InvalidArgument,
            "The configuration's Id doesn't match the id in the request"
        ));
    }
    Ok(())
}

/// The id of a Get or Delete, checked.
pub(crate) fn check_query_id(id: &str) -> S3Result<()> {
    id_problem(id).map_or(Ok(()), |problem| {
        Err(s3_error!(InvalidArgument, "{problem}"))
    })
}

/// A page of `items` (sorted by id) from `token`: the page, and the token of the next.
pub(crate) fn page<'a, T>(
    items: &'a BTreeMap<String, T>,
    token: Option<&str>,
) -> (Vec<(&'a String, &'a T)>, Option<String>) {
    let start = token.unwrap_or("");
    let mut rest =
        items.range::<str, _>((std::ops::Bound::Included(start), std::ops::Bound::Unbounded));
    let page: Vec<_> = rest.by_ref().take(LIST_PAGE).collect();
    let next = rest.next().map(|(id, _)| id.clone());
    (page, next)
}

/// Whether requesters pay, from a `RequestPaymentConfiguration`.
pub(crate) fn requester_pays(config: &dto::RequestPaymentConfiguration) -> S3Result<bool> {
    match config.payer.as_str() {
        dto::Payer::REQUESTER => Ok(true),
        dto::Payer::BUCKET_OWNER => Ok(false),
        _ => Err(malformed()),
    }
}

/// A `Payer` for `GetBucketRequestPayment`.
pub(crate) fn payer(requester_pays: bool) -> dto::Payer {
    dto::Payer::from_static(if requester_pays {
        dto::Payer::REQUESTER
    } else {
        dto::Payer::BUCKET_OWNER
    })
}

/// The bucket a destination ARN names.
fn destination_bucket(arn: &str) -> S3Result<String> {
    let name = arn
        .strip_prefix(BUCKET_ARN)
        .filter(|name| check_bucket(name).is_ok())
        .ok_or_else(|| s3_error!(InvalidArgument, "Invalid bucket ARN: {arn}"))?;
    Ok(name.to_owned())
}

fn tag_filter(tag: dto::Tag) -> S3Result<TagFilter> {
    match (tag.key, tag.value) {
        (Some(key), Some(value)) if !key.is_empty() => Ok(TagFilter { key, value }),
        _ => Err(malformed()),
    }
}

fn tag_to_dto(tag: &TagFilter) -> dto::Tag {
    dto::Tag {
        key: Some(tag.key.clone()),
        value: Some(tag.value.clone()),
    }
}

/// The parts of an `And`, checked: each tag key once.
fn and_filter(
    prefix: Option<String>,
    tags: Option<dto::TagSet>,
    access_point: Option<String>,
) -> S3Result<Filter> {
    let tags = tags
        .unwrap_or_default()
        .into_iter()
        .map(tag_filter)
        .collect::<S3Result<Vec<_>>>()?;
    let mut keys = BTreeSet::new();
    if !tags.iter().all(|tag| keys.insert(tag.key.as_str())) {
        return Err(s3_error!(
            InvalidArgument,
            "Duplicate Tag Keys are not allowed."
        ));
    }
    Ok(Filter {
        and: true,
        prefix,
        tags,
        access_point,
    })
}

fn prefix_filter(prefix: String) -> Filter {
    Filter {
        prefix: Some(prefix),
        ..Filter::default()
    }
}

fn single_tag_filter(tag: dto::Tag) -> S3Result<Filter> {
    Ok(Filter {
        tags: vec![tag_filter(tag)?],
        ..Filter::default()
    })
}

/// An inventory configuration, checked as `PutBucketInventoryConfiguration` checks it.
pub(crate) fn inventory_from_dto(
    config: dto::InventoryConfiguration,
) -> S3Result<(String, InventoryConfig)> {
    let destination = config.destination.s3_bucket_destination;
    let format = InventoryFormat::parse(destination.format.as_str()).ok_or_else(malformed)?;
    let encryption = match destination.encryption {
        None => None,
        Some(dto::InventoryEncryption {
            ssekms: None,
            sses3: Some(_),
        }) => Some(ReportEncryption::S3),
        Some(dto::InventoryEncryption {
            ssekms: Some(kms),
            sses3: None,
        }) if !kms.key_id.is_empty() => Some(ReportEncryption::Kms(kms.key_id)),
        Some(_) => return Err(malformed()),
    };
    let all_versions = match config.included_object_versions.as_str() {
        dto::InventoryIncludedObjectVersions::ALL => true,
        dto::InventoryIncludedObjectVersions::CURRENT => false,
        _ => return Err(malformed()),
    };
    let frequency = Frequency::parse(config.schedule.frequency.as_str()).ok_or_else(malformed)?;
    let mut fields = Vec::new();
    for field in config.optional_fields.unwrap_or_default() {
        let field = InventoryField::parse(field.as_str()).ok_or_else(malformed)?;
        if fields.contains(&field) {
            return Err(s3_error!(
                InvalidArgument,
                "Duplicate field: {}",
                field.name()
            ));
        }
        fields.push(field);
    }
    Ok((
        config.id,
        InventoryConfig {
            enabled: config.is_enabled,
            prefix: config.filter.map(|filter| filter.prefix),
            destination: InventoryDestination {
                bucket: destination_bucket(&destination.bucket)?,
                account: destination.account_id,
                format,
                prefix: destination.prefix,
                encryption,
            },
            all_versions,
            fields,
            frequency,
        },
    ))
}

/// An inventory configuration as S3 answers it.
pub(crate) fn inventory_to_dto(id: &str, config: &InventoryConfig) -> dto::InventoryConfiguration {
    let destination = &config.destination;
    dto::InventoryConfiguration {
        destination: dto::InventoryDestination {
            s3_bucket_destination: dto::InventoryS3BucketDestination {
                account_id: destination.account.clone(),
                bucket: format!("{BUCKET_ARN}{}", destination.bucket),
                encryption: destination
                    .encryption
                    .as_ref()
                    .map(|encryption| match encryption {
                        ReportEncryption::S3 => dto::InventoryEncryption {
                            ssekms: None,
                            sses3: Some(dto::SSES3 {}),
                        },
                        ReportEncryption::Kms(key) => dto::InventoryEncryption {
                            ssekms: Some(dto::SSEKMS {
                                key_id: key.clone(),
                            }),
                            sses3: None,
                        },
                    }),
                format: dto::InventoryFormat::from(destination.format.name().to_owned()),
                prefix: destination.prefix.clone(),
            },
        },
        filter: config
            .prefix
            .clone()
            .map(|prefix| dto::InventoryFilter { prefix }),
        id: id.to_owned(),
        included_object_versions: dto::InventoryIncludedObjectVersions::from_static(
            if config.all_versions {
                dto::InventoryIncludedObjectVersions::ALL
            } else {
                dto::InventoryIncludedObjectVersions::CURRENT
            },
        ),
        is_enabled: config.enabled,
        optional_fields: (!config.fields.is_empty()).then(|| {
            config
                .fields
                .iter()
                .map(|field| dto::InventoryOptionalField::from(field.name().to_owned()))
                .collect()
        }),
        schedule: dto::InventorySchedule {
            frequency: dto::InventoryFrequency::from(config.frequency.name().to_owned()),
        },
    }
}

fn analytics_filter(filter: dto::AnalyticsFilter) -> S3Result<Filter> {
    match filter {
        dto::AnalyticsFilter::Prefix(prefix) => Ok(prefix_filter(prefix)),
        dto::AnalyticsFilter::Tag(tag) => single_tag_filter(tag),
        dto::AnalyticsFilter::And(and) => and_filter(and.prefix, and.tags, None),
        _ => Err(malformed()),
    }
}

fn analytics_filter_to_dto(filter: &Filter) -> dto::AnalyticsFilter {
    if filter.and {
        dto::AnalyticsFilter::And(dto::AnalyticsAndOperator {
            prefix: filter.prefix.clone(),
            tags: tags_to_dto(filter),
        })
    } else if let Some(tag) = filter.tags.first() {
        dto::AnalyticsFilter::Tag(tag_to_dto(tag))
    } else {
        dto::AnalyticsFilter::Prefix(filter.prefix.clone().unwrap_or_default())
    }
}

fn tags_to_dto(filter: &Filter) -> Option<dto::TagSet> {
    (!filter.tags.is_empty()).then(|| filter.tags.iter().map(tag_to_dto).collect())
}

/// A storage class analysis, checked as `PutBucketAnalyticsConfiguration` checks it.
pub(crate) fn analytics_from_dto(
    config: dto::AnalyticsConfiguration,
) -> S3Result<(String, AnalyticsConfig)> {
    let export = config
        .storage_class_analysis
        .data_export
        .map(|export| {
            if export.output_schema_version.as_str() != dto::StorageClassAnalysisSchemaVersion::V_1
            {
                return Err(malformed());
            }
            let destination = export.destination.s3_bucket_destination;
            if destination.format.as_str() != dto::AnalyticsS3ExportFileFormat::CSV {
                return Err(malformed());
            }
            Ok(AnalyticsExport {
                bucket: destination_bucket(&destination.bucket)?,
                account: destination.bucket_account_id,
                prefix: destination.prefix,
            })
        })
        .transpose()?;
    Ok((
        config.id,
        AnalyticsConfig {
            filter: config.filter.map(analytics_filter).transpose()?,
            export,
        },
    ))
}

/// A storage class analysis as S3 answers it.
pub(crate) fn analytics_to_dto(id: &str, config: &AnalyticsConfig) -> dto::AnalyticsConfiguration {
    dto::AnalyticsConfiguration {
        filter: config.filter.as_ref().map(analytics_filter_to_dto),
        id: id.to_owned(),
        storage_class_analysis: dto::StorageClassAnalysis {
            data_export: config
                .export
                .as_ref()
                .map(|export| dto::StorageClassAnalysisDataExport {
                    destination: dto::AnalyticsExportDestination {
                        s3_bucket_destination: dto::AnalyticsS3BucketDestination {
                            bucket: format!("{BUCKET_ARN}{}", export.bucket),
                            bucket_account_id: export.account.clone(),
                            format: dto::AnalyticsS3ExportFileFormat::from_static(
                                dto::AnalyticsS3ExportFileFormat::CSV,
                            ),
                            prefix: export.prefix.clone(),
                        },
                    },
                    output_schema_version: dto::StorageClassAnalysisSchemaVersion::from_static(
                        dto::StorageClassAnalysisSchemaVersion::V_1,
                    ),
                }),
        },
    }
}

/// Request metrics' settings, checked as `PutBucketMetricsConfiguration` checks them.
pub(crate) fn metrics_from_dto(
    config: dto::MetricsConfiguration,
) -> S3Result<(String, MetricsConfig)> {
    let filter = config
        .filter
        .map(|filter| match filter {
            dto::MetricsFilter::Prefix(prefix) => Ok(prefix_filter(prefix)),
            dto::MetricsFilter::Tag(tag) => single_tag_filter(tag),
            dto::MetricsFilter::AccessPointArn(arn) => Ok(Filter {
                access_point: Some(arn),
                ..Filter::default()
            }),
            dto::MetricsFilter::And(and) => and_filter(and.prefix, and.tags, and.access_point_arn),
            _ => Err(malformed()),
        })
        .transpose()?;
    Ok((config.id, MetricsConfig { filter }))
}

/// Request metrics' settings as S3 answers them.
pub(crate) fn metrics_to_dto(id: &str, config: &MetricsConfig) -> dto::MetricsConfiguration {
    dto::MetricsConfiguration {
        filter: config.filter.as_ref().map(|filter| {
            if filter.and {
                dto::MetricsFilter::And(dto::MetricsAndOperator {
                    access_point_arn: filter.access_point.clone(),
                    prefix: filter.prefix.clone(),
                    tags: tags_to_dto(filter),
                })
            } else if let Some(arn) = &filter.access_point {
                dto::MetricsFilter::AccessPointArn(arn.clone())
            } else if let Some(tag) = filter.tags.first() {
                dto::MetricsFilter::Tag(tag_to_dto(tag))
            } else {
                dto::MetricsFilter::Prefix(filter.prefix.clone().unwrap_or_default())
            }
        }),
        id: id.to_owned(),
    }
}

/// Intelligent-Tiering's archive settings, checked as
/// `PutBucketIntelligentTieringConfiguration` checks them: each tier once, after the
/// days S3 allows.
pub(crate) fn tiering_from_dto(
    config: dto::IntelligentTieringConfiguration,
) -> S3Result<(String, TieringConfig)> {
    let filter = config
        .filter
        .map(|filter| match (filter.and, filter.prefix, filter.tag) {
            (Some(and), None, None) => and_filter(and.prefix, and.tags, None),
            (None, Some(prefix), None) => Ok(prefix_filter(prefix)),
            (None, None, Some(tag)) => single_tag_filter(tag),
            (None, None, None) => Ok(Filter::default()),
            _ => Err(malformed()),
        })
        .transpose()?;
    let enabled = match config.status.as_str() {
        dto::IntelligentTieringStatus::ENABLED => true,
        dto::IntelligentTieringStatus::DISABLED => false,
        _ => return Err(malformed()),
    };
    if config.tierings.is_empty() {
        return Err(malformed());
    }
    let mut tierings: Vec<Tiering> = Vec::new();
    for tiering in config.tierings {
        let tier = ArchiveTier::parse(tiering.access_tier.as_str()).ok_or_else(malformed)?;
        if tierings.iter().any(|seen| seen.tier == tier) {
            return Err(s3_error!(
                InvalidArgument,
                "The access tier {} is given more than once",
                tier.name()
            ));
        }
        let range = tier.days();
        let days = u32::try_from(tiering.days)
            .ok()
            .filter(|days| range.contains(days))
            .ok_or_else(|| {
                s3_error!(
                    InvalidArgument,
                    "Days for {} must be between {} and {}",
                    tier.name(),
                    range.start(),
                    range.end()
                )
            })?;
        tierings.push(Tiering { tier, days });
    }
    if let [first, second] = tierings[..] {
        let (archive, deep) = if first.tier == ArchiveTier::Archive {
            (first, second)
        } else {
            (second, first)
        };
        if deep.days <= archive.days {
            return Err(s3_error!(
                InvalidArgument,
                "Days for DEEP_ARCHIVE_ACCESS must be more than days for ARCHIVE_ACCESS"
            ));
        }
    }
    Ok((
        config.id,
        TieringConfig {
            filter,
            enabled,
            tierings,
        },
    ))
}

/// Intelligent-Tiering's archive settings as S3 answers them.
pub(crate) fn tiering_to_dto(
    id: &str,
    config: &TieringConfig,
) -> dto::IntelligentTieringConfiguration {
    dto::IntelligentTieringConfiguration {
        filter: config.filter.as_ref().map(|filter| {
            if filter.and {
                dto::IntelligentTieringFilter {
                    and: Some(dto::IntelligentTieringAndOperator {
                        prefix: filter.prefix.clone(),
                        tags: tags_to_dto(filter),
                    }),
                    prefix: None,
                    tag: None,
                }
            } else {
                dto::IntelligentTieringFilter {
                    and: None,
                    prefix: filter.prefix.clone(),
                    tag: filter.tags.first().map(tag_to_dto),
                }
            }
        }),
        id: id.to_owned(),
        status: dto::IntelligentTieringStatus::from_static(if config.enabled {
            dto::IntelligentTieringStatus::ENABLED
        } else {
            dto::IntelligentTieringStatus::DISABLED
        }),
        tierings: config
            .tierings
            .iter()
            .map(|tiering| dto::Tiering {
                access_tier: dto::IntelligentTieringAccessTier::from(
                    tiering.tier.name().to_owned(),
                ),
                days: i32::try_from(tiering.days).unwrap_or(i32::MAX),
            })
            .collect(),
    }
}

fn malformed() -> S3Error {
    s3_error!(
        MalformedXML,
        "The XML you provided was not well-formed or did not validate against our published schema"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inventory(fields: &[&str]) -> dto::InventoryConfiguration {
        dto::InventoryConfiguration {
            destination: dto::InventoryDestination {
                s3_bucket_destination: dto::InventoryS3BucketDestination {
                    account_id: None,
                    bucket: "arn:aws:s3:::reports".into(),
                    encryption: Some(dto::InventoryEncryption {
                        ssekms: Some(dto::SSEKMS {
                            key_id: "teifs-default".into(),
                        }),
                        sses3: None,
                    }),
                    format: dto::InventoryFormat::from_static(dto::InventoryFormat::PARQUET),
                    prefix: Some("inv".into()),
                },
            },
            filter: Some(dto::InventoryFilter {
                prefix: "docs/".into(),
            }),
            id: "daily".into(),
            included_object_versions: dto::InventoryIncludedObjectVersions::from_static(
                dto::InventoryIncludedObjectVersions::ALL,
            ),
            is_enabled: true,
            optional_fields: Some(
                fields
                    .iter()
                    .map(|f| dto::InventoryOptionalField::from((*f).to_owned()))
                    .collect(),
            ),
            schedule: dto::InventorySchedule {
                frequency: dto::InventoryFrequency::from_static(dto::InventoryFrequency::WEEKLY),
            },
        }
    }

    #[test]
    fn inventory_configurations_are_answered_as_given() {
        let (id, config) = inventory_from_dto(inventory(&["Size", "ETag"])).unwrap();
        assert_eq!(id, "daily");
        assert_eq!(config.destination.bucket, "reports");
        assert_eq!(config.destination.format, InventoryFormat::Parquet);
        assert_eq!(config.fields, [InventoryField::Size, InventoryField::ETag]);
        assert!(config.all_versions);
        assert_eq!(config.frequency, Frequency::Weekly);
        let back = inventory_to_dto(&id, &config);
        assert_eq!(back, inventory(&["Size", "ETag"]));
    }

    #[test]
    fn inventory_configurations_are_checked() {
        let duplicate = inventory_from_dto(inventory(&["Size", "Size"])).unwrap_err();
        assert_eq!(duplicate.code(), &S3ErrorCode::InvalidArgument);
        let unknown = inventory_from_dto(inventory(&["Colour"])).unwrap_err();
        assert_eq!(unknown.code(), &S3ErrorCode::MalformedXML);
        let mut not_arn = inventory(&[]);
        not_arn.destination.s3_bucket_destination.bucket = "reports".into();
        let err = inventory_from_dto(not_arn).unwrap_err();
        assert_eq!(err.code(), &S3ErrorCode::InvalidArgument);
        let mut bad_name = inventory(&[]);
        bad_name.destination.s3_bucket_destination.bucket = "arn:aws:s3:::Bad_Name".into();
        assert!(inventory_from_dto(bad_name).is_err());
        let mut both = inventory(&[]);
        both.destination.s3_bucket_destination.encryption = Some(dto::InventoryEncryption {
            ssekms: Some(dto::SSEKMS { key_id: "k".into() }),
            sses3: Some(dto::SSES3 {}),
        });
        assert_eq!(
            inventory_from_dto(both).unwrap_err().code(),
            &S3ErrorCode::MalformedXML
        );
        let mut format = inventory(&[]);
        format.destination.s3_bucket_destination.format = dto::InventoryFormat::from_static("JSON");
        assert_eq!(
            inventory_from_dto(format).unwrap_err().code(),
            &S3ErrorCode::MalformedXML
        );
    }

    #[test]
    fn ids_must_match_and_be_valid() {
        assert!(check_id("a-1", "a-1").is_ok());
        assert_eq!(
            check_id("a", "b").unwrap_err().code(),
            &S3ErrorCode::InvalidArgument
        );
        assert_eq!(
            check_id("a b", "a b").unwrap_err().code(),
            &S3ErrorCode::InvalidArgument
        );
        assert!(check_query_id("ok").is_ok());
        assert!(check_query_id("").is_err());
    }

    #[test]
    fn filters_keep_their_shape() {
        let tag = || dto::Tag {
            key: Some("team".into()),
            value: Some("blue".into()),
        };
        for filter in [
            dto::MetricsFilter::Prefix("docs/".into()),
            dto::MetricsFilter::Tag(tag()),
            dto::MetricsFilter::AccessPointArn("arn:aws:s3:us-east-1:1:accesspoint/a".into()),
            dto::MetricsFilter::And(dto::MetricsAndOperator {
                access_point_arn: None,
                prefix: Some("docs/".into()),
                tags: Some(vec![tag()]),
            }),
        ] {
            let given = dto::MetricsConfiguration {
                filter: Some(filter),
                id: "m".into(),
            };
            let (id, config) = metrics_from_dto(given.clone()).unwrap();
            assert_eq!(metrics_to_dto(&id, &config), given);
        }
        for filter in [
            dto::AnalyticsFilter::Prefix("p".into()),
            dto::AnalyticsFilter::Tag(tag()),
            dto::AnalyticsFilter::And(dto::AnalyticsAndOperator {
                prefix: None,
                tags: Some(vec![tag()]),
            }),
        ] {
            let given = dto::AnalyticsConfiguration {
                filter: Some(filter),
                id: "a".into(),
                storage_class_analysis: dto::StorageClassAnalysis { data_export: None },
            };
            let (id, config) = analytics_from_dto(given.clone()).unwrap();
            assert_eq!(analytics_to_dto(&id, &config), given);
        }
        let twice = dto::MetricsFilter::And(dto::MetricsAndOperator {
            access_point_arn: None,
            prefix: None,
            tags: Some(vec![tag(), tag()]),
        });
        let err = metrics_from_dto(dto::MetricsConfiguration {
            filter: Some(twice),
            id: "m".into(),
        })
        .unwrap_err();
        assert_eq!(err.code(), &S3ErrorCode::InvalidArgument);
    }

    fn tiering(tiers: &[(&str, i32)]) -> dto::IntelligentTieringConfiguration {
        dto::IntelligentTieringConfiguration {
            filter: Some(dto::IntelligentTieringFilter {
                and: None,
                prefix: Some("cold/".into()),
                tag: None,
            }),
            id: "t".into(),
            status: dto::IntelligentTieringStatus::from_static(
                dto::IntelligentTieringStatus::ENABLED,
            ),
            tierings: tiers
                .iter()
                .map(|(tier, days)| dto::Tiering {
                    access_tier: dto::IntelligentTieringAccessTier::from((*tier).to_owned()),
                    days: *days,
                })
                .collect(),
        }
    }

    #[test]
    fn tierings_are_checked_as_s3_checks_them() {
        let given = tiering(&[("ARCHIVE_ACCESS", 90), ("DEEP_ARCHIVE_ACCESS", 180)]);
        let (id, config) = tiering_from_dto(given.clone()).unwrap();
        assert_eq!(tiering_to_dto(&id, &config), given);
        for bad in [
            &[("ARCHIVE_ACCESS", 89)][..],
            &[("ARCHIVE_ACCESS", 731)],
            &[("DEEP_ARCHIVE_ACCESS", 179)],
            &[("ARCHIVE_ACCESS", 90), ("ARCHIVE_ACCESS", 100)],
            &[("ARCHIVE_ACCESS", 200), ("DEEP_ARCHIVE_ACCESS", 200)],
            &[("ARCHIVE_ACCESS", -1)],
        ] {
            let err = tiering_from_dto(tiering(bad)).unwrap_err();
            assert_eq!(err.code(), &S3ErrorCode::InvalidArgument, "{bad:?}");
        }
        assert_eq!(
            tiering_from_dto(tiering(&[])).unwrap_err().code(),
            &S3ErrorCode::MalformedXML
        );
        let unknown = tiering(&[("GLACIER", 100)]);
        assert_eq!(
            tiering_from_dto(unknown).unwrap_err().code(),
            &S3ErrorCode::MalformedXML
        );
    }

    #[test]
    fn listings_go_a_page_at_a_time() {
        let items: BTreeMap<String, u8> = (0..250).map(|n| (format!("id-{n:03}"), 0)).collect();
        let (first, next) = page(&items, None);
        assert_eq!(first.len(), 100);
        assert_eq!(first[0].0, "id-000");
        assert_eq!(next.as_deref(), Some("id-100"));
        let (second, next) = page(&items, next.as_deref());
        assert_eq!(second[0].0, "id-100");
        let (last, next) = page(&items, next.as_deref());
        assert_eq!(last.len(), 50);
        assert_eq!(next, None);
        let empty = BTreeMap::<String, u8>::new();
        let (none, next) = page(&empty, None);
        assert!(none.is_empty() && next.is_none());
    }

    #[test]
    fn the_payer_is_one_of_two() {
        let config = |payer: &str| dto::RequestPaymentConfiguration {
            payer: dto::Payer::from(payer.to_owned()),
        };
        assert!(requester_pays(&config("Requester")).unwrap());
        assert!(!requester_pays(&config("BucketOwner")).unwrap());
        assert!(requester_pays(&config("Nobody")).is_err());
        assert_eq!(payer(true).as_str(), "Requester");
    }
}
