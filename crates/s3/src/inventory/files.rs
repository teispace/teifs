//! The data files of a report, in its format: gzipped CSV, ORC compressed with zlib, or
//! Parquet compressed with Snappy (as S3 writes them). Rows are added a page at a time;
//! a file is closed once it's about as big as asked.

use std::{
    io::{self, Write},
    sync::Arc,
};

use arrow_array::{
    ArrayRef, BooleanArray, Int64Array, RecordBatch, StringArray, TimestampMillisecondArray,
};
use arrow_schema::{DataType, Field, Schema as ArrowSchema, TimeUnit};
use flate2::{Compression, write::GzEncoder};
use teifs_types::configs::InventoryFormat;

use super::report::{self, Kind, Schema, Value};

/// The manifest's `fileFormat`.
pub(crate) const fn format_name(format: InventoryFormat) -> &'static str {
    match format {
        InventoryFormat::Csv => "CSV",
        InventoryFormat::Orc => "ORC",
        InventoryFormat::Parquet => "Parquet",
    }
}

/// A data file's name ends with it.
pub(crate) const fn extension(format: InventoryFormat) -> &'static str {
    match format {
        InventoryFormat::Csv => "csv.gz",
        InventoryFormat::Orc => "orc",
        InventoryFormat::Parquet => "parquet",
    }
}

/// A data file's `Content-Type`.
pub(crate) const fn content_type(format: InventoryFormat) -> &'static str {
    match format {
        InventoryFormat::Csv => "application/gzip",
        InventoryFormat::Orc => "application/octet-stream",
        InventoryFormat::Parquet => "application/vnd.apache.parquet",
    }
}

/// The data files being written.
pub(crate) struct DataFiles {
    schema: Schema,
    roll_at: usize,
    /// The CSV file being written, compressed as it goes.
    csv: Option<GzEncoder<Vec<u8>>>,
    /// The rows of the ORC or Parquet file being written, and their size.
    rows: Vec<Vec<Value>>,
    bytes: usize,
}

impl DataFiles {
    /// Files of `schema`'s format, each closed once it's `roll_at` bytes (compressed, for
    /// CSV; before encoding, for ORC and Parquet).
    pub(crate) fn new(schema: &Schema, roll_at: usize) -> Self {
        Self {
            schema: schema.clone(),
            roll_at,
            csv: None,
            rows: Vec::new(),
            bytes: 0,
        }
    }

    /// Adds rows; returns a file when it's full.
    pub(crate) fn push(&mut self, rows: Vec<Vec<Value>>) -> io::Result<Option<Vec<u8>>> {
        let full = if self.schema.format == InventoryFormat::Csv {
            let mut text = String::new();
            for row in &rows {
                report::csv(row, &mut text);
            }
            let file = self
                .csv
                .get_or_insert_with(|| GzEncoder::new(Vec::new(), Compression::default()));
            file.write_all(text.as_bytes())?;
            file.get_ref().len() >= self.roll_at
        } else {
            self.bytes += rows.iter().flatten().map(Value::len).sum::<usize>();
            self.rows.extend(rows);
            self.bytes >= self.roll_at
        };
        if full { self.finish() } else { Ok(None) }
    }

    /// The last file, if rows were added since the last one.
    pub(crate) fn finish(&mut self) -> io::Result<Option<Vec<u8>>> {
        if let Some(file) = self.csv.take() {
            return file.finish().map(Some);
        }
        if self.rows.is_empty() {
            return Ok(None);
        }
        let rows = std::mem::take(&mut self.rows);
        self.bytes = 0;
        let batch = batch(&self.schema, &rows).map_err(io::Error::other)?;
        match self.schema.format {
            InventoryFormat::Orc => orc(&batch),
            InventoryFormat::Parquet | InventoryFormat::Csv => parquet(&batch),
        }
        .map(Some)
    }
}

/// The rows as Arrow columns, typed and named as S3's ORC and Parquet schemas say.
fn batch(schema: &Schema, rows: &[Vec<Value>]) -> Result<RecordBatch, arrow_schema::ArrowError> {
    // Parquet's times are instants (`TIMESTAMP_MILLIS`, UTC); ORC's are its `timestamp`.
    let zone: Option<Arc<str>> = (schema.format == InventoryFormat::Parquet).then(|| "UTC".into());
    let columns = schema.columns();
    let mut fields = Vec::with_capacity(columns.len());
    let mut arrays: Vec<ArrayRef> = Vec::with_capacity(columns.len());
    for (i, column) in columns.iter().enumerate() {
        let values = rows.iter().map(|row| &row[i]);
        let (kind, array): (DataType, ArrayRef) = match column.kind {
            Kind::Text => (
                DataType::Utf8,
                Arc::new(
                    values
                        .map(|v| match v {
                            Value::Text(text) => Some(text.as_str()),
                            _ => None,
                        })
                        .collect::<StringArray>(),
                ),
            ),
            Kind::Bool => (
                DataType::Boolean,
                Arc::new(
                    values
                        .map(|v| match v {
                            Value::Bool(b) => Some(*b),
                            _ => None,
                        })
                        .collect::<BooleanArray>(),
                ),
            ),
            Kind::Int => (
                DataType::Int64,
                Arc::new(
                    values
                        .map(|v| match v {
                            Value::Int(n) => Some(*n),
                            _ => None,
                        })
                        .collect::<Int64Array>(),
                ),
            ),
            Kind::Time => (
                DataType::Timestamp(TimeUnit::Millisecond, zone.clone()),
                Arc::new(
                    values
                        .map(|v| match v {
                            Value::Time(ms) => Some(*ms),
                            _ => None,
                        })
                        .collect::<TimestampMillisecondArray>()
                        .with_timezone_opt(zone.clone()),
                ),
            ),
        };
        fields.push(Field::new(column.snake_name(), kind, !column.required));
        arrays.push(array);
    }
    RecordBatch::try_new(Arc::new(ArrowSchema::new(fields)), arrays)
}

/// An ORC file of the batch, compressed with zlib.
fn orc(batch: &RecordBatch) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut writer = orc_rust::ArrowWriterBuilder::new(&mut out, batch.schema())
        .with_compression(orc_rust::compression::CompressionType::Zlib)
        .try_build()
        .map_err(io::Error::other)?;
    writer.write(batch).map_err(io::Error::other)?;
    writer.close().map_err(io::Error::other)?;
    Ok(out)
}

/// A Parquet file of the batch, compressed with Snappy.
fn parquet(batch: &RecordBatch) -> io::Result<Vec<u8>> {
    let properties = parquet::file::properties::WriterProperties::builder()
        .set_compression(parquet::basic::Compression::SNAPPY)
        .build();
    let mut writer =
        parquet::arrow::ArrowWriter::try_new(Vec::new(), batch.schema(), Some(properties))
            .map_err(io::Error::other)?;
    writer.write(batch).map_err(io::Error::other)?;
    writer.into_inner().map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "test helpers fail the test on any error"
    )]

    use std::io::Read;

    use arrow_array::Array;
    use bytes::Bytes;
    use teifs_types::configs::InventoryField;

    use super::*;

    fn schema(format: InventoryFormat) -> Schema {
        Schema {
            format,
            versions: true,
            fields: vec![
                InventoryField::Size,
                InventoryField::LastModifiedDate,
                InventoryField::IsMultipartUploaded,
            ],
        }
    }

    fn rows() -> Vec<Vec<Value>> {
        let text = |t: &str| Value::Text(t.to_owned());
        vec![
            vec![
                text("photos"),
                text("a b"),
                text("v1"),
                Value::Bool(true),
                Value::Bool(false),
                Value::Int(5),
                Value::Time(1_724_254_106_123),
                Value::Bool(false),
            ],
            vec![
                text("photos"),
                text("gone"),
                Value::None,
                Value::Bool(true),
                Value::Bool(true),
                Value::None,
                Value::Time(1_724_254_106_000),
                Value::None,
            ],
        ]
    }

    /// The batch a file holds, read back.
    fn read(format: InventoryFormat, file: Vec<u8>) -> RecordBatch {
        let file = Bytes::from(file);
        let mut batches: Vec<RecordBatch> = match format {
            InventoryFormat::Orc => orc_rust::ArrowReaderBuilder::try_new(file)
                .unwrap()
                .build()
                .map(Result::unwrap)
                .collect(),
            _ => parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(file)
                .unwrap()
                .build()
                .unwrap()
                .map(Result::unwrap)
                .collect(),
        };
        assert_eq!(batches.len(), 1);
        batches.remove(0)
    }

    #[test]
    fn csv_files_roll_when_full() {
        let gunzip = |file: &[u8]| {
            let mut text = String::new();
            flate2::read::GzDecoder::new(file)
                .read_to_string(&mut text)
                .unwrap();
            text
        };
        let schema = schema(InventoryFormat::Csv);
        let row = || vec![rows().remove(0)];
        let line = "\"photos\",\"a%20b\",\"v1\",\"true\",\"false\",\"5\",\"2024-08-21T15:28:26.123Z\",\"false\"\n";
        let mut files = DataFiles::new(&schema, 1);
        assert_eq!(gunzip(&files.push(row()).unwrap().unwrap()), line);
        assert!(files.finish().unwrap().is_none());
        let mut files = DataFiles::new(&schema, 1 << 20);
        assert!(files.push(row()).unwrap().is_none());
        assert!(files.push(row()).unwrap().is_none());
        assert_eq!(gunzip(&files.finish().unwrap().unwrap()), line.repeat(2));
        // A file closes once it's exactly as big as asked.
        let mut files = DataFiles::new(&schema, 10);
        assert!(
            files.push(row()).unwrap().is_some(),
            "the gzip header alone is 10 bytes"
        );
        assert!(files.finish().unwrap().is_none());
    }

    #[test]
    fn orc_and_parquet_files_hold_typed_columns() {
        for format in [InventoryFormat::Orc, InventoryFormat::Parquet] {
            let mut files = DataFiles::new(&schema(format), 1 << 20);
            assert!(files.push(rows()).unwrap().is_none());
            let batch = read(format, files.finish().unwrap().unwrap());
            assert!(files.finish().unwrap().is_none());
            let names: Vec<&str> = batch
                .schema_ref()
                .fields()
                .iter()
                .map(|f| f.name().as_str())
                .collect();
            assert_eq!(
                names,
                [
                    "bucket",
                    "key",
                    "version_id",
                    "is_latest",
                    "is_delete_marker",
                    "size",
                    "last_modified_date",
                    "is_multipart_uploaded"
                ]
            );
            let field = |name: &str| batch.schema_ref().field_with_name(name).unwrap().clone();
            assert!(!field("bucket").is_nullable() && !field("key").is_nullable());
            assert!(field("version_id").is_nullable() && field("size").is_nullable());
            if format == InventoryFormat::Parquet {
                // TIMESTAMP_MILLIS: instants, in UTC.
                assert_eq!(
                    field("last_modified_date").data_type(),
                    &DataType::Timestamp(TimeUnit::Millisecond, Some("UTC".into()))
                );
            }
            let column = |name: &str| batch.column_by_name(name).unwrap().clone();
            let key = column("key");
            let key = key.as_any().downcast_ref::<StringArray>().unwrap();
            // Keys aren't URL-encoded outside CSV.
            assert_eq!((key.value(0), key.value(1)), ("a b", "gone"), "{format:?}");
            let version = column("version_id");
            assert!(version.is_valid(0) && version.is_null(1), "{format:?}");
            let size = column("size");
            let size = size.as_any().downcast_ref::<Int64Array>().unwrap();
            assert_eq!(size.value(0), 5);
            assert!(size.is_null(1));
            let marker = column("is_delete_marker");
            let marker = marker.as_any().downcast_ref::<BooleanArray>().unwrap();
            assert!(!marker.value(0) && marker.value(1));
            let modified = column("last_modified_date");
            // ORC's reader gives nanoseconds.
            let any = modified.as_any();
            let ms = if let Some(ms) = any.downcast_ref::<TimestampMillisecondArray>() {
                ms.value(0)
            } else {
                let ns = any.downcast_ref::<arrow_array::TimestampNanosecondArray>();
                ns.unwrap().value(0) / 1_000_000
            };
            assert_eq!(ms, 1_724_254_106_123, "{format:?}");
            assert_eq!(batch.num_rows(), 2);
        }
    }

    #[test]
    fn columnar_files_roll_by_size() {
        // The first row's values come to 51 bytes (texts' lengths, 8 for the others), the
        // second's to 37 (1 for each missing value).
        let (first, second) = {
            let mut rows = rows();
            let second = rows.pop().unwrap();
            (rows.pop().unwrap(), second)
        };
        let mut files = DataFiles::new(&schema(InventoryFormat::Parquet), 51);
        assert!(files.push(vec![first]).unwrap().is_some(), "exactly full");
        assert!(
            files.push(vec![second.clone()]).unwrap().is_none(),
            "a new file"
        );
        assert!(files.finish().unwrap().is_some());
        assert!(files.finish().unwrap().is_none());
        let mut files = DataFiles::new(&schema(InventoryFormat::Orc), 37);
        assert!(files.push(vec![second]).unwrap().is_some());
    }

    #[test]
    fn orc_is_zlib_and_parquet_snappy() {
        let file = |format| {
            let mut files = DataFiles::new(&schema(format), 1 << 20);
            files.push(rows()).unwrap();
            Bytes::from(files.finish().unwrap().unwrap())
        };
        let orc = orc_rust::ArrowReaderBuilder::try_new(file(InventoryFormat::Orc)).unwrap();
        let compression = orc.file_metadata().compression().unwrap();
        assert!(matches!(
            compression.compression_type(),
            orc_rust::compression::CompressionType::Zlib
        ));
        let parquet = parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder::try_new(file(
            InventoryFormat::Parquet,
        ))
        .unwrap();
        let columns = parquet.metadata().row_group(0).columns();
        assert!(
            columns
                .iter()
                .all(|c| c.compression() == parquet::basic::Compression::SNAPPY)
        );
    }

    #[test]
    fn formats_are_named_as_s3_names_them() {
        assert_eq!(
            [
                InventoryFormat::Csv,
                InventoryFormat::Orc,
                InventoryFormat::Parquet
            ]
            .map(|f| (format_name(f), extension(f))),
            [("CSV", "csv.gz"), ("ORC", "orc"), ("Parquet", "parquet")]
        );
    }
}
