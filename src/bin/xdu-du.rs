use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use duckdb::Connection;

use xdu::format_bytes;

#[derive(Parser, Debug)]
#[command(
    name = "xdu-du",
    about = "Summarize disk usage from a file metadata index",
    disable_help_flag = true,
    after_help = "Examples:
  xdu-du -i /index/scratch -h
  xdu-du -i /index/scratch -h -c
  xdu-du -i /index/scratch -s -h
  xdu-du -i /index/scratch -h /gpfs/scratch/alice /gpfs/scratch/bob
  xdu-du -i /index/scratch -h -c /gpfs/scratch/alice /gpfs/scratch/bob
  xdu-du -i /index/scratch -h -u alice"
)]
struct Args {
    /// Path to the Parquet index directory
    #[arg(short, long, value_name = "DIR", env = "XDU_INDEX")]
    index: PathBuf,

    /// Summarize: show only a total for each argument (or grand total if no args)
    #[arg(short, long)]
    summarize: bool,

    /// Human-readable sizes (e.g. 1.5 GiB)
    #[arg(short = 'h', long)]
    human_readable: bool,

    /// Produce a grand total
    #[arg(short = 'c', long)]
    total: bool,

    /// Restrict to a single partition (user directory)
    #[arg(short = 'u', long, value_name = "NAME")]
    partition: Option<String>,

    /// Path prefixes to summarize (default: all partitions)
    paths: Vec<String>,

    /// Show help
    #[arg(long, action = clap::ArgAction::Help)]
    help: Option<bool>,
}

fn fmt_size(bytes: i64, human: bool) -> String {
    if human { format_bytes(bytes as u64) } else { bytes.to_string() }
}

fn main() -> Result<()> {
    let args = Args::parse();

    let index_path = args.index.canonicalize()
        .with_context(|| format!("Index directory not found: {}", args.index.display()))?;

    let glob = if let Some(ref p) = args.partition {
        format!("{}/{}/*.parquet", index_path.display(), p)
    } else {
        format!("{}/*/*.parquet", index_path.display())
    };

    let conn = Connection::open_in_memory()?;
    let stdout = io::stdout();
    let mut out = stdout.lock();
    let mut grand_total: i64 = 0;

    if args.paths.is_empty() {
        if args.summarize {
            let sql = format!("SELECT COALESCE(SUM(size), 0) FROM read_parquet('{}')", glob);
            let mut stmt = conn.prepare(&sql)?;
            let mut rows = stmt.query([])?;
            if let Some(row) = rows.next()? {
                let total: i64 = row.get(0)?;
                grand_total = total;
                writeln!(out, "{}\t.", fmt_size(total, args.human_readable))?;
            }
        } else {
            let sql = format!(
                "SELECT regexp_extract(filename, '.*/([^/]+)/[^/]+\\.parquet$', 1) as partition, \
                 COALESCE(SUM(size), 0) as total_size \
                 FROM read_parquet('{}', filename=true) \
                 GROUP BY partition \
                 HAVING partition IS NOT NULL AND partition != '' \
                 ORDER BY partition",
                glob
            );
            let mut stmt = conn.prepare(&sql)?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let partition: String = row.get(0)?;
                let size: i64 = row.get(1)?;
                grand_total += size;
                writeln!(out, "{}\t{}", fmt_size(size, args.human_readable), partition)?;
            }
        }
    } else {
        for path in &args.paths {
            let path = path.trim_end_matches('/');
            let sql = format!(
                "SELECT COALESCE(SUM(size), 0) FROM read_parquet('{}') \
                 WHERE path LIKE '{}/%' OR path = '{}'",
                glob, path, path
            );
            let mut stmt = conn.prepare(&sql)?;
            let mut rows = stmt.query([])?;
            if let Some(row) = rows.next()? {
                let size: i64 = row.get(0)?;
                grand_total += size;
                writeln!(out, "{}\t{}", fmt_size(size, args.human_readable), path)?;
            }
        }
    }

    if args.total {
        writeln!(out, "{}\ttotal", fmt_size(grand_total, args.human_readable))?;
    }

    Ok(())
}
