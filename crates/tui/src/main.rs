use clap::Parser;
use dns_filter_tui::run;

#[derive(Parser)]
#[command(
    name = "dns-filter-tui",
    about = "Terminal UI dashboard for Ad-Wolf DNS filter"
)]
struct Args {
    /// Path to the query log database
    db: Option<String>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let db_path = args.db.map(std::path::PathBuf::from);
    run(db_path)
}
