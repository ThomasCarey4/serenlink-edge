use std::process::ExitCode;

use clap::Parser;
use sl_agent::run::{Args, print_pubkey, run};

fn main() -> ExitCode {
    let args = Args::parse();
    if args.print_pubkey {
        return match print_pubkey(&args) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("sl-agent: {e}");
                ExitCode::FAILURE
            }
        };
    }
    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("sl-agent: {e}");
            return ExitCode::FAILURE;
        }
    };
    match rt.block_on(run(args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("sl-agent: {e}");
            ExitCode::FAILURE
        }
    }
}
