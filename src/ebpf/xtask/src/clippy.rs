// custom xtask command to run clippy

use std::process::Command;
use clap::Parser;

use crate::build_ebpf::Architecture;

#[derive(Debug, Parser)]
pub struct Options {
    /// Set the endianness of the BPF target
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub bpf_target: Architecture,
    /// Clippy will fix the issues
    #[clap(long)]
    pub fix: bool,
    /// Clippy will ignore if the directory has uncommitted changes
    #[clap(long)]
    pub allow_dirty: bool,
    /// Clippy will fix staged files
    #[clap(long)]
    pub allow_staged: bool,
}

/// Run clippy on the program
pub fn run_clippy(opts: Options) -> Result<(), anyhow::Error> {
    let mut args = vec!["clippy"];
    if opts.fix {
        args.push("--fix")
    }
    if opts.allow_dirty {
        args.push("--allow-dirty")
    }
    if opts.allow_staged {
        args.push("--allow-staged")
    }
    let status = Command::new("cargo")
        .current_dir("ghostwire-ebpf")
        .args(&args)
        .status()
        .expect("failed to build userspace");
    assert!(status.success());
    Ok(())
}

