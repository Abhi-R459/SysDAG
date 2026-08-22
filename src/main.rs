use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};

use sysdag::config::Config;
use sysdag::help::{ABOUT, HELP};
use sysdag::pipeline::{analyze_path, print_report, run_demo, Mode};
use sysdag::sandbox::doctor;
use sysdag::tui::{self, Session};
use sysdag::visualizer::to_dot;

#[derive(Parser, Debug)]
#[command(
    name = "sysdag",
    version,
    about = ABOUT,
    after_help = HELP,
    help_template = "{after-help}",
    disable_help_subcommand = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Program, source file, or strace log (shortcut for `sysdag run <file>`)
    path: Option<PathBuf>,

    /// Arguments forwarded to the target inside the micro-VM
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    target_args: Vec<String>,

    #[arg(long, global = true)]
    config: Option<PathBuf>,

    #[arg(long, global = true)]
    json: bool,

    /// Skip the TUI and print a plain report
    #[arg(long, global = true)]
    plain: bool,

    #[arg(long, global = true)]
    workdir: Option<PathBuf>,

    /// Baseline identity (defaults to the file digest for programs, `strace-anonymous` for traces)
    #[arg(long, global = true)]
    id: Option<String>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run a target or analyze a trace (train if no baseline, else monitor)
    Run(RunArgs),
    /// Force baseline training from a clean execution or trace
    Train(RunArgs),
    /// Score a run against a frozen baseline
    Monitor(RunArgs),
    /// Train on clean demo workloads, then score a decoy exfiltration
    Demo,
    /// Check host prerequisites (Docker / guest image)
    Doctor,
    /// Print Graphviz DOT for a saved GraphRecord JSON
    Viz { graph: PathBuf },
}

#[derive(Parser, Debug)]
struct RunArgs {
    /// Program (.c/.py/.sh/ELF) or strace log
    path: PathBuf,
    /// Arguments forwarded to the target inside the micro-VM
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    target_args: Vec<String>,
}

fn main() -> ExitCode {
    match real_main() {
        Ok(code) => ExitCode::from(code as u8),
        Err(err) => {
            eprintln!("sysdag: {err:#}");
            ExitCode::from(1)
        }
    }
}

fn real_main() -> Result<i32> {
    let cli = Cli::parse();
    let cfg = Config::load(cli.config.as_deref())?;
    let work = cli.workdir.unwrap_or_else(|| PathBuf::from(".sysdag"));
    let baseline_dir = work.join("baselines");

    match cli.command {
        Some(Command::Doctor) => {
            doctor()?;
            Ok(0)
        }
        Some(Command::Demo) => run_demo(&cfg, &work, cli.json),
        Some(Command::Viz { graph }) => {
            let text = std::fs::read_to_string(&graph)?;
            let g: sysdag::graph::GraphRecord = serde_json::from_str(&text)?;
            print!("{}", to_dot(&g));
            Ok(0)
        }
        Some(Command::Train(args)) => dispatch(
            &args.path,
            Mode::Train,
            &cfg,
            &work,
            &baseline_dir,
            &args.target_args,
            cli.json,
            cli.plain,
            cli.id.as_deref(),
        ),
        Some(Command::Monitor(args)) => dispatch(
            &args.path,
            Mode::Monitor,
            &cfg,
            &work,
            &baseline_dir,
            &args.target_args,
            cli.json,
            cli.plain,
            cli.id.as_deref(),
        ),
        Some(Command::Run(args)) => dispatch(
            &args.path,
            Mode::Auto,
            &cfg,
            &work,
            &baseline_dir,
            &args.target_args,
            cli.json,
            cli.plain,
            cli.id.as_deref(),
        ),
        None => {
            let Some(path) = cli.path else {
                print!("{HELP}");
                return Ok(0);
            };
            dispatch(
                &path,
                Mode::Auto,
                &cfg,
                &work,
                &baseline_dir,
                &cli.target_args,
                cli.json,
                cli.plain,
                cli.id.as_deref(),
            )
        }
    }
}

fn dispatch(
    path: &std::path::Path,
    mode: Mode,
    cfg: &Config,
    work: &std::path::Path,
    baseline_dir: &std::path::Path,
    target_args: &[String],
    json: bool,
    plain: bool,
    identity: Option<&str>,
) -> Result<i32> {
    if !path.exists() {
        bail!("{} does not exist", path.display());
    }
    if tui::should_open(plain, json) {
        return tui::run(Session {
            path: path.to_path_buf(),
            mode,
            cfg: cfg.clone(),
            work: work.to_path_buf(),
            baseline_dir: baseline_dir.to_path_buf(),
            target_args: target_args.to_vec(),
            identity: identity.map(str::to_string),
        });
    }
    let report = analyze_path(
        path,
        mode,
        cfg,
        work,
        baseline_dir,
        target_args,
        true,
        identity,
    )?;
    print_report(&report, json)
}
