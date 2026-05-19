//! dxlspy — passive Dynamixel bus sniffer.

mod decode;
mod parser;
mod pretty;

use std::fs::OpenOptions;
use std::io::{self, IsTerminal, Read, Write};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::Local;
use clap::{Parser as ClapParser, ValueEnum};

use crate::decode::Classifier;
use crate::parser::{Parser, Version};
use crate::pretty::Formatter;

#[derive(ClapParser, Debug)]
#[command(
    name = "dxlspy",
    about = "Passive sniffer for Robotis Dynamixel buses (v1 and v2)",
    long_about = "Reads bytes from a USB-serial port and decodes Dynamixel \
                  Protocol v1 and v2 traffic. Open the port read-only; the \
                  spy never transmits."
)]
struct Cli {
    /// Serial port path (e.g. /dev/ttyUSB0, /dev/ttyACM0).
    #[arg(long)]
    port: String,

    /// Bus baud rate (e.g. 1000000, 57600). No default — must be specified.
    #[arg(long)]
    baud: u32,

    /// Protocol version. `auto` detects per-packet from the header bytes.
    #[arg(long, value_enum, default_value_t = ProtoArg::Auto)]
    protocol: ProtoArg,

    /// Append decoded output (uncolored) to this file.
    #[arg(long)]
    log: Option<PathBuf>,

    /// Hide the raw frame bytes (shown by default after the decoded line).
    #[arg(long)]
    no_hex: bool,

    /// Disable color even if stdout is a TTY.
    #[arg(long)]
    no_color: bool,

    /// V1-only: how long after a master instruction we still expect the
    /// status reply. After this window the pending state is dropped, so
    /// a re-scan of the same ID is correctly seen as a fresh PING
    /// instead of a phantom reply. Real v1 turnaround is ~1-5 ms; the
    /// 50 ms default leaves room for USB-serial latency.
    #[arg(long, default_value_t = 50)]
    v1_reply_timeout_ms: u64,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum ProtoArg {
    V1,
    V2,
    Auto,
}

impl From<ProtoArg> for Version {
    fn from(p: ProtoArg) -> Self {
        match p {
            ProtoArg::V1 => Version::V1,
            ProtoArg::V2 => Version::V2,
            ProtoArg::Auto => Version::Auto,
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let color = !cli.no_color && io::stdout().is_terminal();

    let mut port = serialport::new(&cli.port, cli.baud)
        .timeout(Duration::from_millis(100))
        .open()
        .with_context(|| format!("opening serial port {}", cli.port))?;

    let mut parser = Parser::new(cli.protocol.into());
    let mut classifier = Classifier::new(Duration::from_millis(cli.v1_reply_timeout_ms));
    let hex = !cli.no_hex;
    let tty_fmt = Formatter { color, hex };
    let log_fmt = Formatter { color: false, hex };

    let mut log_file = match &cli.log {
        Some(p) => Some(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
                .with_context(|| format!("opening log file {}", p.display()))?,
        ),
        None => None,
    };

    eprintln!(
        "dxlspy: listening on {} @ {} bps (protocol {:?}). Ctrl-C to stop.",
        cli.port, cli.baud, cli.protocol
    );

    let mut buf = [0u8; 256];
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    loop {
        match port.read(&mut buf) {
            Ok(0) => continue,
            Ok(n) => {
                parser.feed(&buf[..n]);
                while let Some(pkt) = parser.next_packet() {
                    let ts = Local::now().format("%H:%M:%S%.3f").to_string();
                    let decoded = classifier.classify(pkt);
                    let line = tty_fmt.format(&ts, &decoded);
                    writeln!(stdout, "{line}")?;
                    if let Some(f) = log_file.as_mut() {
                        writeln!(f, "{}", log_fmt.format(&ts, &decoded))?;
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::TimedOut => continue,
            Err(e) => return Err(e).context("reading from serial port"),
        }
    }
}
