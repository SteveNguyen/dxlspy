//! One-line-per-packet formatter, with optional color.

use std::fmt::Write as _;

use owo_colors::{OwoColorize, Style};

use crate::decode::{Decoded, InstrKind, Instruction, Status};
use crate::parser::{ProtocolVersion, RawPacket};

pub struct Formatter {
    pub color: bool,
    pub hex: bool,
}

impl Formatter {
    pub fn format(&self, ts: &str, d: &Decoded) -> String {
        let mut out = String::new();
        let (tag, body, raw) = match d {
            Decoded::Master(i) => (self.style_master("MASTER →"), self.format_instr(i), &i.raw),
            Decoded::Slave(s) => (
                self.style_slave(&format!("ID {:3} ←", s.raw.id)),
                self.format_status(s),
                &s.raw,
            ),
            Decoded::Unknown(p) => (self.style_unknown("UNKNOWN "), self.format_unknown(p), p),
        };
        let _ = write!(out, "[{ts}] {} {}  {}", tag, self.proto_tag(raw.version), body);
        if self.hex {
            let _ = write!(out, "  {}", self.hexdump(&raw.raw));
        }
        out
    }

    fn proto_tag(&self, v: ProtocolVersion) -> String {
        let s = match v {
            ProtocolVersion::V1 => "v1",
            ProtocolVersion::V2 => "v2",
        };
        if self.color {
            format!("{}", s.dimmed())
        } else {
            s.to_string()
        }
    }

    fn style_master(&self, s: &str) -> String {
        if self.color {
            format!("{}", s.style(Style::new().bold().cyan()))
        } else {
            s.to_string()
        }
    }

    fn style_slave(&self, s: &str) -> String {
        if self.color {
            format!("{}", s.style(Style::new().bold().green()))
        } else {
            s.to_string()
        }
    }

    fn style_unknown(&self, s: &str) -> String {
        if self.color {
            format!("{}", s.style(Style::new().bold().yellow()))
        } else {
            s.to_string()
        }
    }

    fn style_err(&self, s: &str) -> String {
        if self.color {
            format!("{}", s.style(Style::new().bold().red()))
        } else {
            s.to_string()
        }
    }

    fn format_instr(&self, i: &Instruction) -> String {
        let id_str = if i.raw.id == 0xFE {
            "0xFE".to_string()
        } else {
            format!("ID {:3}", i.raw.id)
        };
        match &i.kind {
            InstrKind::Ping => format!("{:<11} → {}", i.name, id_str),
            InstrKind::Read { addr, len } => {
                format!("{:<11} → {}  addr=0x{:04X} len={}", i.name, id_str, addr, len)
            }
            InstrKind::Write { addr, data } | InstrKind::RegWrite { addr, data } => {
                format!(
                    "{:<11} → {}  addr=0x{:04X} data={}",
                    i.name, id_str, addr, hexs(data)
                )
            }
            InstrKind::Action | InstrKind::FactoryReset | InstrKind::Reboot => {
                format!("{:<11} → {}", i.name, id_str)
            }
            InstrKind::SyncRead { addr, len, ids } => format!(
                "{:<11} → {}  addr=0x{:04X} len={} ids={:?}",
                i.name, id_str, addr, len, ids
            ),
            InstrKind::SyncWrite { addr, len, entries } => {
                let mut s = format!(
                    "{:<11} → {}  addr=0x{:04X} len={} ",
                    i.name, id_str, addr, len
                );
                for (id, data) in entries {
                    let _ = write!(s, "[{}={}] ", id, hexs(data));
                }
                s
            }
            InstrKind::BulkRead { entries } => {
                let mut s = format!("{:<11} → {}  ", i.name, id_str);
                for (id, addr, len) in entries {
                    let _ = write!(s, "[ID {} addr=0x{:04X} len={}] ", id, addr, len);
                }
                s
            }
            InstrKind::BulkWrite { entries } => {
                let mut s = format!("{:<11} → {}  ", i.name, id_str);
                for (id, addr, data) in entries {
                    let _ = write!(s, "[ID {} addr=0x{:04X} {}] ", id, addr, hexs(data));
                }
                s
            }
            InstrKind::Other => format!(
                "{:<11} → {}  params={}",
                i.name,
                id_str,
                hexs(&i.raw.params)
            ),
        }
    }

    fn format_status(&self, s: &Status) -> String {
        let err = if s.error == 0 {
            "ok".to_string()
        } else {
            let flags = if s.error_flags.is_empty() {
                format!("0x{:02X}", s.error)
            } else {
                format!("0x{:02X}({})", s.error, s.error_flags.join("|"))
            };
            self.style_err(&format!("err={flags}"))
        };
        format!("STATUS       {}  data={}", err, hexs(&s.data))
    }

    fn format_unknown(&self, p: &RawPacket) -> String {
        format!(
            "?            id={} byte=0x{:02X} params={}",
            p.id,
            p.instr_or_err,
            hexs(&p.params)
        )
    }

    fn hexdump(&self, b: &[u8]) -> String {
        let s = format!("[{}]", hexs(b));
        if self.color {
            format!("{}", s.dimmed())
        } else {
            s
        }
    }
}

fn hexs(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 3);
    for (i, x) in b.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        let _ = write!(s, "{:02X}", x);
    }
    s
}
