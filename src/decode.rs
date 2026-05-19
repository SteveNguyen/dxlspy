//! Interpret framed `RawPacket`s as either a master instruction or a
//! slave status response, with named instructions and error flags.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::parser::{ProtocolVersion, RawPacket};

const BROADCAST_ID: u8 = 0xFE;

#[derive(Debug, Clone)]
pub enum Decoded {
    Master(Instruction),
    Slave(Status),
    /// Could not confidently classify (v1 ambiguity when bus state is
    /// unknown — e.g. first packets after startup).
    Unknown(RawPacket),
}

#[derive(Debug, Clone)]
pub struct Instruction {
    pub raw: RawPacket,
    pub name: &'static str,
    pub kind: InstrKind,
}

#[derive(Debug, Clone)]
pub enum InstrKind {
    Ping,
    Read { addr: u16, len: u16 },
    Write { addr: u16, data: Vec<u8> },
    RegWrite { addr: u16, data: Vec<u8> },
    Action,
    FactoryReset,
    Reboot,
    SyncRead { addr: u16, len: u16, ids: Vec<u8> },
    SyncWrite { addr: u16, len: u16, entries: Vec<(u8, Vec<u8>)> },
    BulkRead { entries: Vec<(u8, u16, u16)> },
    BulkWrite { entries: Vec<(u8, u16, Vec<u8>)> },
    Other,
}

#[derive(Debug, Clone)]
pub struct Status {
    pub raw: RawPacket,
    pub error: u8,
    pub error_flags: Vec<&'static str>,
    /// The user-visible params (i.e. without the v2 error byte).
    pub data: Vec<u8>,
}

/// Stateful classifier. For v1 we need to remember what instruction the
/// master last sent to each ID, so the next packet from that ID can be
/// recognised as a status response.
///
/// Pending entries expire after `reply_timeout`. This is essential because
/// in v1 a PING-to-ID-N and a STATUS-from-ID-N-with-error-0x01 are byte-
/// identical. Without expiry, a master re-scanning an absent ID gets
/// matched against the previous scan's pending entry and mislabeled as a
/// status reply with INPUT_VOLTAGE error.
#[derive(Debug)]
pub struct Classifier {
    v1_pending: HashMap<u8, Instant>,
    reply_timeout: Duration,
}

impl Default for Classifier {
    fn default() -> Self {
        Self::new(Duration::from_millis(50))
    }
}

impl Classifier {
    pub fn new(reply_timeout: Duration) -> Self {
        Self {
            v1_pending: HashMap::new(),
            reply_timeout,
        }
    }

    pub fn classify(&mut self, pkt: RawPacket) -> Decoded {
        match pkt.version {
            ProtocolVersion::V2 => self.classify_v2(pkt),
            ProtocolVersion::V1 => self.classify_v1(pkt),
        }
    }

    fn expire_pending(&mut self, now: Instant) {
        let timeout = self.reply_timeout;
        self.v1_pending.retain(|_, t| now.duration_since(*t) < timeout);
    }

    fn classify_v2(&mut self, pkt: RawPacket) -> Decoded {
        // V2 is unambiguous: status packets have instruction byte 0x55.
        if pkt.instr_or_err == 0x55 {
            // V2 status: first param byte is the error, rest is data.
            let (error, data) = if pkt.params.is_empty() {
                (0, vec![])
            } else {
                (pkt.params[0], pkt.params[1..].to_vec())
            };
            Decoded::Slave(Status {
                error_flags: v2_error_flags(error),
                error,
                data,
                raw: pkt,
            })
        } else {
            Decoded::Master(decode_v2_instruction(pkt))
        }
    }

    fn classify_v1(&mut self, pkt: RawPacket) -> Decoded {
        let now = Instant::now();
        self.expire_pending(now);

        // Broadcasts are always master-side (slaves cannot send to 0xFE).
        if pkt.id == BROADCAST_ID {
            self.v1_pending.clear();
            return Decoded::Master(decode_v1_instruction(pkt));
        }

        let known_instr = v1_instr_name(pkt.instr_or_err).is_some();
        let pending = self.v1_pending.contains_key(&pkt.id);

        if pending {
            // Recent master instruction to this ID — treat as the reply.
            self.v1_pending.remove(&pkt.id);
            return Decoded::Slave(Status {
                error_flags: v1_error_flags(pkt.instr_or_err),
                error: pkt.instr_or_err,
                data: pkt.params.clone(),
                raw: pkt,
            });
        }

        if known_instr {
            // Master sending to a specific ID — expect a reply soon.
            self.v1_pending.insert(pkt.id, now);
            return Decoded::Master(decode_v1_instruction(pkt));
        }

        // Unknown instruction byte and no pending: could be a status
        // packet with a non-zero error, or a malformed master frame.
        // Mark as Unknown so the user can investigate.
        Decoded::Unknown(pkt)
    }
}

fn decode_v1_instruction(pkt: RawPacket) -> Instruction {
    let name = v1_instr_name(pkt.instr_or_err).unwrap_or("UNKNOWN");
    let kind = match pkt.instr_or_err {
        0x01 => InstrKind::Ping,
        0x02 if pkt.params.len() >= 2 => InstrKind::Read {
            addr: pkt.params[0] as u16,
            len: pkt.params[1] as u16,
        },
        0x03 if !pkt.params.is_empty() => InstrKind::Write {
            addr: pkt.params[0] as u16,
            data: pkt.params[1..].to_vec(),
        },
        0x04 if !pkt.params.is_empty() => InstrKind::RegWrite {
            addr: pkt.params[0] as u16,
            data: pkt.params[1..].to_vec(),
        },
        0x05 => InstrKind::Action,
        0x06 => InstrKind::FactoryReset,
        0x08 => InstrKind::Reboot,
        0x83 if pkt.params.len() >= 2 => {
            // SYNC_WRITE v1: ADDR LEN [ID DATA...]*
            let addr = pkt.params[0] as u16;
            let len = pkt.params[1] as u16;
            let mut entries = Vec::new();
            let stride = 1 + len as usize;
            let body = &pkt.params[2..];
            if stride > 0 {
                for chunk in body.chunks_exact(stride) {
                    entries.push((chunk[0], chunk[1..].to_vec()));
                }
            }
            InstrKind::SyncWrite { addr, len, entries }
        }
        0x92 if pkt.params.len() >= 1 => {
            // BULK_READ v1: 0x00 [LEN ID ADDR]*
            // First param is reserved 0x00, then triplets.
            let mut entries = Vec::new();
            let body = &pkt.params[1..];
            for chunk in body.chunks_exact(3) {
                let len = chunk[0] as u16;
                let id = chunk[1];
                let addr = chunk[2] as u16;
                entries.push((id, addr, len));
            }
            InstrKind::BulkRead { entries }
        }
        _ => InstrKind::Other,
    };
    Instruction { raw: pkt, name, kind }
}

fn decode_v2_instruction(pkt: RawPacket) -> Instruction {
    let name = v2_instr_name(pkt.instr_or_err).unwrap_or("UNKNOWN");
    let kind = match pkt.instr_or_err {
        0x01 => InstrKind::Ping,
        0x02 if pkt.params.len() >= 4 => InstrKind::Read {
            addr: u16::from_le_bytes([pkt.params[0], pkt.params[1]]),
            len: u16::from_le_bytes([pkt.params[2], pkt.params[3]]),
        },
        0x03 if pkt.params.len() >= 2 => InstrKind::Write {
            addr: u16::from_le_bytes([pkt.params[0], pkt.params[1]]),
            data: pkt.params[2..].to_vec(),
        },
        0x04 if pkt.params.len() >= 2 => InstrKind::RegWrite {
            addr: u16::from_le_bytes([pkt.params[0], pkt.params[1]]),
            data: pkt.params[2..].to_vec(),
        },
        0x05 => InstrKind::Action,
        0x06 => InstrKind::FactoryReset,
        0x08 => InstrKind::Reboot,
        0x82 if pkt.params.len() >= 4 => {
            // SYNC_READ v2: ADDR_L ADDR_H LEN_L LEN_H ID1 ID2 ...
            let addr = u16::from_le_bytes([pkt.params[0], pkt.params[1]]);
            let len = u16::from_le_bytes([pkt.params[2], pkt.params[3]]);
            let ids = pkt.params[4..].to_vec();
            InstrKind::SyncRead { addr, len, ids }
        }
        0x83 if pkt.params.len() >= 4 => {
            // SYNC_WRITE v2: ADDR_L ADDR_H LEN_L LEN_H [ID DATA...]*
            let addr = u16::from_le_bytes([pkt.params[0], pkt.params[1]]);
            let len = u16::from_le_bytes([pkt.params[2], pkt.params[3]]);
            let mut entries = Vec::new();
            let stride = 1 + len as usize;
            let body = &pkt.params[4..];
            if stride > 0 {
                for chunk in body.chunks_exact(stride) {
                    entries.push((chunk[0], chunk[1..].to_vec()));
                }
            }
            InstrKind::SyncWrite { addr, len, entries }
        }
        0x93 if !pkt.params.is_empty() => {
            // BULK_WRITE v2: [ID ADDR_L ADDR_H LEN_L LEN_H DATA...]*
            let mut entries = Vec::new();
            let mut i = 0;
            while i + 5 <= pkt.params.len() {
                let id = pkt.params[i];
                let addr = u16::from_le_bytes([pkt.params[i + 1], pkt.params[i + 2]]);
                let len = u16::from_le_bytes([pkt.params[i + 3], pkt.params[i + 4]]) as usize;
                let end = i + 5 + len;
                if end > pkt.params.len() {
                    break;
                }
                entries.push((id, addr, pkt.params[i + 5..end].to_vec()));
                i = end;
            }
            InstrKind::BulkWrite { entries }
        }
        _ => InstrKind::Other,
    };
    Instruction { raw: pkt, name, kind }
}

fn v1_instr_name(b: u8) -> Option<&'static str> {
    Some(match b {
        0x01 => "PING",
        0x02 => "READ",
        0x03 => "WRITE",
        0x04 => "REG_WRITE",
        0x05 => "ACTION",
        0x06 => "FACTORY_RESET",
        0x08 => "REBOOT",
        0x83 => "SYNC_WRITE",
        0x92 => "BULK_READ",
        _ => return None,
    })
}

fn v2_instr_name(b: u8) -> Option<&'static str> {
    Some(match b {
        0x01 => "PING",
        0x02 => "READ",
        0x03 => "WRITE",
        0x04 => "REG_WRITE",
        0x05 => "ACTION",
        0x06 => "FACTORY_RESET",
        0x08 => "REBOOT",
        0x10 => "CLEAR",
        0x20 => "CONTROL_TABLE_BACKUP",
        0x55 => "STATUS",
        0x82 => "SYNC_READ",
        0x83 => "SYNC_WRITE",
        0x8A => "FAST_SYNC_READ",
        0x92 => "BULK_READ",
        0x93 => "BULK_WRITE",
        0x9A => "FAST_BULK_READ",
        _ => return None,
    })
}

/// V1 error byte bitmask names (Dynamixel emanual).
fn v1_error_flags(b: u8) -> Vec<&'static str> {
    let mut out = Vec::new();
    if b & 0x01 != 0 { out.push("INPUT_VOLTAGE"); }
    if b & 0x02 != 0 { out.push("ANGLE_LIMIT"); }
    if b & 0x04 != 0 { out.push("OVERHEATING"); }
    if b & 0x08 != 0 { out.push("RANGE"); }
    if b & 0x10 != 0 { out.push("CHECKSUM"); }
    if b & 0x20 != 0 { out.push("OVERLOAD"); }
    if b & 0x40 != 0 { out.push("INSTRUCTION"); }
    out
}

/// V2 error byte: high bit = HW alert latch, low 7 bits = result code.
fn v2_error_flags(b: u8) -> Vec<&'static str> {
    let mut out = Vec::new();
    if b & 0x80 != 0 {
        out.push("HW_ALERT");
    }
    let code = b & 0x7F;
    if code != 0 {
        out.push(match code {
            0x01 => "RESULT_FAIL",
            0x02 => "INSTRUCTION_ERR",
            0x03 => "CRC_ERR",
            0x04 => "DATA_RANGE",
            0x05 => "DATA_LENGTH",
            0x06 => "DATA_LIMIT",
            0x07 => "ACCESS",
            _ => "UNKNOWN_ERR",
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::{Parser, Version};

    fn parse_one(bytes: &[u8], mode: Version) -> RawPacket {
        let mut p = Parser::new(mode);
        p.feed(bytes);
        p.next_packet().expect("parsed")
    }

    fn v2_frame(id: u8, instr: u8, params: &[u8]) -> Vec<u8> {
        let len = (params.len() + 3) as u16;
        let mut p = vec![0xFF, 0xFF, 0xFD, 0x00, id, len as u8, (len >> 8) as u8, instr];
        p.extend_from_slice(params);
        let crc = crate::parser::crc16_ibm(&p);
        p.push(crc as u8);
        p.push((crc >> 8) as u8);
        p
    }

    #[test]
    fn v2_status_is_slave() {
        let raw = parse_one(&v2_frame(0x05, 0x55, &[0x00, 0xAA, 0xBB]), Version::V2);
        let mut c = Classifier::default();
        match c.classify(raw) {
            Decoded::Slave(s) => {
                assert_eq!(s.error, 0);
                assert_eq!(s.data, vec![0xAA, 0xBB]);
            }
            _ => panic!("expected slave"),
        }
    }

    #[test]
    fn v2_read_is_master_with_kind() {
        // READ addr 0x0084 (132), len 4
        let raw = parse_one(&v2_frame(0x01, 0x02, &[0x84, 0x00, 0x04, 0x00]), Version::V2);
        let mut c = Classifier::default();
        match c.classify(raw) {
            Decoded::Master(i) => {
                assert_eq!(i.name, "READ");
                match i.kind {
                    InstrKind::Read { addr, len } => {
                        assert_eq!(addr, 132);
                        assert_eq!(len, 4);
                    }
                    _ => panic!("expected Read"),
                }
            }
            _ => panic!("expected master"),
        }
    }

    #[test]
    fn v1_request_then_reply_pairing() {
        // Master READ to ID 5
        let req_bytes = {
            let body = [5u8, 4, 2, 0x24, 0x02];
            let sum: u32 = body.iter().map(|&b| b as u32).sum();
            let cs = !(sum as u8);
            let mut v = vec![0xFF, 0xFF];
            v.extend_from_slice(&body);
            v.push(cs);
            v
        };
        // Slave reply from ID 5: err=0, params=[0x00, 0x08]
        let rep_bytes = {
            let body = [5u8, 4, 0, 0x00, 0x08];
            let sum: u32 = body.iter().map(|&b| b as u32).sum();
            let cs = !(sum as u8);
            let mut v = vec![0xFF, 0xFF];
            v.extend_from_slice(&body);
            v.push(cs);
            v
        };
        let mut p = Parser::new(Version::V1);
        p.feed(&req_bytes);
        p.feed(&rep_bytes);
        let mut c = Classifier::default();
        let a = c.classify(p.next_packet().unwrap());
        let b = c.classify(p.next_packet().unwrap());
        assert!(matches!(a, Decoded::Master(_)));
        assert!(matches!(b, Decoded::Slave(_)));
    }

    #[test]
    fn v1_broadcast_is_master_no_pending() {
        let mut bytes = vec![0xFF, 0xFF, 0xFE, 4, 0x83, 0x1E, 0x04];
        let sum: u32 = bytes[2..].iter().map(|&b| b as u32).sum();
        bytes.push(!(sum as u8));
        let raw = parse_one(&bytes, Version::V1);
        let mut c = Classifier::default();
        let d = c.classify(raw);
        assert!(matches!(d, Decoded::Master(_)));
        assert!(c.v1_pending.is_empty());
    }

    /// The regression that motivated the timeout: a master scans absent
    /// IDs; a long time later it scans them again. Without expiry the
    /// second-scan PING gets matched to the first-scan pending entry
    /// and mislabeled as a STATUS reply with error byte 0x01
    /// (INPUT_VOLTAGE). With expiry it's correctly re-classified as a
    /// fresh master PING.
    #[test]
    fn v1_pending_expires_after_timeout() {
        // Build PING to ID 0: FF FF 00 02 01 FC
        let mut bytes = vec![0xFF, 0xFF, 0x00, 0x02, 0x01];
        let sum: u32 = bytes[2..].iter().map(|&b| b as u32).sum();
        bytes.push(!(sum as u8));

        let parse = |b: &[u8]| {
            let mut p = Parser::new(Version::V1);
            p.feed(b);
            p.next_packet().expect("parsed")
        };

        let mut c = Classifier::new(Duration::from_millis(5));
        // First scan: master pings absent ID 0.
        let a = c.classify(parse(&bytes));
        assert!(matches!(a, Decoded::Master(_)), "first ping should be master");

        // Wait long enough for the pending entry to expire.
        std::thread::sleep(Duration::from_millis(15));

        // Second scan: same exact bytes. With expiry, this is a fresh master PING.
        let b = c.classify(parse(&bytes));
        assert!(
            matches!(b, Decoded::Master(_)),
            "second ping (after timeout) should be master, not a phantom status reply"
        );
    }

    /// Without expiry (i.e. when the timeout is huge), the back-to-back
    /// identical frames intentionally pair up — first as instruction,
    /// second as reply. This documents the v1 ambiguity.
    #[test]
    fn v1_pending_within_timeout_still_pairs() {
        let mut bytes = vec![0xFF, 0xFF, 0x00, 0x02, 0x01];
        let sum: u32 = bytes[2..].iter().map(|&b| b as u32).sum();
        bytes.push(!(sum as u8));
        let parse = |b: &[u8]| {
            let mut p = Parser::new(Version::V1);
            p.feed(b);
            p.next_packet().expect("parsed")
        };
        let mut c = Classifier::new(Duration::from_secs(60));
        let a = c.classify(parse(&bytes));
        let b = c.classify(parse(&bytes));
        assert!(matches!(a, Decoded::Master(_)));
        assert!(matches!(b, Decoded::Slave(_)));
    }
}
