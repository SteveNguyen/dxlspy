//! Streaming framer for Dynamixel Protocol v1 and v2.
//!
//! Feeds raw bytes from the serial port and emits framed `RawPacket`s.
//! Recovers automatically on bad checksum/CRC or out-of-frame bytes by
//! advancing one byte and rescanning for a header.
//!
//! The parser is "framing only" — it does not interpret the instruction
//! byte or split master/slave. That is `decode.rs`'s job.

use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    V1,
    V2,
    Auto,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawPacket {
    pub version: ProtocolVersion,
    /// ID byte (broadcast for v1 = 0xFE, for v2 = 0xFE).
    pub id: u8,
    /// For instruction packets this is the instruction byte.
    /// For status packets this is the error byte (v1) or 0x55 (v2).
    pub instr_or_err: u8,
    /// Already byte-unstuffed for v2.
    pub params: Vec<u8>,
    /// The complete on-wire bytes (still stuffed for v2), for hex dump.
    pub raw: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVersion {
    V1,
    V2,
}

#[derive(Debug)]
pub struct Parser {
    buf: VecDeque<u8>,
    mode: Version,
}

impl Parser {
    pub fn new(mode: Version) -> Self {
        Self {
            buf: VecDeque::with_capacity(512),
            mode,
        }
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        self.buf.extend(bytes);
    }

    /// Try to extract one packet from the buffer.
    ///
    /// Returns `Some(pkt)` when a fully-framed, checksum-valid packet is
    /// available. Returns `None` when more bytes are needed. On garbage
    /// or bad checksums, it advances and keeps scanning, so calling
    /// `next_packet` in a loop will drain everything currently extractable.
    pub fn next_packet(&mut self) -> Option<RawPacket> {
        loop {
            // Need at least 2 bytes to even see the v1 header.
            if self.buf.len() < 2 {
                return None;
            }

            // Find next FF FF header.
            let mut start = None;
            for i in 0..self.buf.len().saturating_sub(1) {
                if self.buf[i] == 0xFF && self.buf[i + 1] == 0xFF {
                    start = Some(i);
                    break;
                }
            }
            let Some(s) = start else {
                // No header at all — keep the last byte in case it's the
                // first FF of a future header.
                let drop = self.buf.len().saturating_sub(1);
                self.buf.drain(..drop);
                return None;
            };
            // Discard pre-header garbage.
            if s > 0 {
                self.buf.drain(..s);
            }

            // Decide version.
            let is_v2 = self.buf.len() >= 4
                && self.buf[2] == 0xFD
                && self.buf[3] == 0x00;

            match (self.mode, is_v2) {
                (Version::V1, _) => match self.try_v1() {
                    TryResult::Ok(p) => return Some(p),
                    TryResult::NeedMore => return None,
                    TryResult::Bad => {
                        self.buf.pop_front();
                        continue;
                    }
                },
                (Version::V2, _) => {
                    if !is_v2 && self.buf.len() >= 4 {
                        // Looked like v1 but we're in v2-only mode.
                        self.buf.pop_front();
                        continue;
                    }
                    match self.try_v2() {
                        TryResult::Ok(p) => return Some(p),
                        TryResult::NeedMore => return None,
                        TryResult::Bad => {
                            self.buf.pop_front();
                            continue;
                        }
                    }
                }
                (Version::Auto, true) => match self.try_v2() {
                    TryResult::Ok(p) => return Some(p),
                    TryResult::NeedMore => return None,
                    TryResult::Bad => {
                        self.buf.pop_front();
                        continue;
                    }
                },
                (Version::Auto, false) => match self.try_v1() {
                    TryResult::Ok(p) => return Some(p),
                    TryResult::NeedMore => return None,
                    TryResult::Bad => {
                        self.buf.pop_front();
                        continue;
                    }
                },
            }
        }
    }

    /// V1 frame: FF FF ID LEN INSTR/ERR PARAMS... CHECKSUM
    /// Total length = LEN + 4. LEN counts INSTR/ERR + PARAMS + CHECKSUM.
    fn try_v1(&mut self) -> TryResult {
        if self.buf.len() < 4 {
            return TryResult::NeedMore;
        }
        let id = self.buf[2];
        let len = self.buf[3] as usize;
        if len < 2 {
            // Minimum: instr + checksum.
            return TryResult::Bad;
        }
        let total = 4 + len;
        if self.buf.len() < total {
            return TryResult::NeedMore;
        }
        // Collect frame.
        let frame: Vec<u8> = self.buf.iter().take(total).copied().collect();
        // Checksum is ~(ID + LEN + INSTR/ERR + PARAMS) low byte.
        let sum: u32 = frame[2..total - 1].iter().map(|&b| b as u32).sum();
        let expected = (!(sum as u8)) & 0xFF;
        let got = frame[total - 1];
        if expected != got {
            return TryResult::Bad;
        }
        let pkt = RawPacket {
            version: ProtocolVersion::V1,
            id,
            instr_or_err: frame[4],
            params: frame[5..total - 1].to_vec(),
            raw: frame,
        };
        self.buf.drain(..total);
        TryResult::Ok(pkt)
    }

    /// V2 frame: FF FF FD 00 ID LEN_L LEN_H INSTR PARAMS... CRC_L CRC_H
    /// LEN counts INSTR + PARAMS + CRC. Total = 7 + LEN.
    /// Params are byte-stuffed: any FF FF FD in the payload becomes FF FF FD FD.
    fn try_v2(&mut self) -> TryResult {
        if self.buf.len() < 7 {
            return TryResult::NeedMore;
        }
        let id = self.buf[4];
        let len = (self.buf[5] as usize) | ((self.buf[6] as usize) << 8);
        if len < 3 {
            // Minimum: instr + 2 CRC bytes.
            return TryResult::Bad;
        }
        let total = 7 + len;
        // Hard cap to refuse absurd lengths (corrupted len field).
        if total > 1024 {
            return TryResult::Bad;
        }
        if self.buf.len() < total {
            return TryResult::NeedMore;
        }
        let frame: Vec<u8> = self.buf.iter().take(total).copied().collect();
        let crc_got = (frame[total - 2] as u16) | ((frame[total - 1] as u16) << 8);
        let crc_calc = crc16_ibm(&frame[..total - 2]);
        if crc_got != crc_calc {
            return TryResult::Bad;
        }
        let instr = frame[7];
        let stuffed_params = &frame[8..total - 2];
        let params = v2_unstuff(stuffed_params);
        let pkt = RawPacket {
            version: ProtocolVersion::V2,
            id,
            instr_or_err: instr,
            params,
            raw: frame,
        };
        self.buf.drain(..total);
        TryResult::Ok(pkt)
    }
}

enum TryResult {
    Ok(RawPacket),
    NeedMore,
    Bad,
}

/// Reverse the byte-stuffing applied to v2 packet payloads.
/// On the wire, any sequence `FF FF FD` inside the payload is followed by
/// a stuffing `FD` to disambiguate from the frame header. Strip those.
fn v2_unstuff(stuffed: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(stuffed.len());
    let mut i = 0;
    while i < stuffed.len() {
        out.push(stuffed[i]);
        if i + 3 < stuffed.len()
            && stuffed[i] == 0xFF
            && stuffed[i + 1] == 0xFF
            && stuffed[i + 2] == 0xFD
            && stuffed[i + 3] == 0xFD
        {
            out.push(stuffed[i + 1]);
            out.push(stuffed[i + 2]);
            i += 4;
        } else {
            i += 1;
        }
    }
    out
}

/// CRC-16/IBM-3740 with polynomial 0x8005, init 0, no reflection — the
/// variant Robotis specifies for Protocol 2.0. The table is the standard
/// one from the Dynamixel SDK reference.
pub fn crc16_ibm(data: &[u8]) -> u16 {
    const TABLE: [u16; 256] = {
        let poly: u16 = 0x8005;
        let mut t = [0u16; 256];
        let mut i = 0u16;
        while i < 256 {
            let mut crc = i << 8;
            let mut j = 0;
            while j < 8 {
                if crc & 0x8000 != 0 {
                    crc = (crc << 1) ^ poly;
                } else {
                    crc <<= 1;
                }
                j += 1;
            }
            t[i as usize] = crc;
            i += 1;
        }
        t
    };
    let mut crc: u16 = 0;
    for &b in data {
        let idx = ((crc >> 8) as u8 ^ b) as usize;
        crc = (crc << 8) ^ TABLE[idx];
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v1_checksum(body: &[u8]) -> u8 {
        let s: u32 = body.iter().map(|&b| b as u32).sum();
        !(s as u8)
    }

    fn build_v1(id: u8, instr: u8, params: &[u8]) -> Vec<u8> {
        let len = (params.len() + 2) as u8;
        let mut p = vec![0xFF, 0xFF, id, len, instr];
        p.extend_from_slice(params);
        p.push(v1_checksum(&p[2..]));
        p
    }

    fn build_v2(id: u8, instr: u8, params: &[u8]) -> Vec<u8> {
        let len = (params.len() + 3) as u16;
        let mut p = vec![0xFF, 0xFF, 0xFD, 0x00, id, len as u8, (len >> 8) as u8, instr];
        p.extend_from_slice(params);
        let crc = crc16_ibm(&p);
        p.push(crc as u8);
        p.push((crc >> 8) as u8);
        p
    }

    #[test]
    fn v1_read_packet() {
        let bytes = build_v1(0x01, 0x02, &[0x24, 0x02]);
        let mut p = Parser::new(Version::V1);
        p.feed(&bytes);
        let pkt = p.next_packet().expect("parsed");
        assert_eq!(pkt.id, 0x01);
        assert_eq!(pkt.instr_or_err, 0x02);
        assert_eq!(pkt.params, vec![0x24, 0x02]);
        assert!(p.next_packet().is_none());
    }

    #[test]
    fn v1_sync_write_broadcast() {
        // SYNC_WRITE on broadcast ID
        let bytes = build_v1(0xFE, 0x83, &[0x1E, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00]);
        let mut p = Parser::new(Version::V1);
        p.feed(&bytes);
        let pkt = p.next_packet().unwrap();
        assert_eq!(pkt.id, 0xFE);
        assert_eq!(pkt.instr_or_err, 0x83);
    }

    #[test]
    fn v1_resync_after_garbage() {
        let mut p = Parser::new(Version::V1);
        let good = build_v1(0x05, 0x02, &[0x24, 0x02]);
        p.feed(&[0xAA, 0xBB, 0xCC]); // garbage
        p.feed(&good);
        let pkt = p.next_packet().expect("should resync");
        assert_eq!(pkt.id, 0x05);
    }

    #[test]
    fn v1_bad_checksum_drops_packet() {
        let mut bytes = build_v1(0x01, 0x02, &[0x24, 0x02]);
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        // Follow with a good packet — parser should skip the bad one and find the next.
        let good = build_v1(0x02, 0x02, &[0x24, 0x02]);
        let mut p = Parser::new(Version::V1);
        p.feed(&bytes);
        p.feed(&good);
        let pkt = p.next_packet().expect("recovered");
        assert_eq!(pkt.id, 0x02);
    }

    #[test]
    fn v1_streaming_partial_feed() {
        let bytes = build_v1(0x01, 0x02, &[0x24, 0x02]);
        let mut p = Parser::new(Version::V1);
        for b in &bytes {
            assert!(p.next_packet().is_none());
            p.feed(std::slice::from_ref(b));
        }
        let pkt = p.next_packet().expect("parsed after byte-by-byte feed");
        assert_eq!(pkt.id, 0x01);
    }

    #[test]
    fn v2_status_packet() {
        // Status: instr = 0x55, error = 0x00, params = present_position bytes
        let bytes = build_v2(0x01, 0x55, &[0x00, 0xA6, 0x00, 0x00, 0x00]);
        let mut p = Parser::new(Version::V2);
        p.feed(&bytes);
        let pkt = p.next_packet().expect("parsed");
        assert_eq!(pkt.version, ProtocolVersion::V2);
        assert_eq!(pkt.id, 0x01);
        assert_eq!(pkt.instr_or_err, 0x55);
    }

    #[test]
    fn v2_byte_stuffing_roundtrip() {
        // Payload contains FF FF FD which on the wire becomes FF FF FD FD.
        // Manually craft the stuffed frame.
        let id = 0x01;
        let instr = 0x03;
        // Logical params: FF FF FD AB
        // Wire (stuffed): FF FF FD FD AB
        let stuffed_params: Vec<u8> = vec![0xFF, 0xFF, 0xFD, 0xFD, 0xAB];
        let len = (stuffed_params.len() + 3) as u16;
        let mut frame = vec![0xFF, 0xFF, 0xFD, 0x00, id, len as u8, (len >> 8) as u8, instr];
        frame.extend_from_slice(&stuffed_params);
        let crc = crc16_ibm(&frame);
        frame.push(crc as u8);
        frame.push((crc >> 8) as u8);

        let mut p = Parser::new(Version::V2);
        p.feed(&frame);
        let pkt = p.next_packet().unwrap();
        assert_eq!(pkt.params, vec![0xFF, 0xFF, 0xFD, 0xAB]);
    }

    #[test]
    fn auto_detects_v1_and_v2() {
        let v1 = build_v1(0x01, 0x02, &[0x24, 0x02]);
        let v2 = build_v2(0x02, 0x55, &[0x00, 0xAA]);
        let mut p = Parser::new(Version::Auto);
        p.feed(&v1);
        p.feed(&v2);
        let a = p.next_packet().unwrap();
        let b = p.next_packet().unwrap();
        assert_eq!(a.version, ProtocolVersion::V1);
        assert_eq!(a.id, 0x01);
        assert_eq!(b.version, ProtocolVersion::V2);
        assert_eq!(b.id, 0x02);
    }

    #[test]
    fn crc16_known_vector() {
        // Cross-checked against pollen-robotics/rustypot's test vector:
        // ping ID 0x2A -> CRC bytes 16 D2 little-endian (value 0xD216).
        let frame = [0xFF, 0xFF, 0xFD, 0x00, 0x2A, 0x03, 0x00, 0x01];
        assert_eq!(crc16_ibm(&frame), 0xD216);
    }
}
