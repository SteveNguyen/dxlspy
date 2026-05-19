# dxlspy

Passive sniffer for Robotis Dynamixel buses. Reads a USB-serial port and
prints decoded Protocol v1 and v2 traffic, one packet per line, with the
master/slave direction labeled.

```
[20:02:04.150] MASTER → v1  READ        → ID   1  addr=0x0000 len=74  [FF FF 01 04 02 00 4A AE]
[20:02:04.166] ID   1 ← v1  STATUS       err=0x01(INPUT_VOLTAGE)  data=40 01 29 01 22 00 00 00 FF 0F …
[20:02:04.178] MASTER → v1  WRITE       → ID   1  addr=0x001E data=30 07  [FF FF 01 05 03 1E 30 07 A1]
[20:02:04.179] ID   1 ← v1  STATUS       err=0x01(INPUT_VOLTAGE)  data=  [FF FF 01 02 01 FB]
```

## Why not rustypot

[rustypot](https://github.com/pollen-robotics/rustypot)'s parser is a
private module — its public API (`DynamixelProtocolHandler`) is
master-oriented: send an instruction, read the expected reply. A bus
spy observes arbitrarily interleaved instruction and status packets
without initiating anything, which the public API can't express. So
dxlspy ships its own ~150 LoC v1/v2 framing parser. The CRC-16 was
cross-checked against rustypot's test vector.

## Build / run

```sh
cargo build --release
./target/release/dxlspy --port /dev/ttyUSB0 --baud 1000000
```

Both `--port` and `--baud` are required (no defaults — too easy to spy
the wrong bus otherwise).

## Flags

| Flag                          | Default | Notes                                                    |
| ----------------------------- | ------- | -------------------------------------------------------- |
| `--port <path>`               | —       | Serial port (e.g. `/dev/ttyUSB0`).                       |
| `--baud <bps>`                | —       | Bus baud rate (1000000, 57600, …).                       |
| `--protocol {v1,v2,auto}`     | `auto`  | `auto` detects per-packet by header bytes.               |
| `--log <file>`                | off     | Append uncolored decoded output to a file.               |
| `--no-hex`                    | off     | Hide the raw frame bytes after each decoded line.        |
| `--no-color`                  | off     | Disable ANSI color even on a TTY.                        |
| `--v1-reply-timeout-ms <ms>`  | `50`    | See below.                                               |

## Hardware setup

Dynamixel buses are half-duplex over a single data line (TTL) or RS-485
differential pair (Pro / X-series Pro). To spy, attach a USB-to-TTL (or
USB-to-RS-485) adapter to the same line as the rest of the bus and run
dxlspy against it. The tool **opens the port read-only and never
transmits** — safe to drop onto a live bus without arbitrating.

## V1 protocol caveat: PING/STATUS ambiguity

In Protocol v1, the frame layout for a master `PING to ID N` is
byte-identical to a slave `STATUS from ID N with error 0x01
(INPUT_VOLTAGE)`:

```
FF FF  N  02  01  <checksum>
       └─┴──┴──┴── ID, LEN=2, INSTR=PING / ERROR=INPUT_VOLTAGE
```

There is no in-band way to tell them apart — disambiguation requires
*context*. dxlspy uses a small state machine: after a master instruction
to ID N, the next packet from N (within `--v1-reply-timeout-ms`) is the
status reply; outside that window the pending state is dropped, so the
master's next scan correctly shows up as a fresh PING instead of a
phantom reply.

If you ever see suspicious `INPUT_VOLTAGE` lines that look identical to
preceding PING frames, look at the hex dump and compare. Raise the
timeout if your bus has unusually slow replies, lower it if your master
rescans faster than 50 ms per slot.

Protocol v2 has no such ambiguity — status packets carry instruction
byte `0x55`, which never appears in master instructions.

## Tests

```sh
cargo test
```

Covers v1/v2 framing, byte-stuffing, CRC, resync after garbage, the
pending-reply timeout, and the PING/STATUS ambiguity behavior on either
side of the timeout.
