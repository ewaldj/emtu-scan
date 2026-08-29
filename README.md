# emtu-scan.py — Express MTU Scan

A lightweight, dependency-free Python host reachability and path-MTU (PMTUD) scanner. Sweeps large IP ranges fast with an async ICMP probe/elimination phase, then confirms the real path MTU per host with a `ping`-based DF-bit test — without needing root.

## Features

- **No Root Required** — uses unprivileged ICMP sockets (`SOCK_DGRAM` + `IPPROTO_ICMP`), the same mechanism plain `ping` uses as a non-root user
- **Fast Subnet Elimination** — probes just the first/last host (or a custom set, see `--probe-hosts`) of every `--mask`-sized block before expanding it fully, so dead ranges are skipped cheaply
- **Full Host-by-Host Mode** — `--full-scan` skips subnet elimination entirely when partial-alive subnets need to be caught completely
- **Real Path-MTU Detection** — a DF-bit `ping` test classifies every reachable host as `OK`, `DF-Needed` (with the router-reported MTU), `Blackhole`, or `LocalMTUTooSmall`
- **Cross-Platform ping Support** — auto-detects `iputils` (Linux default), macOS/BSD `ping`, and aborts cleanly with a fix hint if `ping` (e.g. GNU inetutils) can't set the DF bit at all
- **Safety Guards** — rejects malformed CIDR arguments, a `--mask` smaller than the given network, or an unwritable `--outdir` with a clear message instead of a stack trace; a huge unsplit range (roughly bigger than a /8) is refused unless you pass `--allow-huge-scan`
- **Excel + Text Output** — results written as a pre-sorted `.xlsx` (3 tabs, AutoFilter) and matching plain-text files, no `openpyxl` needed
- **Zero Dependencies** — Python 3 standard library only
- **Ctrl+C Safe** — an interrupted run still writes out everything scanned so far, no traceback (exit code 130)

## Installation / Update

```
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/ewaldj/emtu-scan/refs/heads/main/e-install.sh)"
```

or

```bash
git clone https://github.com/ewaldj/emtu-scan.git
cd emtu-scan
chmod +x emtu-scan.py
```

## Quick Start

```bash
./emtu-scan.py 10.0.0.0/24 192.168.1.0/28
./emtu-scan.py -f networks.txt --mask 24 --mtu 1500
```

## Supported Systems

Ubuntu, Debian, Raspberry Pi OS, CentOS/RHEL, macOS. On startup the script detects the system `ping` variant automatically:

- **iputils** (Ubuntu, CentOS/RHEL, most other Linux distros' default): DF-bit via `-M do`.
- **macOS/BSD ping**: DF-bit via `-D`.
- **GNU inetutils** (a common default on some Debian / Raspberry Pi OS installs): has no option to set the DF bit at all, so the MTU/PMTUD test is technically impossible. The script aborts at startup with a clear message instead of producing wrong results. Fix:
  `sudo apt install iputils-ping` (then, if still needed, `sudo update-alternatives --set ping /usr/bin/ping.iputils`).
- Unknown/unrecognized ping variant: same abort, asking for `ping --help` and `ping -V` output so support can be added.

## How It Works

Three phases:

1. **Probe phase** — one asyncio event loop sends ICMP echo requests over a single unprivileged ICMP socket to the first and last usable host of every `--mask`-sized subnet (or a custom set of hosts, see `--probe-hosts`). A subnet is only expanded and scanned further if at least one of its probed hosts replies.
2. **Expand phase** — the same asyncio ICMP sweep against every host in every subnet that passed the probe phase.
3. **MTU/DF test phase** — for every host found reachable in phases 1+2, a `ping` subprocess (`ThreadPoolExecutor`, `--workers` parallel) tests whether a full-size packet with the DF bit set arrives unfragmented.

Root privileges are NOT required, provided the OS allows unprivileged ICMP sockets: on Linux this is gated by `net.ipv4.ping_group_range` (must include the user's GID; many distros ship it disabled by default), on macOS it works natively. If the socket can't be opened, the script aborts at startup with the fix:

```
sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"
# persist across reboots:
echo 'net.ipv4.ping_group_range = 0 2147483647' | sudo tee -a /etc/sysctl.conf && sudo sysctl -p
```

Why the MTU/DF test still uses `ping` instead of the raw ICMP layer: reachability only needs a yes/no per host, but the MTU/DF test needs a specific distinction (OK vs. DF-Needed/wire vs. DF-Needed/cached vs. Blackhole) that `ping`'s text output already encodes reliably.

## CLI Options

| Option | Description |
|--------|-------------|
| `networks` | CIDR(s) to scan, e.g. `10.0.0.0/24` (positional, one or more) |
| `-f`, `--file` | text file with one CIDR per line (`#` comments allowed) |
| `--mask` | probe-subnet size (e.g. `24`): only scan a block fully if its first/last host answers. Default: no splitting, scan the given CIDR directly |
| `--probe-hosts` | comma-separated host offsets to probe instead of just first/last, e.g. `1,10,253,254,16`. An offset outside a subnet's valid host range is skipped for that subnet. Ignored with `--full-scan` |
| `--full-scan` | skip the `--mask` probe phase entirely — every host in every given network goes straight to the ICMP reachability check. Slower than probing (no subnet elimination), but still far faster than a raw ping-based full scan |
| `--mtu` | MTU to test (default 1500; payload = MTU − 28 bytes of IP/ICMP header) |
| `--count`, `--timeout` | ping repeat count and per-packet timeout (ms) for the MTU/DF test phase (defaults 3, 1000) |
| `--icmp-timeout`, `--icmp-retries` | per-round timeout (s) and retry-round count for the ICMP reachability phases (defaults 1.0, 2). A genuinely dead host costs at most `(retries+1) * icmp-timeout` seconds per phase, not per host |
| `--icmp-send-burst`, `--icmp-send-pause` | pace outbound ICMP sends by pausing `--icmp-send-pause` seconds after every `--icmp-send-burst` packets (defaults 500, 0.001s). `--icmp-send-burst 0` disables pacing. Lower the burst size (and/or raise the pause) if very large scans show send-side or receive-buffer packet loss |
| `--workers` | parallel worker threads for the MTU/DF test phase only (default 50); very high values can overload the local machine or exceed the open-file limit (`ulimit -n`) — the script aborts up front if `--workers` exceeds the estimated safe cap |
| `--interval` | seconds between ping packets (`-i`) during the MTU/DF test phase (default 0.05s). Tested against `127.0.0.1` at startup; if rejected (some systems rate-limit unprivileged users below a minimum interval), the script falls back to 0.2s or 1.0s automatically and notes this in the output. To use a low interval as an unprivileged user: `sudo setcap cap_net_raw+ep $(which ping)` or run as root |
| `--outdir` | base output directory (default `./scan_results`). Each run creates a timestamped subfolder `YYYYMMDD_HHMMSS` |
| `--allow-huge-scan` | required to proceed when the given network(s) total more than ~20,000,000 addresses (roughly a /8 or larger) **without** `--mask` splitting, or with `--full-scan`. Without `--mask`, the whole range is held in memory at once — a /7 or bigger can need several GB and a long runtime. Splitting into smaller networks, or adding `--mask` (memory then scales with active subnets, not the whole range), is usually the better fix |
| `--quiet` | suppress per-host progress log |

Ctrl+C aborts cleanly: hosts already scanned are still written to xlsx/txt, no traceback (exit code 130). A malformed CIDR, a `--mask` smaller than the given network, or an unwritable `--outdir` are all rejected with a clear one-line error (and, for CLI syntax errors, the `--help` text) instead of a Python traceback.

## Detection

- **Reachable**: a plain ICMP probe without the DF bit replied.
- **MTU_OK**: a ping with the DF bit set and payload size = MTU tests whether the full size arrives unfragmented.
- **PMTUD_Status**:
  - `OK` — packet arrived at full size.
  - `DF-Needed` — the router replied with ICMP Fragmentation-Needed (PMTUD is working; `DF_Needed_MTU` shows the router-reported MTU).
  - `Blackhole` — the packet was silently dropped, no ICMP reply (PMTUD blackhole / a firewall filters ICMP type 3), CONFIRMED by a `ping` summary line that explicitly reports 100% packet loss AND no `rtt min/avg/max` line is present anywhere in that same output. Since 100% packet loss looks identical to transient loss from local overload, the DF test is retried once before `Blackhole` is reported as final. If a real `rtt` line IS present in the same output — even alongside a "packet loss" line missing entirely or explicitly claiming 100% (seen on real hardware during busy scans, where local overload can make `ping`'s own loss/rtt bookkeeping momentarily self-contradictory) — that's trusted over the loss-line claim and reported as `OK` instead, not silently guessed as a false Blackhole.
  - `LocalMTUTooSmall` — a local send error with no usable MTU value (e.g. macOS "sendto: Message too long" without a number). Rare. A local error WITH an MTU value (Linux: "Message too long, mtu=X" — typically the kernel's cached PMTU entry for that address from an earlier scan) is reported as `DF-Needed` instead, since it carries the same information as a live ICMP reply; the note field records that it came from the cache, not from a fresh reply in this run.
  - `Error` — either the ping test for this host failed with an unexpected exception (e.g. `OSError: Too many open files` from `--workers` set too high), or `ping`'s output couldn't be classified at all: no recognizable "packet loss" line AND no "rtt" summary line either — an unrecognized `ping` output format, not a confirmed failure of any kind. The rest of the scan continues; the reason is recorded in the note field.
  - `Unreachable` / `NotScanned` — the host didn't reply, or its subnet was skipped because the probe phase found nothing alive.
  - `RTT_MTU_Test_ms`: average RTT (ms) of the DF-set MTU test, parsed from the `rtt min/avg/max/...` summary already present in the ping output — no extra ping, no added runtime cost. Empty when the ping produced no rtt line (e.g. Blackhole, local error). `RTT_Reachability_ms` is always empty in this scanner — reachability is decided by the ICMP prober, which doesn't parse RTT; the column exists only for output-schema consistency.

After the probe phase, `scanned_networks.txt` lists which subnets will be scanned (active vs. skipped) and a rough runtime estimate for the remaining phases, based on the probe phase's measured duration and alive-host ratio (`--full-scan` skips this estimate, since there is no probe-phase sample to base it on — it lists the full subnet/host count instead).

## Output (in the timestamped subfolder)

- `mtu_scan_results.xlsx` — 3 tabs, pre-sorted: `By_IP`, `By_Octet2`, `By_Octet3` (with AutoFilter, so you can re-sort in Excel yourself).
- `sorted_by_ip.txt`, `sorted_by_octet2.txt`, `sorted_by_octet3.txt` — the same three sort orders as plain text.
- `scanned_networks.txt` — which subnets are in scope and the runtime estimate (written right after the probe phase).
- `summary.txt` — the run's command line, effective options, runtime, and a PMTUD status breakdown.

## Project Structure

```
├── emtu-scan.py          # The scanner (single file)
├── e-install.sh          # One-line installer/updater (fetches from GitHub)
├── LICENSE
└── README.md              # This file
```

## Requirements

- Python 3
- No external packages — the `.xlsx` file is generated directly via the standard library (`zipfile` + XML)

## License

GNU Affero General Public License v3.0 — see [LICENSE](LICENSE).

## Author

Ewald Jeitler — [www.jeitler.guru](https://www.jeitler.guru)
