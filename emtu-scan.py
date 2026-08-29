#!/usr/bin/env python3
# - - - - - - - - - - - - - - - - - - - - - - - -
# emtu-scan.py  by ewald@jeitler.cc 2026 https://www.jeitler.guru
# - - - - - - - - - - - - - - - - - - - - - - - -
# When I wrote this code, only God and I knew how it worked.
# Now only God and the AI know it.
# And since the AI helped write it… good luck to all of us.
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
"""
emtu-scan.py (express MTU scan) - Host reachability and path-MTU / PMTUD scanner.

The reachability/probe phase uses a single asyncio event loop over one
unprivileged ICMP socket (SOCK_DGRAM + IPPROTO_ICMP): it fires all sends
for a round back-to-back (pausing briefly every --icmp-send-burst packets
so the loop can flush and the kernel can drain), then awaits replies
concurrently via one callback. Total time is bounded by round-trip time
and timeout, not by target count times a fixed per-target send interval.

Root privileges: NOT required, IF the OS allows unprivileged ICMP
(SOCK_DGRAM + IPPROTO_ICMP) - on Linux gated by
`net.ipv4.ping_group_range` (must include this user's GID; many distros
ship it disabled by default - see check_async_icmp_capability_or_exit's
error message for the fix), on macOS supported natively. This is the same
mechanism plain `ping` itself typically uses as a non-root user.

For large ranges, only the first and last usable host of each probe
subnet (--mask) are tested first (or a custom set via --probe-hosts); the
full subnet is only expanded and scanned if at least one of those probe
hosts responds. --full-scan skips this subnet-level elimination entirely.

Why the MTU/DF test still uses `ping` (not the raw ICMP layer):
  Reachability only needs a yes/no per host. The MTU/DF test needs a
  specific DISTINCTION (OK vs DF-Needed/wire vs DF-Needed/cached vs
  Blackhole) that `ping`'s text output already encodes reliably (see
  classify_mtu_test). Reimplementing DF-bit + ICMP-type-3-code-4 parsing
  at the raw-socket level would duplicate that logic for no benefit, since
  the MTU-test phase runs only against hosts already confirmed reachable.

Output:
  - one .xlsx workbook with 3 pre-sorted sheets (by IP, by 2nd octet,
    by 3rd octet)
  - 3 plain-text result files (same 3 sort orders)
  all written into a timestamped subfolder of --outdir.

Requires: system `ping` binary (for the MTU/DF test) and an OS/user
combination that allows unprivileged ICMP sockets (for the reachability
phase - see above). No external Python packages needed.
"""

import argparse
import asyncio
import concurrent.futures
import errno
import ipaddress
import platform
import random
import re
import socket
import struct
import subprocess
import sys
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set

VERSION = "0.16"

IS_MACOS = platform.system() == "Darwin"

# Above this many total addresses (summed across all given networks, before
# --mask splitting), a run needs --allow-huge-scan to proceed. Chosen from
# measured RSS: a /8 (16,777,216 addresses) full-scan target list costs
# ~1.6GB; a /7 or bigger climbs fast and a /0 is infeasible (~324GB+). This
# is a blanket size guard, not a full-scan-only check - without --mask the
# given CIDR is scanned as a single block the same way --full-scan does, so
# the same memory risk applies there too.
_HUGE_SCAN_ADDRESS_THRESHOLD = 20_000_000


def detect_ping_variant() -> str:
    """Identify the system 'ping' binary so the right DF-bit flag can be
    used. This is a real capability difference, not just a naming
    difference: GNU inetutils ping (a common default on some Debian /
    Raspberry Pi OS installs) has NO option to set the Don't Fragment
    bit at all - confirmed against its --help output. iputils ping
    (Ubuntu, CentOS/RHEL, and most other Linux distros' default) uses
    '-M do'. macOS/BSD ping is handled separately via IS_MACOS and
    doesn't need probing (its '-D' flag is a stable, well-known default).
    Returns one of: 'iputils', 'inetutils', 'unknown'.
    """
    try:
        help_out = subprocess.run(["ping", "--help"], capture_output=True, text=True, timeout=5)
        help_text = (help_out.stdout or "") + (help_out.stderr or "")
    except Exception:
        help_text = ""
    try:
        ver_out = subprocess.run(["ping", "-V"], capture_output=True, text=True, timeout=5)
        ver_text = (ver_out.stdout or "") + (ver_out.stderr or "")
    except Exception:
        ver_text = ""
    combined_lower = (help_text + ver_text).lower()
    if "iputils" in combined_lower:
        return "iputils"
    if "inetutils" in combined_lower:
        return "inetutils"
    if re.search(r"(?<![\w-])-M(?![\w-])", help_text):
        return "iputils"
    return "unknown"


PING_VARIANT = "bsd" if IS_MACOS else detect_ping_variant()

IP_ICMP_OVERHEAD = 28

RE_FRAG_NEEDED = re.compile(r"frag(?:mentation)?\s+needed", re.IGNORECASE)
RE_FRAG_MTU = re.compile(r"mtu[\s=]+(\d+)", re.IGNORECASE)
RE_LOCAL_TOO_LONG = re.compile(
    r"message too long|local error.*message too long", re.IGNORECASE
)
RE_PACKET_LOSS = re.compile(r"(\d+)%\s+packet loss", re.IGNORECASE)
RE_INTERVAL_RESTRICTED = re.compile(
    r"cannot flood|minimal interval|permission|not permitted|must be root|only.{0,20}root",
    re.IGNORECASE,
)
RE_RTT_AVG = re.compile(
    r"(?:rtt|round-trip)\s+min/avg/max(?:/mdev|/stddev)?\s*=\s*[\d.]+/([\d.]+)/[\d.]+", re.IGNORECASE
)


def parse_rtt_avg_ms(output: str) -> Optional[float]:
    m = RE_RTT_AVG.search(output)
    return float(m.group(1)) if m else None


@dataclass
class HostResult:
    ip: str
    network: str
    scanned: bool = True
    reachable: Optional[bool] = None
    mtu_tested: int = 0
    mtu_ok: Optional[bool] = None
    pmtud_status: str = "N/A"
    df_needed_mtu: Optional[int] = None
    rtt_reachability_ms: Optional[float] = None   # kept for output-schema consistency; the ICMP
                                                    # reachability phase here doesn't parse RTT, so
                                                    # this stays None - only rtt_mtu_test_ms is set
    rtt_mtu_test_ms: Optional[float] = None
    note: str = ""

    def octet(self, n: int) -> int:
        return int(ipaddress.IPv4Address(self.ip).packed[n - 1])


def build_ping_cmd(host: str, size: int, count: int, timeout_ms: int, df: bool, interval: float) -> List[str]:
    timeout_s = max(1, round(timeout_ms / 1000))
    if IS_MACOS:
        cmd = ["ping", "-c", str(count), "-W", str(timeout_ms), "-i", str(interval)]
        if df:
            cmd += ["-D", "-s", str(size)]
        cmd += [host]
        return cmd
    if PING_VARIANT == "iputils":
        cmd = ["ping", "-c", str(count), "-W", str(timeout_s), "-i", str(interval)]
        if df:
            cmd += ["-M", "do", "-s", str(size)]
        cmd += [host]
        return cmd
    if df:
        raise RuntimeError(f"ping variant {PING_VARIANT!r} cannot set the DF bit "
                            f"(this should have been caught at startup)")
    cmd = ["ping", "-c", str(count), "-W", str(timeout_s), "-i", str(interval), host]
    return cmd


def run_ping(host: str, size: int, count: int, timeout_ms: int, df: bool, interval: float) -> str:
    cmd = build_ping_cmd(host, size, count, timeout_ms, df, interval)
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=(timeout_ms / 1000 * count) + (interval * count) + 5,
        )
        return proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        return ""
    except FileNotFoundError:
        raise RuntimeError("system 'ping' binary not found")


def is_reachable(output: str) -> Optional[bool]:
    """True/False if a 'X% packet loss' line was found and parsed, or None
    if no such line could be found at all - which is NOT the same thing as
    100% loss (a real Blackhole) and must be handled separately by the
    caller instead of being silently treated as unreachable. See
    classify_mtu_test for why this distinction matters."""
    m = RE_PACKET_LOSS.search(output)
    if m:
        return int(m.group(1)) < 100
    return None


def classify_mtu_test(output: str) -> tuple:
    """Returns (mtu_ok, status, reported_mtu, source). `source` also carries
    a short reason tag for the two ambiguous-output cases below, used by
    mtu_test_host to leave an explanatory note."""
    if RE_FRAG_NEEDED.search(output):
        m = RE_FRAG_MTU.search(output)
        reported = int(m.group(1)) if m else None
        return False, "DF-Needed", reported, "wire"
    if RE_LOCAL_TOO_LONG.search(output):
        m = RE_FRAG_MTU.search(output)
        if m:
            return False, "DF-Needed", int(m.group(1)), "local"
        return False, "LocalMTUTooSmall", None, "local"
    reachable = is_reachable(output)
    # A parsed "rtt min/avg/max" line is concrete proof that a full-size
    # DF-set echo reply genuinely came back (that line only exists in
    # ping's output when at least one real round trip was measured) - so
    # it wins over whatever the "packet loss" line claims, including an
    # explicit "100% packet loss" (confirmed on real hardware: rows
    # labelled Blackhole nonetheless carried a plausible, real
    # RTT_MTU_Test_ms - either because no loss line could be matched at
    # all, or because the loss line explicitly said 100% while a real rtt
    # line was ALSO present in that same run - both are self-contradictory
    # ping output, and in both cases the concrete rtt evidence is trusted
    # over the loss-line claim rather than silently reported as a
    # confirmed Blackhole).
    if RE_RTT_AVG.search(output):
        source = None if reachable is True else "rtt-present-despite-loss-claim"
        return True, "OK", None, source
    if reachable is True:
        # A clean "<100% packet loss" line was found, but this ping output
        # has no rtt summary line at all (some ping variants/formats omit
        # it) - still a plain, unambiguous OK, not the ambiguous case above.
        return True, "OK", None, None
    if reachable is False:
        return False, "Blackhole", None, None
    # reachable is None and no rtt line either: genuinely unparseable ping
    # output (unexpected wording, truncated/garbled capture, etc.) - NOT a
    # confirmed Blackhole. Flagged honestly as Error instead of guessing,
    # so it's visible and reported rather than silently miscounted.
    return None, "Error", None, "unparseable-ping-output"


RETRY_BACKOFF = (0.05, 0.2)
BLACKHOLE_CONFIRM_ATTEMPTS = 2


def mtu_test_host(ip: str, network: str, mtu: int, count: int, timeout_ms: int, interval: float) -> HostResult:
    """Run only the DF/MTU test - reachability has ALREADY been confirmed
    via the asyncio ICMP prober before this is called."""
    res = HostResult(ip=ip, network=network, reachable=True)
    payload = max(0, mtu - IP_ICMP_OVERHEAD)
    res.mtu_tested = mtu
    ok = status = reported = source = None
    mtu_out = ""
    for attempt in range(BLACKHOLE_CONFIRM_ATTEMPTS):
        if attempt > 0:
            time.sleep(random.uniform(*RETRY_BACKOFF))
        mtu_out = run_ping(ip, size=payload, count=count, timeout_ms=timeout_ms, df=True, interval=interval)
        ok, status, reported, source = classify_mtu_test(mtu_out)
        if status != "Blackhole":
            break
    res.rtt_mtu_test_ms = parse_rtt_avg_ms(mtu_out)
    res.mtu_ok = ok
    res.pmtud_status = status
    res.df_needed_mtu = reported
    if status == "DF-Needed" and reported:
        if source == "local":
            res.note = f"path MTU {reported} (local/cached PMTU, no live ICMP seen this scan)"
        else:
            res.note = f"router reports path MTU {reported}"
    elif source == "unparseable-ping-output":
        res.note = ("ping output not recognized (no packet-loss or rtt line found) - "
                     "MTU/PMTUD result unknown, NOT a confirmed Blackhole")
    return res


# --- asyncio-based batched reachability -----------------------------------

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0
_ICMP_SEND_YIELD_EVERY = 500   # yield this often while blasting sends, so the event loop
                                # gets to flush/process incoming replies instead of one
                                # giant uninterrupted send burst
_ICMP_SEND_YIELD_SLEEP = 0.001  # REAL sleep duration at each yield point above (not a
                                 # zero-length yield) - gives the kernel/network actual
                                 # drain time between micro-bursts of _ICMP_SEND_YIELD_EVERY
                                 # packets; see _icmp_alive_async's send loop for why
_ICMP_CHUNK_SIZE = 60000       # keep well under the 16-bit ICMP sequence-number space
                                # (65536) per round, so seq numbers stay unique within a round
_ICMP_POLL_INTERVAL = 0.02     # how often to check for early round completion instead of
                                # unconditionally sleeping the full round timeout every round
_ICMP_EAGAIN_RETRIES = 5       # EAGAIN/EWOULDBLOCK on a non-blocking socket's sendto() means
                                # "the local send buffer is full right now, try again shortly" -
                                # it is transient by definition, so retry the SAME send a few
                                # times with a short pause instead of treating it as a dropped
                                # packet on the first hit
_ICMP_EAGAIN_RETRY_PAUSE = 0.005  # pause between EAGAIN retries (seconds); real, not zero-length,
                                   # so the kernel gets actual time to drain the send buffer

_ICMP_MACOS_ARP_ERRNOS = ("EHOSTUNREACH", "EHOSTDOWN")  # macOS-only: sendto() on an unprivileged
                                   # ICMP socket to a directly-connected host with no ARP cache
                                   # entry yet fails SYNCHRONOUSLY - confirmed on real hardware
                                   # with BOTH of these errno names on different runs against the
                                   # same subnet (the BSD ARP-resolution-failure path can surface
                                   # as either, and which one shows up isn't consistent - so both
                                   # get the same treatment, not just EHOSTUNREACH). This differs
                                   # from Linux, where the kernel queues the packet and ARPs
                                   # transparently instead of failing the send. The failed macOS
                                   # send itself triggers the ARP request, so a short retry once
                                   # it resolves (typically single-digit ms on a local LAN)
                                   # succeeds - same idea as the EAGAIN retry above, just for a
                                   # different transient condition. NOT applied on Linux, where
                                   # these errnos reliably mean "genuinely no route" and should
                                   # stay a permanent failure.
_ICMP_MACOS_ARP_RETRIES = 8
_ICMP_MACOS_ARP_RETRY_PAUSE = 0.02  # seconds between macOS ARP-wait retries; longer than the
                                     # EAGAIN pause since this waits on an actual ARP round trip,
                                     # not just local buffer drain
_ICMP_MACOS_ARP_ERRNO_VALUES = {getattr(errno, name) for name in _ICMP_MACOS_ARP_ERRNOS
                                 if hasattr(errno, name)}


def _icmp_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return (~s) & 0xffff


def build_icmp_echo(identifier: int, seq: int) -> bytes:
    payload = b"emtu-scan-icmp-probe"
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, identifier, seq)
    checksum = _icmp_checksum(header + payload)
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, checksum, identifier, seq)
    return header + payload


def parse_icmp_reply(data: bytes) -> Optional[tuple]:
    """Return (icmp_type, code, identifier, seq) or None if data is too
    short to be a valid ICMP header. On Linux, unprivileged
    SOCK_DGRAM+IPPROTO_ICMP sockets deliver just the ICMP message (no outer
    IP header), same as what was sent - verified extensively on real Linux
    hardware. macOS/BSD is DIFFERENT: the received datagram has the IPv4
    header (20+ bytes, more with options) PREPENDED, even though sends
    don't need one - confirmed on real hardware (a full scan against a
    subnet where plain system `ping` got replies fine still showed 0%
    reachable here, because every reply's ICMP header was being read at
    the wrong offset and never matched). Detected structurally (IPv4
    version nibble + protocol=ICMP byte) rather than assumed from platform
    alone, and skipped before parsing the actual ICMP header. A real ICMP
    reply can never false-trigger this check: its first byte is the ICMP
    type (0 for echo reply), whose high nibble is 0, not 4."""
    if len(data) >= 20:
        version_ihl = data[0]
        if (version_ihl >> 4) == 4 and data[9] == socket.IPPROTO_ICMP:
            ihl_bytes = (version_ihl & 0x0F) * 4
            data = data[ihl_bytes:]
    if len(data) < 8:
        return None
    icmp_type, code, checksum, identifier, seq = struct.unpack("!BBHHH", data[:8])
    return icmp_type, code, identifier, seq


def _process_reply(data: bytes, addr_ip: str, identifier: int, pending: Dict[int, str]) -> Optional[str]:
    """Given one received datagram + its source IP, return the target IP
    it should be attributed to, or None if it must be ignored: wrong ICMP
    type, wrong identifier (not ours), unmatched sequence number, or a
    stale reply from an earlier probing round whose sequence number has
    since been reassigned to a different target (guarded by requiring the
    reply's source address to match the CURRENT round's target for that
    seq - a stale reply's source won't match unless it coincidentally is
    the same target again)."""
    parsed = parse_icmp_reply(data)
    if not parsed:
        return None
    icmp_type, code, ident, seq = parsed
    if icmp_type != ICMP_ECHO_REPLY or ident != identifier:
        return None
    ip = pending.get(seq)
    if ip is not None and addr_ip == ip:
        return ip
    return None


class _IcmpReplyProtocol(asyncio.DatagramProtocol):
    def __init__(self, on_datagram):
        self._on_datagram = on_datagram

    def datagram_received(self, data, addr):
        self._on_datagram(data, addr[0])

    def error_received(self, exc):
        pass  # e.g. ICMP error for a previous send (dest unreachable etc.) - ignore, counts as no reply


def _icmp_socket_identifier(sock: socket.socket) -> int:
    """Determine the ICMP identifier the kernel will actually use for this
    socket, and bind it so that identifier is fixed for the socket's
    lifetime. On Linux/BSD "ping sockets" (SOCK_DGRAM + IPPROTO_ICMP) the
    kernel silently OVERWRITES whatever identifier field we put in our own
    crafted ICMP echo header with the local port this socket is bound to,
    and only delivers replies whose id matches that same port (this is how
    the kernel demultiplexes ICMP replies to the right unprivileged
    socket). So: bind explicitly, then read back the actual port via
    getsockname() and use THAT as the identifier for both building
    outbound packets and matching inbound replies."""
    sock.bind(("0.0.0.0", 0))
    return sock.getsockname()[1] & 0xFFFF


def _enlarge_socket_buffers(sock: socket.socket, size: int = 4 * 1024 * 1024) -> None:
    """Raise the socket's receive/send buffer sizes well above the OS
    default (commonly ~200KB on Linux), so a large burst of ICMP replies
    is less likely to overflow the kernel receive buffer before the event
    loop drains each datagram. setsockopt silently clamps to the kernel's
    net.core.rmem_max/wmem_max ceiling rather than erroring if size is
    larger than allowed, so this is a best-effort request, not a
    guarantee."""
    for opt in (socket.SO_RCVBUF, socket.SO_SNDBUF):
        try:
            sock.setsockopt(socket.SOL_SOCKET, opt, size)
        except OSError:
            pass  # not fatal - proceed with whatever buffer size the OS gives us


async def _wait_for_round(remaining: List[str], alive: Set[str], round_timeout: float,
                           poll_interval: float = _ICMP_POLL_INTERVAL) -> List[str]:
    """Wait for targets in `remaining` to show up in `alive`, but no longer
    than round_timeout - polling every poll_interval instead of always
    sleeping the full round_timeout. This means a round where every target
    replies quickly (the common case - most hosts are up) finishes in
    ~RTT instead of unconditionally paying the full timeout on every round.
    Only a round with genuinely unresponsive hosts pays close to the full
    timeout. Returns the still-not-alive subset of `remaining`."""
    waited = 0.0
    remaining = [ip for ip in remaining if ip not in alive]
    while remaining and waited < round_timeout:
        await asyncio.sleep(poll_interval)
        waited += poll_interval
        remaining = [ip for ip in remaining if ip not in alive]
    return remaining


async def _icmp_alive_async(targets: List[str], timeout_s: float, retries: int,
                             retry_pause: float = 0.05,
                             send_burst: int = _ICMP_SEND_YIELD_EVERY,
                             send_pause: float = _ICMP_SEND_YIELD_SLEEP) -> Set[str]:
    """Probe `targets` for ICMP reachability over one asyncio event loop /
    one socket. The per-round wait (`timeout_s`) stays FIXED across
    retries (only a small `retry_pause` between attempts) rather than
    growing - so the worst case for a genuinely dead host is bounded and
    predictable: (retries+1) * timeout_s at most."""
    if not targets:
        return set()
    alive: Set[str] = set()
    pending: Dict[int, str] = {}

    loop = asyncio.get_event_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
    _enlarge_socket_buffers(sock)
    identifier = _icmp_socket_identifier(sock)

    def on_datagram(data: bytes, addr_ip: str):
        ip = _process_reply(data, addr_ip, identifier, pending)
        if ip is not None:
            alive.add(ip)

    sock.setblocking(False)
    transport, _protocol = await loop.create_datagram_endpoint(
        lambda: _IcmpReplyProtocol(on_datagram), sock=sock
    )
    try:
        for chunk_start in range(0, len(targets), _ICMP_CHUNK_SIZE):
            chunk = targets[chunk_start:chunk_start + _ICMP_CHUNK_SIZE]
            remaining = list(chunk)
            # Targets whose macOS ARP-retry budget already ran out once in an
            # earlier round of THIS chunk. A host that didn't answer ARP
            # after the full retry budget (real hardware: up to
            # _ICMP_MACOS_ARP_RETRIES x _ICMP_MACOS_ARP_RETRY_PAUSE of active
            # retrying) is, for practical purposes, proven not to be there -
            # paying that same wait again on every icmp_retries round for a
            # genuinely dead host is pure waste (confirmed on real hardware:
            # a --full-scan with ~90% dead hosts took 10x longer on macOS
            # than the identical scan on Linux, entirely from this). Once
            # exhausted, later rounds get a single plain attempt for that
            # host instead of the full retry budget again.
            macos_arp_exhausted: Set[str] = set()
            for attempt in range(retries + 1):
                if not remaining:
                    break
                if attempt > 0:
                    await asyncio.sleep(retry_pause)
                pending.clear()
                for seq, ip in enumerate(remaining):
                    pending[seq] = ip
                send_error_counts: Counter = Counter()
                _send_max_attempts = max(_ICMP_EAGAIN_RETRIES, _ICMP_MACOS_ARP_RETRIES) + 1
                for seq, ip in enumerate(remaining):
                    packet = build_icmp_echo(identifier, seq)
                    for send_attempt in range(_send_max_attempts):
                        try:
                            # Send on the raw socket directly, not via
                            # transport.sendto(): for an unconnected datagram
                            # socket, asyncio's DatagramTransport.sendto()
                            # routes a synchronous OSError to
                            # protocol.error_received() instead of raising
                            # it, so our own except OSError below would
                            # never see it (error_received() is a no-op
                            # here). Sending directly on the socket gives
                            # genuine per-target send-error visibility,
                            # counted and reported below instead of
                            # vanishing silently.
                            sock.sendto(packet, (ip, 0))
                            break
                        except OSError as e:
                            # NOTE: these are deliberately NOT named
                            # retry_budget/retry_pause - this function's own
                            # `retry_pause` parameter (the OUTER icmp-retries
                            # round pause) lives in this same scope, and
                            # reusing that name here would silently
                            # overwrite it after the first send error.
                            if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                                # Non-blocking socket, local send buffer is
                                # momentarily full - by definition transient,
                                # so retry the SAME send shortly instead of
                                # treating this one packet as a dropped send.
                                send_retry_budget, send_retry_pause = _ICMP_EAGAIN_RETRIES, _ICMP_EAGAIN_RETRY_PAUSE
                            elif IS_MACOS and e.errno in _ICMP_MACOS_ARP_ERRNO_VALUES and ip not in macos_arp_exhausted:
                                # macOS-only: no ARP entry yet for a
                                # directly-connected host - see
                                # _ICMP_MACOS_ARP_ERRNOS above. The failed
                                # send just triggered the ARP request; retry
                                # once it resolves. Skipped (falls through to
                                # the permanent-failure branch below) if this
                                # target already exhausted this budget in an
                                # earlier round - see macos_arp_exhausted above.
                                send_retry_budget, send_retry_pause = _ICMP_MACOS_ARP_RETRIES, _ICMP_MACOS_ARP_RETRY_PAUSE
                            else:
                                send_retry_budget, send_retry_pause = 0, 0
                            if send_attempt < send_retry_budget:
                                await asyncio.sleep(send_retry_pause)
                                continue
                            if IS_MACOS and e.errno in _ICMP_MACOS_ARP_ERRNO_VALUES:
                                macos_arp_exhausted.add(ip)
                            # Either a permanently-classified error (e.g.
                            # EHOSTUNREACH on Linux - genuinely unroutable,
                            # no point retrying), or a transient one that
                            # didn't clear within its retry budget. Break
                            # down by errno name so the cause is visible
                            # directly in the warning rather than guessed at
                            # afterwards.
                            key = errno.errorcode.get(e.errno, str(e.errno)) if e.errno is not None else "unknown"
                            send_error_counts[key] += 1
                            break
                    if send_burst > 0 and seq % send_burst == 0:
                        # A real (not zero-length) sleep here, not just a
                        # cooperative yield: gives the kernel/network actual
                        # time to drain between bursts of send_burst packets,
                        # instead of firing the whole round's sends as one
                        # uninterrupted burst. Tune via --icmp-send-burst /
                        # --icmp-send-pause for the target network/NIC.
                        await asyncio.sleep(send_pause)
                if send_error_counts:
                    total_errors = sum(send_error_counts.values())
                    breakdown = ", ".join(f"{k}={v}" for k, v in send_error_counts.most_common())
                    print(f"WARNING: {total_errors}/{len(remaining)} ICMP sendto() call(s) raised an "
                          f"OSError this round ({breakdown}) - those targets got no echo request sent "
                          f"this attempt.")
                remaining = await _wait_for_round(remaining, alive, timeout_s)
    finally:
        transport.close()
    return alive


def icmp_alive(targets: List[str], timeout_s: float, retries: int,
                send_burst: int = _ICMP_SEND_YIELD_EVERY,
                send_pause: float = _ICMP_SEND_YIELD_SLEEP) -> Set[str]:
    """Synchronous entry point - runs the asyncio prober to completion.
    Empty input returns an empty set without touching asyncio/sockets."""
    if not targets:
        return set()
    return asyncio.run(_icmp_alive_async(targets, timeout_s, retries,
                                          send_burst=send_burst, send_pause=send_pause))


def check_async_icmp_capability_or_exit() -> None:
    """Abort early with a clear, actionable message if this user/system
    cannot open an unprivileged ICMP socket, rather than failing
    confusingly mid-scan. On Linux this is gated by
    net.ipv4.ping_group_range, independent of root."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        sock.close()
    except PermissionError as e:
        print(f"ERROR: cannot open an unprivileged ICMP socket ({e}). emtu-scan.py needs this "
              f"for the reachability/probe phase.")
        print("Fix (Linux) - allow this via net.ipv4.ping_group_range (independent of root/sudo):")
        print('  sudo sysctl -w net.ipv4.ping_group_range="0 2147483647"')
        print("  # persist across reboots:")
        print("  echo 'net.ipv4.ping_group_range = 0 2147483647' | sudo tee -a /etc/sysctl.conf && sudo sysctl -p")
        print("macOS: this should normally work without changes - if it's still denied, please "
              "report the exact error so support can be added.")
        sys.exit(1)
    except OSError as e:
        print(f"ERROR: cannot open an unprivileged ICMP socket ({e}). emtu-scan.py needs this "
              f"for the reachability/probe phase.")
        sys.exit(1)


# --- range expansion ----------------------------------------------------

def parse_networks(cli_nets: List[str], file_path: Optional[str]) -> List[ipaddress.IPv4Network]:
    raw = list(cli_nets)
    if file_path:
        for line in Path(file_path).read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                raw.append(line)
    nets = []
    for item in raw:
        if "/" not in item:
            item = item + "/32"
        nets.append(ipaddress.ip_network(item, strict=False))
    return nets


def probe_subnets(net: ipaddress.IPv4Network, mask: Optional[int]):
    target_mask = mask if mask is not None else net.prefixlen
    if target_mask < net.prefixlen:
        raise ValueError(f"--mask /{target_mask} is larger than network {net} (/{net.prefixlen})")
    if target_mask == net.prefixlen:
        yield net
    else:
        yield from net.subnets(new_prefix=target_mask)


def probe_endpoints(sub: ipaddress.IPv4Network, probe_offsets: Optional[List[int]] = None) -> List[str]:
    """Which host(s) within `sub` to probe to decide if the whole subnet is
    worth expanding. Default: first + last usable host. If `probe_offsets`
    is given (e.g. [1, 10, 253, 254, 16] from --probe-hosts), those are used
    instead - each is an offset added to the subnet's network address
    (so for a /24, offset 254 means x.x.x.254), letting the user probe
    hosts other than just first/last (useful when a subnet's alive hosts
    are known to sit elsewhere, e.g. gateways at .1/.254 but active hosts
    clustered around .16). An offset outside this particular subnet's valid
    host range (not strictly between network and broadcast address) is
    silently skipped for that subnet, not an error - it may still be valid
    for other, larger subnets in the same scan. Duplicate offsets, or
    offsets that collide after wraparound, are de-duplicated."""
    if sub.num_addresses <= 2:
        return [str(a) for a in sub]
    if probe_offsets:
        base = int(sub.network_address)
        broadcast = int(sub.broadcast_address)
        seen: List[str] = []
        for off in probe_offsets:
            addr_int = base + off
            if base < addr_int < broadcast:
                ip = str(ipaddress.IPv4Address(addr_int))
                if ip not in seen:
                    seen.append(ip)
        return seen
    hosts = list(sub.hosts())
    if not hosts:
        return [str(sub.network_address)]
    first, last = hosts[0], hosts[-1]
    return [str(first)] if first == last else [str(first), str(last)]


def all_scan_targets(sub: ipaddress.IPv4Network) -> List[str]:
    if sub.num_addresses <= 2:
        return [str(a) for a in sub]
    return [str(h) for h in sub.hosts()]


def subnet_host_count(sub: ipaddress.IPv4Network) -> int:
    """Same count all_scan_targets(sub) would produce, without building/
    str()-converting the actual address list - matters at high subnet
    counts (e.g. a /8 --mask 24 scan has 65536 subnets; materializing full
    host lists just to call len() on them wastes real CPU time there)."""
    return sub.num_addresses if sub.num_addresses <= 2 else sub.num_addresses - 2


# --- scan orchestration --------------------------------------------------

def _future_result_or_error(fut, ip: str, network: str) -> HostResult:
    try:
        return fut.result()
    except KeyboardInterrupt:
        raise
    except Exception as e:
        return HostResult(ip=ip, network=network, reachable=None,
                           pmtud_status="Error", note=str(e)[:200])


_SCAN_LINE_REACH_WIDTH = len("UNREACHABLE")
_SCAN_LINE_MTU_WIDTH = 12
_SCAN_LINE_STATUS_WIDTH = max(len(s) for s in
                               ("OK", "DF-Needed", "Blackhole", "LocalMTUTooSmall", "Error"))


def _fmt_probe_line(ip: str, alive: bool) -> str:
    """Console line for one [probe] endpoint result - same REACHABLE/
    UNREACHABLE wording as [scan], but without the MTU/status/rtt columns
    (the probe phase only checks reachability, no MTU/DF test runs here)."""
    reach_word = "REACHABLE" if alive else "UNREACHABLE"
    return f"[probe] {ip:<15} {reach_word:<{_SCAN_LINE_REACH_WIDTH}}"


def _fmt_mtu_field(r: HostResult) -> str:
    """MTU column for one [scan] line. OK: the full tested size arrived.
    DF-Needed: the router told us the EXACT working MTU (df_needed_mtu),
    shown with '=' since it's a known value, not just a bound.
    Blackhole/LocalMTUTooSmall/Error: no ICMP reply told us a real number,
    so only the tested (and failed) size is known - shown as an upper
    bound with '<'."""
    if r.mtu_ok:
        return "MTU=OK"
    if r.pmtud_status == "DF-Needed" and r.df_needed_mtu:
        return f"MTU={r.df_needed_mtu}"
    if r.mtu_tested:
        return f"MTU=<{r.mtu_tested}"
    return ""


def _fmt_scan_line(r: HostResult) -> str:
    """Console-friendly [scan] result line: IP, REACHABLE/UNREACHABLE/ERROR,
    MTU threshold, PMTUD status, RTT of the MTU/DF test (blank for
    anything that produced no ICMP reply to time: Unreachable, Blackhole,
    LocalMTUTooSmall, Error)."""
    if r.reachable is False:
        reach_word = "UNREACHABLE"
    elif r.reachable is True:
        reach_word = "REACHABLE"
    else:
        reach_word = "ERROR"
    if r.reachable is False:
        return f"[scan]  {r.ip:<15} {reach_word:<{_SCAN_LINE_REACH_WIDTH}} |{' ' * (_SCAN_LINE_MTU_WIDTH + 2)}|"
    mtu_field = _fmt_mtu_field(r)
    rtt = f"{r.rtt_mtu_test_ms:.2f}ms" if r.rtt_mtu_test_ms is not None else "NA"
    # Shown whenever there IS a note, not just for the reachable=None/
    # host-level-exception case - e.g. the mtu-level "ambiguous ping
    # output" notes from mtu_test_host (see classify_mtu_test) need to be
    # visible here too, not just in the xlsx/txt output.
    note_tail = f" note={r.note}" if r.note else ""
    return (f"[scan]  {r.ip:<15} {reach_word:<{_SCAN_LINE_REACH_WIDTH}} | "
            f"{mtu_field:<{_SCAN_LINE_MTU_WIDTH}} | {r.pmtud_status:<{_SCAN_LINE_STATUS_WIDTH}} "
            f"rtt={rtt}{note_tail}")


def _fast_pool_shutdown(pool: concurrent.futures.ThreadPoolExecutor) -> None:
    try:
        pool.shutdown(wait=False, cancel_futures=True)
    except TypeError:
        pool.shutdown(wait=False)


def _ceil_div(a: int, b: int) -> int:
    return (a + b - 1) // b if b > 0 else 0


def build_scanned_networks_report(active_subnets: List[ipaddress.IPv4Network],
                                   skipped_subnets: List[ipaddress.IPv4Network],
                                   probe_alive_count: int, probe_total: int,
                                   count: int, interval: float, timeout_ms: int, workers: int,
                                   icmp_timeout_s: float, icmp_retries: int,
                                   probe_elapsed_s: float) -> tuple:
    """Build the post-probe-phase networks report: which subnets will
    actually be scanned, and a ROUGH runtime estimate. Returns
    (report_text, estimate_summary_line_for_console).

    Estimate model (documented here so the assumptions are visible, not
    hidden in a formula): the MTU/DF-test phase (Phase 3) only runs ping
    against hosts later found alive during the expand ICMP phase - that
    count isn't known yet at this point, so it's approximated as
    (total addresses in active subnets) * (probe-phase alive ratio),
    using the probe phase's own endpoints as a same-network sample. Each
    such host is assumed to cost about count*interval + timeout_ms/1000
    seconds of ping time (a rough upper-ish bound - real RTT is usually
    much less than the timeout), divided across --workers threads. The
    expand ICMP phase itself is anchored on the ACTUALLY MEASURED probe
    phase duration (same batched retry/timeout mechanism, so same order
    of magnitude), with the mechanically-derived worst-case bound (all
    targets in the batch dead) shown alongside it for reference."""
    total_target_hosts = sum(subnet_host_count(sub) for sub in active_subnets)
    probe_alive_ratio = (probe_alive_count / probe_total) if probe_total else 0.0
    estimated_alive_hosts = round(total_target_hosts * probe_alive_ratio)
    assumed_seconds_per_host = count * interval + (timeout_ms / 1000.0)
    estimated_mtu_seconds = _ceil_div(estimated_alive_hosts, max(1, workers)) * assumed_seconds_per_host
    expand_worst_case_seconds = (icmp_retries + 1) * icmp_timeout_s + icmp_retries * 0.05
    estimated_expand_seconds = min(probe_elapsed_s, expand_worst_case_seconds) if probe_elapsed_s > 0 else 0.0
    estimated_total_seconds = estimated_expand_seconds + estimated_mtu_seconds
    worst_case_total_seconds = expand_worst_case_seconds + estimated_mtu_seconds

    lines = [
        f"emtu-scan.py v{VERSION} - networks planned for scanning (written right after the probe phase)",
        f"Probe subnets total: {len(active_subnets) + len(skipped_subnets)}",
        f"Active (probe succeeded, will be expanded+scanned): {len(active_subnets)}",
        f"Skipped (probe failed on all its endpoints): {len(skipped_subnets)}",
        "",
        "Active subnets (CIDR, host count):",
    ]
    for sub in sorted(active_subnets, key=lambda s: int(s.network_address)):
        lines.append(f"  {str(sub):<20} {subnet_host_count(sub)}")
    if skipped_subnets:
        lines.append("")
        lines.append("Skipped subnets (CIDR):")
        for sub in sorted(skipped_subnets, key=lambda s: int(s.network_address)):
            lines.append(f"  {sub}")
    lines += [
        "",
        f"Planned host count (all addresses in active subnets): {total_target_hosts}",
        f"Probe-phase alive ratio: {probe_alive_count}/{probe_total} endpoints "
        f"({probe_alive_ratio * 100:.1f}%)",
        f"Estimated alive hosts to MTU/DF-test: ~{estimated_alive_hosts} "
        f"(planned host count x probe-phase alive ratio, rounded)",
        "",
        "Runtime estimate (ROUGH - see assumptions below):",
        f"  Expand ICMP phase: ~{estimated_expand_seconds:.1f}s "
        f"(anchored on the measured probe phase duration, {probe_elapsed_s:.1f}s; "
        f"mechanical worst case if this whole batch were dead: ~{expand_worst_case_seconds:.1f}s)",
        f"  MTU/DF test phase: ~{estimated_mtu_seconds:.1f}s "
        f"(~{estimated_alive_hosts} hosts / {workers} workers x "
        f"~{assumed_seconds_per_host:.2f}s/host)",
        f"  TOTAL (est.): ~{estimated_total_seconds:.1f}s "
        f"(worst case up to ~{worst_case_total_seconds:.1f}s)",
        "",
        "ASSUMPTIONS: per-host MTU/DF-test time ~= --count * --interval + --timeout/1000 "
        f"= {count} * {interval}s + {timeout_ms}/1000s = {assumed_seconds_per_host:.2f}s "
        "(usually an overestimate - real RTT is normally well under --timeout). The expand-phase "
        "alive ratio is assumed to match the probe phase's sample - a genuinely different mix of "
        "alive/dead hosts in the expanded subnets, or many Blackhole re-tests "
        f"(each retried once more, doubling that host's ping cost), will shift the real runtime "
        "away from this estimate. Treat this as a rough planning number, not a guarantee.",
    ]
    summary_line = (
        f"[estimate] {len(active_subnets)} active subnet(s), ~{total_target_hosts} host(s) planned, "
        f"~{estimated_alive_hosts} expected alive -> expand ~{estimated_expand_seconds:.1f}s + "
        f"MTU/DF-test ~{estimated_mtu_seconds:.1f}s = ~{estimated_total_seconds:.1f}s total (rough, "
        f"worst case ~{worst_case_total_seconds:.1f}s)"
    )
    return "\n".join(lines) + "\n", summary_line


def build_full_scan_report(subnets: List[ipaddress.IPv4Network]) -> tuple:
    """Networks report for --full-scan mode. There is no probe phase to base
    an alive-ratio/runtime estimate on here (that's the whole point of
    --full-scan - every host goes straight to the ICMP reachability check),
    so this just lists every subnet in scope with its raw host count instead
    of reusing build_scanned_networks_report()'s probe-ratio-based estimate,
    which would silently show 0 estimated-alive-hosts (misleading, not an
    honest "no estimate available")."""
    total_target_hosts = sum(subnet_host_count(sub) for sub in subnets)
    lines = [
        "emtu-scan.py - full-scan mode (--full-scan: no probe-phase elimination)",
        "",
        f"Subnets: {len(subnets)}",
        f"Total hosts: {total_target_hosts}",
        "",
        "Networks:",
    ]
    for sub in subnets:
        lines.append(f"  {sub}  ({subnet_host_count(sub)} hosts)")
    summary_line = (
        f"[full-scan] {len(subnets)} subnet(s), {total_target_hosts} host(s) total - "
        f"no runtime estimate (no probe phase to base it on)"
    )
    return "\n".join(lines) + "\n", summary_line


def _build_expand_targets(subnets: List[ipaddress.IPv4Network], probe_ip_to_subnet: Dict[str, ipaddress.IPv4Network],
                           probed_ok: Dict[ipaddress.IPv4Network, bool]) -> tuple:
    """Build the expand-phase target list from probe results. Groups
    already-probed IPs by subnet in ONE pass first, instead of rescanning
    the whole probe_ip_to_subnet dict once per subnet - that per-subnet
    rescan pattern is O(subnet_count * probe_endpoint_count), which
    dominates at very large subnet counts (e.g. 65536 subnets for a /8
    scanned at --mask 24). Returns
    (expand_targets, expand_ip_to_subnet, notscanned_results)."""
    probed_by_subnet: Dict[ipaddress.IPv4Network, Set[str]] = {}
    for ip, sub in probe_ip_to_subnet.items():
        probed_by_subnet.setdefault(sub, set()).add(ip)

    expand_targets: List[str] = []
    expand_ip_to_subnet: Dict[str, ipaddress.IPv4Network] = {}
    notscanned_results: List[HostResult] = []
    for sub in subnets:
        already = probed_by_subnet.get(sub, set())
        if probed_ok.get(sub):
            for ip in all_scan_targets(sub):
                if ip in already:
                    continue
                expand_targets.append(ip)
                expand_ip_to_subnet[ip] = sub
        elif sub not in probed_ok:
            notscanned_results.append(HostResult(ip=str(sub.network_address), network=str(sub),
                                                  scanned=False, reachable=False, pmtud_status="NotScanned",
                                                  note="probe subnet empty"))
    return expand_targets, expand_ip_to_subnet, notscanned_results


def scan(networks, mask, mtu, count, timeout_ms, workers, interval,
         icmp_timeout_s=1.0, icmp_retries=3, log=print, outdir: Optional[Path] = None,
         icmp_send_burst: int = _ICMP_SEND_YIELD_EVERY, icmp_send_pause: float = _ICMP_SEND_YIELD_SLEEP,
         full_scan: bool = False, probe_hosts: Optional[List[int]] = None):
    """Returns (results, interrupted).

    Three phases:
      1. ONE asyncio ICMP sweep for every subnet's probe endpoint(s).
      2. ONE asyncio ICMP sweep for every host in subnets whose probe
         succeeded (the "expand" set).
      3. Per-host MTU/DF test (ThreadPoolExecutor + ping, unchanged) for
         every host phases 1+2 found alive.

    If full_scan=True, phase 1 is skipped entirely: every subnet is treated
    as active (no --mask first/last-host elimination), so every host in
    every given network goes straight into phase 2's ICMP reachability
    check. probe_hosts (parsed --probe-hosts offsets) is meaningless in this
    mode and ignored - there is no probe phase to apply it to.
    """
    subnets = []
    for net in networks:
        subnets.extend(probe_subnets(net, mask))

    results: List[HostResult] = []
    interrupted = False

    if full_scan:
        probe_ip_to_subnet: Dict[str, ipaddress.IPv4Network] = {}
        probe_alive: Set[str] = set()
        probe_elapsed_s = 0.0
        expand_targets: List[str] = []
        expand_ip_to_subnet: Dict[str, ipaddress.IPv4Network] = {}
        for sub in subnets:
            for ip in all_scan_targets(sub):
                expand_targets.append(ip)
                expand_ip_to_subnet[ip] = sub
        notscanned_results: List[HostResult] = []
        active_subnets = list(subnets)
        skipped_subnets: List[ipaddress.IPv4Network] = []

        log(f"[scan] --full-scan: probe phase skipped, {len(expand_targets)} host(s) across "
            f"{len(subnets)} subnet(s) go straight to the ICMP reachability check")
        report_text, estimate_line = build_full_scan_report(subnets)
        log(estimate_line)
        if outdir is not None:
            try:
                (Path(outdir) / "scanned_networks.txt").write_text(report_text)
            except OSError as e:
                log(f"WARNING: could not write scanned_networks.txt ({e})")
    else:
        probe_ip_to_subnet = {}
        for sub in subnets:
            for ip in probe_endpoints(sub, probe_hosts):
                probe_ip_to_subnet[ip] = sub

        try:
            log(f"[icmp] probe phase: {len(probe_ip_to_subnet)} endpoint(s) across {len(subnets)} subnet(s)...")
            probe_t0 = time.monotonic()
            probe_alive = icmp_alive(list(probe_ip_to_subnet.keys()), icmp_timeout_s, icmp_retries,
                                      send_burst=icmp_send_burst, send_pause=icmp_send_pause)
            probe_elapsed_s = time.monotonic() - probe_t0
        except KeyboardInterrupt:
            log("\nInterrupted during probe phase - nothing scanned yet.")
            return results, True

        probed_ok = {}
        for ip, sub in probe_ip_to_subnet.items():
            alive = ip in probe_alive
            probed_ok[sub] = probed_ok.get(sub, False) or alive
            if not alive:
                results.append(HostResult(ip=ip, network=str(sub), reachable=False, pmtud_status="Unreachable"))
            log(_fmt_probe_line(ip, alive))

        expand_targets, expand_ip_to_subnet, notscanned_results = _build_expand_targets(
            subnets, probe_ip_to_subnet, probed_ok
        )

        # Networks report + rough runtime estimate - written and shown right
        # after the probe phase, before the (potentially long) expand/MTU-test
        # phases start.
        active_subnets = [sub for sub in subnets if probed_ok.get(sub)]
        skipped_subnets = [sub for sub in subnets if not probed_ok.get(sub)]
        report_text, estimate_line = build_scanned_networks_report(
            active_subnets, skipped_subnets, len(probe_alive), len(probe_ip_to_subnet),
            count, interval, timeout_ms, workers, icmp_timeout_s, icmp_retries, probe_elapsed_s,
        )
        log(f"[networks] {len(active_subnets)} active subnet(s), {len(skipped_subnets)} skipped - "
            f"see scanned_networks.txt for details")
        log(estimate_line)
        if outdir is not None:
            try:
                (Path(outdir) / "scanned_networks.txt").write_text(report_text)
            except OSError as e:
                log(f"WARNING: could not write scanned_networks.txt ({e})")

    results.extend(notscanned_results)

    try:
        if expand_targets:
            log(f"[icmp] expand phase: {len(expand_targets)} host(s) across "
                f"{len(active_subnets)} active subnet(s)...")
        expand_alive = icmp_alive(expand_targets, icmp_timeout_s, icmp_retries,
                                   send_burst=icmp_send_burst, send_pause=icmp_send_pause)
    except KeyboardInterrupt:
        log("\nInterrupted during expand phase - writing out probe-phase results so far...")
        return results, True

    mtu_test_targets: List[tuple] = []
    for ip in expand_targets:
        sub = expand_ip_to_subnet[ip]
        if ip in expand_alive:
            mtu_test_targets.append((ip, sub))
        else:
            unreachable = HostResult(ip=ip, network=str(sub), reachable=False, pmtud_status="Unreachable")
            results.append(unreachable)
            log(_fmt_scan_line(unreachable))
    for ip, sub in probe_ip_to_subnet.items():
        if ip in probe_alive:
            mtu_test_targets.append((ip, sub))

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=workers)
    try:
        futs = {}
        for ip, sub in mtu_test_targets:
            fut = pool.submit(mtu_test_host, ip, str(sub), mtu, count, timeout_ms, interval)
            futs[fut] = (sub, ip)
        for fut in concurrent.futures.as_completed(futs):
            sub, ip = futs[fut]
            r = _future_result_or_error(fut, ip, str(sub))
            results.append(r)
            log(_fmt_scan_line(r))
        pool.shutdown(wait=True)
    except KeyboardInterrupt:
        interrupted = True
        log("\nInterrupted - stopping, writing out what was scanned so far...")
        _fast_pool_shutdown(pool)

    return results, interrupted


# --- output ---------------------------------------------------------------

COLUMNS = ["IP", "Octet1", "Octet2", "Octet3", "Octet4", "Network",
           "Scanned", "Reachable", "MTU_Tested", "MTU_OK", "PMTUD_Status",
           "DF_Needed_MTU", "RTT_Reachability_ms", "RTT_MTU_Test_ms", "Note"]


def to_row(r: HostResult) -> list:
    ip = ipaddress.IPv4Address(r.ip)
    o = ip.packed
    return [r.ip, o[0], o[1], o[2], o[3], r.network, r.scanned,
            r.reachable, r.mtu_tested or "", r.mtu_ok, r.pmtud_status,
            r.df_needed_mtu or "",
            r.rtt_reachability_ms if r.rtt_reachability_ms is not None else "",
            r.rtt_mtu_test_ms if r.rtt_mtu_test_ms is not None else "",
            r.note]


def sort_by_ip(rows):
    return sorted(rows, key=lambda row: tuple(int(p) for p in row[0].split(".")))


def sort_by_octet(rows, idx):
    return sorted(rows, key=lambda row: (row[idx], tuple(int(p) for p in row[0].split("."))))


# --- minimal stdlib .xlsx writer (no openpyxl / no external deps) --------

_XLSX_NS_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_XLSX_NS_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_XLSX_NS_PKG_REL = "http://schemas.openxmlformats.org/package/2006/relationships"

_STYLE_DEFAULT = 0
_STYLE_HEADER = 1
_STATUS_STYLE = {
    "OK": 2,
    "DF-Needed": 3,
    "Blackhole": 4,
    "LocalMTUTooSmall": 4,
    "Error": 4,
    "Unreachable": 5,
    "NotScanned": 5,
}


def _xlsx_col_letter(n: int) -> str:
    s = ""
    while n:
        n, r = divmod(n - 1, 26)
        s = chr(65 + r) + s
    return s


def _xlsx_escape(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;"))


def _xlsx_cell_xml(col: int, row: int, value, style: int) -> str:
    ref = f"{_xlsx_col_letter(col)}{row}"
    if value is None or value == "":
        return f'<c r="{ref}" s="{style}"/>'
    if isinstance(value, bool):
        text = "True" if value else "False"
        return f'<c r="{ref}" s="{style}" t="inlineStr"><is><t>{text}</t></is></c>'
    if isinstance(value, (int, float)):
        return f'<c r="{ref}" s="{style}"><v>{value}</v></c>'
    text = _xlsx_escape(str(value))
    return f'<c r="{ref}" s="{style}" t="inlineStr"><is><t>{text}</t></is></c>'


def _xlsx_sheet_xml(header: list, sorted_rows: list, status_col_idx: int, col_widths: list) -> str:
    all_rows = [header] + sorted_rows
    n_rows, n_cols = len(all_rows), len(header)
    dim_ref = f"A1:{_xlsx_col_letter(n_cols)}{n_rows}"
    cols_xml = "".join(
        f'<col min="{i + 1}" max="{i + 1}" width="{w}" customWidth="1"/>'
        for i, w in enumerate(col_widths)
    )
    row_chunks = []
    for r_idx, row in enumerate(all_rows, start=1):
        if r_idx == 1:
            style = _STYLE_HEADER
        else:
            style = _STATUS_STYLE.get(row[status_col_idx], _STYLE_DEFAULT)
        cells = "".join(_xlsx_cell_xml(c_idx, r_idx, v, style) for c_idx, v in enumerate(row, start=1))
        row_chunks.append(f'<row r="{r_idx}">{cells}</row>')
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<worksheet xmlns="{_XLSX_NS_MAIN}">'
        f'<dimension ref="{dim_ref}"/>'
        '<sheetViews><sheetView workbookViewId="0">'
        '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>'
        '</sheetView></sheetViews>'
        f'<cols>{cols_xml}</cols>'
        f'<sheetData>{"".join(row_chunks)}</sheetData>'
        f'<autoFilter ref="{dim_ref}"/>'
        '</worksheet>'
    )


def _xlsx_styles_xml() -> str:
    fill_colors = ["FFC6EFCE", "FFFFEB9C", "FFFFC7CE", "FFD9D9D9"]
    fills_xml = (
        '<fill><patternFill patternType="none"/></fill>'
        '<fill><patternFill patternType="gray125"/></fill>'
        + "".join(
            f'<fill><patternFill patternType="solid"><fgColor rgb="{c}"/>'
            f'<bgColor indexed="64"/></patternFill></fill>'
            for c in fill_colors
        )
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<styleSheet xmlns="{_XLSX_NS_MAIN}">'
        '<fonts count="2"><font><sz val="11"/><name val="Calibri"/></font>'
        '<font><b/><sz val="11"/><name val="Calibri"/></font></fonts>'
        f'<fills count="6">{fills_xml}</fills>'
        '<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>'
        '<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>'
        '<cellXfs count="6">'
        '<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>'
        '<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/>'
        '<xf numFmtId="0" fontId="0" fillId="2" borderId="0" xfId="0" applyFill="1"/>'
        '<xf numFmtId="0" fontId="0" fillId="3" borderId="0" xfId="0" applyFill="1"/>'
        '<xf numFmtId="0" fontId="0" fillId="4" borderId="0" xfId="0" applyFill="1"/>'
        '<xf numFmtId="0" fontId="0" fillId="5" borderId="0" xfId="0" applyFill="1"/>'
        '</cellXfs>'
        '<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>'
        '</styleSheet>'
    )


def write_excel(rows, path: Path):
    import zipfile

    status_col_idx = COLUMNS.index("PMTUD_Status")
    col_widths = [max(10, len(c) + 2) for c in COLUMNS]
    sheets = [
        ("By_IP", sort_by_ip(rows)),
        ("By_Octet2", sort_by_octet(rows, 2)),
        ("By_Octet3", sort_by_octet(rows, 3)),
    ]

    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        + "".join(
            f'<Override PartName="/xl/worksheets/sheet{i}.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
            for i in range(1, len(sheets) + 1)
        )
        + "</Types>"
    )
    root_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<Relationships xmlns="{_XLSX_NS_PKG_REL}">'
        f'<Relationship Id="rId1" Type="{_XLSX_NS_REL}/officeDocument" Target="xl/workbook.xml"/>'
        '</Relationships>'
    )
    workbook_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<workbook xmlns="{_XLSX_NS_MAIN}" xmlns:r="{_XLSX_NS_REL}"><sheets>'
        + "".join(
            f'<sheet name="{name}" sheetId="{i}" r:id="rId{i}"/>'
            for i, (name, _) in enumerate(sheets, start=1)
        )
        + "</sheets></workbook>"
    )
    n = len(sheets)
    workbook_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<Relationships xmlns="{_XLSX_NS_PKG_REL}">'
        + "".join(
            f'<Relationship Id="rId{i}" Type="{_XLSX_NS_REL}/worksheet" Target="worksheets/sheet{i}.xml"/>'
            for i in range(1, n + 1)
        )
        + f'<Relationship Id="rId{n + 1}" Type="{_XLSX_NS_REL}/styles" Target="styles.xml"/>'
        + "</Relationships>"
    )

    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("_rels/.rels", root_rels)
        z.writestr("xl/workbook.xml", workbook_xml)
        z.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
        z.writestr("xl/styles.xml", _xlsx_styles_xml())
        for i, (name, sorted_rows) in enumerate(sheets, start=1):
            z.writestr(f"xl/worksheets/sheet{i}.xml",
                       _xlsx_sheet_xml(COLUMNS, sorted_rows, status_col_idx, col_widths))


def write_text(rows, path: Path, title: str):
    widths = [15, 7, 7, 7, 7, 18, 8, 9, 10, 7, 16, 14, 19, 15, 30]
    with open(path, "w") as f:
        f.write(f"# {title}\n")
        f.write("  ".join(c.ljust(w) for c, w in zip(COLUMNS, widths)) + "\n")
        for row in rows:
            f.write("  ".join(str(v).ljust(w) for v, w in zip(row, widths)) + "\n")


_STATUS_ORDER = ["OK", "DF-Needed", "Blackhole", "LocalMTUTooSmall", "Error", "Unreachable", "NotScanned"]


def build_summary(rows, elapsed_s: float, interrupted: bool, command_line: str,
                   options_summary: Optional[str] = None,
                   interval_note: Optional[str] = None) -> str:
    total = len(rows)
    reachable_idx = COLUMNS.index("Reachable")
    status_idx = COLUMNS.index("PMTUD_Status")
    reachable = sum(1 for row in rows if row[reachable_idx] is True)
    status_counts = Counter(row[status_idx] for row in rows)

    lines = [
        f"emtu-scan.py v{VERSION} - run summary",
        f"Command: {command_line}",
    ]
    if options_summary:
        lines.append(options_summary)
    if interval_note:
        lines.append(interval_note)
    lines += [
        f"Runtime: {elapsed_s:.1f}s" + (" (interrupted by Ctrl+C)" if interrupted else ""),
        f"Hosts total: {total}",
        f"Reachable: {reachable} ({(reachable / total * 100):.1f}%)" if total else "Reachable: 0",
        f"Unreachable: {total - reachable}",
        "PMTUD status breakdown:",
    ]
    for status in _STATUS_ORDER:
        if status_counts.get(status):
            lines.append(f"  {status}: {status_counts[status]}")
    for status, n in status_counts.items():
        if status not in _STATUS_ORDER:
            lines.append(f"  {status}: {n}")
    return "\n".join(lines) + "\n"


def workers_fd_warning(requested_workers: int) -> Optional[str]:
    """Only applies to the per-host MTU/DF test phase (Phase 3, uses
    `ping` subprocesses) - the asyncio ICMP reachability phases use a
    single socket, not one fd per target."""
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    except Exception:
        return None
    fds_per_worker = 3
    headroom = 50
    safe_cap = max(1, (soft - headroom) // fds_per_worker)
    if requested_workers > safe_cap:
        return (f"WARNING: --workers {requested_workers} may exceed this process's open-file "
                f"limit (ulimit -n = {soft}, hard = {hard}); estimated safe cap ~{safe_cap}. "
                f"Raise it with 'ulimit -n 4096' before running, or lower --workers.")
    return None


def probe_max_allowed_interval(requested_interval: float, timeout_ms: int) -> tuple:
    """Dynamic --interval capability probe against 127.0.0.1, used only by
    the per-host ping-based MTU/DF test (Phase 3)."""
    candidates = [requested_interval]
    for fallback in (0.2, 1.0):
        if fallback > requested_interval and fallback not in candidates:
            candidates.append(fallback)
    for candidate in candidates:
        out = run_ping("127.0.0.1", size=32, count=1, timeout_ms=timeout_ms, df=False, interval=candidate)
        if not RE_INTERVAL_RESTRICTED.search(out):
            if candidate == requested_interval:
                return candidate, None
            return candidate, (
                f"NOTE: --interval {requested_interval}s is not permitted for this user/ping binary "
                f"on this system (rate-limited); auto-detected and using {candidate}s instead. "
                f"Grant CAP_NET_RAW (e.g. 'sudo setcap cap_net_raw+ep $(which ping)') or run as root "
                f"to use lower intervals."
            )
    return requested_interval, (
        f"WARNING: could not confirm a working ping interval (tried {candidates} against 127.0.0.1); "
        f"proceeding with --interval {requested_interval}s anyway - expect possible false "
        f"'Unreachable' results if it is in fact rejected per-host during the MTU/DF test phase."
    )


def check_ping_df_capability_or_exit() -> None:
    if IS_MACOS or PING_VARIANT == "iputils":
        return
    print(f"ERROR: this system's ping cannot set the DF (Don't Fragment) bit "
          f"(detected: {PING_VARIANT}), so the MTU/PMTUD test cannot run correctly.")
    if PING_VARIANT == "inetutils":
        print("This is GNU inetutils ping (a common default on some Debian / Raspberry Pi "
              "OS installs) - it has no DF-bit option at all.")
        print("Fix: install iputils-ping instead, e.g. on Debian/Raspberry Pi OS:")
        print("  sudo apt install iputils-ping")
        print("  sudo update-alternatives --set ping /usr/bin/ping.iputils   # if still needed")
    else:
        print("Could not identify a supported ping variant on this system.")
        print("Please send the output of 'ping --help' and 'ping -V' so support can be added.")
    sys.exit(1)


def _parse_probe_hosts(s: str) -> List[int]:
    """argparse type= for --probe-hosts: '1,10,253,254,16' -> [1, 10, 253, 254, 16]."""
    try:
        offsets = [int(x.strip()) for x in s.split(",") if x.strip() != ""]
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"invalid --probe-hosts value {s!r} - expected comma-separated integers, "
            f"e.g. 1,10,253,254,16"
        )
    if not offsets:
        raise argparse.ArgumentTypeError("--probe-hosts must list at least one offset")
    return offsets


_BANNER_RULE = "-" * 60


def print_banner() -> None:
    print(_BANNER_RULE)
    print(f"Express MTU Scanner / emtu-scan.py  v{VERSION}")
    print("by AI & Ewald Jeitler  - May your packets always fit")
    print(_BANNER_RULE)


def print_footer() -> None:
    print("THX for using emtu-scan.py visit https://www.jeitler.cc")


def main():
    ap = argparse.ArgumentParser(description="emtu-scan.py - fast host reachability + path-MTU/PMTUD scanner")
    ap.add_argument("networks", nargs="*", help="CIDR(s), e.g. 10.0.0.0/24")
    ap.add_argument("-f", "--file", help="text file with one CIDR per line (# comments allowed)")
    ap.add_argument("--mask", type=int, default=None,
                     help="probe-subnet size (e.g. 24): only scan a block fully if its "
                          "first/last host answers. Default: no splitting, scan given CIDR directly")
    ap.add_argument("--probe-hosts", type=_parse_probe_hosts, default=None,
                     help="comma-separated list of host offsets from each --mask subnet's network "
                          "address to probe, instead of just the first and last host (e.g. "
                          "'1,10,253,254,16' probes x.x.x.1, .10, .253, .254 and .16 in every /24 "
                          "subnet). More probe points catch subnets whose alive hosts aren't the "
                          "first/last one, at the cost of more probe-phase ICMP traffic. An offset "
                          "outside a given subnet's valid host range is skipped for that subnet. "
                          "Ignored if --full-scan is set (no probe phase to apply it to)")
    ap.add_argument("--full-scan", action="store_true",
                     help="skip the --mask probe phase (first/last-host subnet elimination) "
                          "entirely and treat every subnet as active: every host in every given "
                          "network goes straight to the ICMP reachability check before the MTU/DF "
                          "test. Use this when subnets with only some hosts alive (not the probed "
                          "one(s)) are being wrongly skipped, or when you want a complete "
                          "host-by-host scan. Slower than probing (no subnet elimination happens "
                          "at all), but still far faster than a raw ping-based full scan since "
                          "reachability is still checked via the fast asyncio ICMP sweep before "
                          "the expensive per-host ping/MTU test")
    ap.add_argument("--mtu", type=int, default=1500, help="MTU to test (default 1500)")
    ap.add_argument("--count", type=int, default=3, help="pings per MTU/DF test (default 3)")
    ap.add_argument("--timeout", type=int, default=1000,
                     help="per-packet timeout in ms (default 1000) for the MTU/DF test phase")
    ap.add_argument("--interval", type=float, default=0.05,
                     help="seconds between ping packets during the MTU/DF test phase (default "
                          "0.05); auto-adjusted at startup if rejected by this user/ping binary.")
    ap.add_argument("--workers", type=int, default=50,
                     help="parallel worker threads for the MTU/DF test phase only (default 50); "
                          "the asyncio reachability phases are unaffected by this value")
    ap.add_argument("--icmp-timeout", type=float, default=1.0,
                     help="seconds to wait for ICMP echo replies per round during the "
                          "reachability/probe phases (default 1.0)")
    ap.add_argument("--icmp-retries", type=int, default=2,
                     help="retry rounds for hosts that didn't reply, during the "
                          "reachability/probe phases (default 2; each round waits up to "
                          "--icmp-timeout, so genuinely dead hosts cost at most "
                          "(retries+1)*icmp-timeout seconds once per phase, not per host)")
    ap.add_argument("--icmp-send-burst", type=int, default=_ICMP_SEND_YIELD_EVERY,
                     help=f"pause for --icmp-send-pause seconds after every N ICMP sends within "
                          f"a round, during the reachability/probe phases (default "
                          f"{_ICMP_SEND_YIELD_EVERY}; 0 disables pacing entirely - sends the whole "
                          f"round as one uninterrupted burst). Lower this (e.g. 100 or 50) to slow "
                          f"down large bursts if you suspect send-side/receive-buffer packet loss "
                          f"at very large scan sizes (e.g. under-detection on a /8-sized scan)")
    ap.add_argument("--icmp-send-pause", type=float, default=_ICMP_SEND_YIELD_SLEEP,
                     help=f"seconds to sleep at each --icmp-send-burst pacing point (default "
                          f"{_ICMP_SEND_YIELD_SLEEP}); raise this together with a lower "
                          f"--icmp-send-burst for more aggressive pacing")
    ap.add_argument("--outdir", default="./scan_results", help="base output directory")
    ap.add_argument("--quiet", action="store_true", help="suppress per-host progress log")
    ap.add_argument("--allow-huge-scan", action="store_true",
                     help=f"required to proceed when the given network(s) total more than "
                          f"{_HUGE_SCAN_ADDRESS_THRESHOLD:,} addresses (roughly a /8 or larger). "
                          f"Without --mask, or with --full-scan, the whole address range is held "
                          f"in memory at once - a /7 or bigger can need several GB and a long "
                          f"runtime. Splitting into smaller networks (or adding --mask) is usually "
                          f"a better fix than raising this")
    args = ap.parse_args()

    if not args.networks and not args.file:
        ap.error("provide at least one CIDR argument or --file")
    if args.full_scan and args.probe_hosts:
        print("NOTE: --probe-hosts is ignored with --full-scan set (there is no probe phase to apply it to).")

    try:
        networks = parse_networks(args.networks, args.file)
    except ValueError as e:
        print(f"ERROR: invalid network/CIDR argument - {e}")
        print("(check for a typo, or a missing '--' before an option, e.g. 'mask' instead of '--mask')")
        print()
        ap.print_help()
        sys.exit(2)

    # Memory risk is specifically the "whole range materialized as one block"
    # path: --full-scan, or no --mask (the given CIDR is then scanned as a
    # single block - same thing). With --mask set to a real subnet split,
    # only subnets that pass the probe phase get expanded, so a /8 (or
    # bigger) at e.g. --mask 24 is NOT the same memory risk and is not
    # gated here.
    materializes_whole_range = args.full_scan or args.mask is None
    total_addresses = sum(n.num_addresses for n in networks)
    if materializes_whole_range and total_addresses > _HUGE_SCAN_ADDRESS_THRESHOLD and not args.allow_huge_scan:
        approx_gb = total_addresses * 104 / (1024 ** 3)  # ~104 bytes/address, measured (list+dict)
        print(f"ERROR: {total_addresses:,} address(es) given without subnet-level splitting - "
              f"that's above the {_HUGE_SCAN_ADDRESS_THRESHOLD:,}-address safety threshold "
              f"(roughly a /8).")
        print(f"Without --mask, or with --full-scan, the full target list is built in memory at "
              f"once - this would need on the order of {approx_gb:.1f}GB and a long runtime.")
        print("Fix: add --mask to probe/eliminate subnets first (memory then scales with active "
              "subnets, not the whole range), split the range into smaller networks, or pass "
              "--allow-huge-scan if you really mean this and have the memory for it.")
        sys.exit(1)

    if args.mask is not None and not args.full_scan:
        too_small = [n for n in networks if args.mask < n.prefixlen]
        if too_small:
            print(f"ERROR: --mask /{args.mask} is larger than {'network' if len(too_small) == 1 else 'these networks'} "
                  + ", ".join(str(n) for n in too_small)
                  + f" (/{too_small[0].prefixlen}{'' if len(too_small) == 1 else ' or smaller'}).")
            print(f"--mask /{args.mask} means 'split into /{args.mask} blocks', which only makes "
                  f"sense for a mask that's NUMERICALLY LARGER than (i.e. a smaller block than) the "
                  f"network(s) given.")
            if any(n.prefixlen == 32 for n in too_small):
                print("Note: a bare host IP with no '/prefix' (e.g. '10.1.1.1') is treated as /32 - "
                      "if you meant a whole subnet, give it explicitly (e.g. '10.1.1.0/24') or drop "
                      "--mask to scan just that one host.")
            sys.exit(1)

    log = (lambda *a, **k: None) if args.quiet else print
    print_banner()
    print(f"{len(networks)} network(s), mask=/{args.mask}, mtu={args.mtu}")
    print(f"ping variant (MTU/DF test): {'bsd (macOS)' if IS_MACOS else PING_VARIANT}")
    check_ping_df_capability_or_exit()
    check_async_icmp_capability_or_exit()
    fd_warning = workers_fd_warning(args.workers)
    if fd_warning:
        print(fd_warning)
        print("Aborting - lower --workers or raise the open-file limit first, then re-run.")
        sys.exit(1)

    effective_interval, interval_note = probe_max_allowed_interval(args.interval, args.timeout)
    if interval_note:
        print(interval_note)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = Path(args.outdir) / ts
    try:
        outdir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        print(f"ERROR: cannot create output directory {str(outdir)!r} ({e}).")
        print(f"Check that {args.outdir!r} exists and is writable, or pass a different "
              f"--outdir.")
        sys.exit(1)

    t0 = time.monotonic()
    try:
        results, interrupted = scan(networks, args.mask, args.mtu, args.count, args.timeout,
                                     args.workers, effective_interval,
                                     icmp_timeout_s=args.icmp_timeout, icmp_retries=args.icmp_retries,
                                     log=log, outdir=outdir,
                                     icmp_send_burst=args.icmp_send_burst, icmp_send_pause=args.icmp_send_pause,
                                     full_scan=args.full_scan, probe_hosts=args.probe_hosts)
    except ValueError as e:
        # Safety net: the --mask/network mismatch above should already catch
        # this before we get here, but never let a ValueError from deep
        # inside scan() surface as a raw traceback either.
        print(f"ERROR: {e}")
        sys.exit(1)
    elapsed = time.monotonic() - t0
    rows = [to_row(r) for r in results]

    write_text(sort_by_ip(rows), outdir / "sorted_by_ip.txt", "sorted by full IP")
    write_text(sort_by_octet(rows, 2), outdir / "sorted_by_octet2.txt", "sorted by 2nd octet")
    write_text(sort_by_octet(rows, 3), outdir / "sorted_by_octet3.txt", "sorted by 3rd octet")
    try:
        write_excel(rows, outdir / "mtu_scan_results.xlsx")
    except Exception as e:
        print(f"WARNING: xlsx write failed ({e}); text results are still in {outdir}")

    command_line = " ".join(["python3"] + sys.argv)
    interval_opt = (f"{effective_interval}s" if effective_interval == args.interval
                     else f"{effective_interval}s (requested {args.interval}s)")
    probe_hosts_opt = (",".join(str(o) for o in args.probe_hosts) if args.probe_hosts else "default(first+last)")
    options_summary = (
        "Options (incl. unspecified defaults): "
        f"mask=/{args.mask}, mtu={args.mtu}, count={args.count}, timeout={args.timeout}ms, "
        f"interval={interval_opt}, workers={args.workers}, icmp-timeout={args.icmp_timeout}s, "
        f"icmp-retries={args.icmp_retries}, icmp-send-burst={args.icmp_send_burst}, "
        f"icmp-send-pause={args.icmp_send_pause}s, full-scan={args.full_scan}, "
        f"probe-hosts={probe_hosts_opt}, outdir={args.outdir}"
    )
    summary = build_summary(rows, elapsed, interrupted, command_line,
                             options_summary=options_summary, interval_note=interval_note)
    (outdir / "summary.txt").write_text(summary)
    print()
    print(summary)
    print(f"output -> {outdir}")
    print()
    print_footer()

    if interrupted:
        sys.exit(130)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(130)
