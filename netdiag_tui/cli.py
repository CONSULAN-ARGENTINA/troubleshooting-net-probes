#!/usr/bin/env python3
import argparse
import curses
import os
import queue
import re
import socket
import struct
import subprocess
import threading
import time
import select
import json
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Optional PDF (RHEL9: python3-reportlab)
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas as rl_canvas
    REPORTLAB_OK = True
except Exception:
    REPORTLAB_OK = False

TRACEPATH_BIN = "tracepath"
TRACEROUTE_BIN = "traceroute"
CURL_BIN = "curl"
WGET_BIN = "wget"

# ============================================================
# Borders: curses ACS (portable in SSH/tmux/TTY) ✅
# Popups: opaque (fill with spaces) ✅
# Added:
#  - RIR/RDAP NIC info per hop (owner/email/range, v4/v6) ✅
#  - MPLS best-effort per hop (RFC4950 ICMP extensions for pytrace IPv4 + parse traceroute -e) ✅
# NEW for publish:
#  - Change trace probe port from Menu (M) and hotkey 'Y' ✅
#  - PDF report from current screen state with hotkey 'P' + filename popup ✅
#  - Web server probe menu (curl/wget) to non-existing endpoint ✅
# ============================================================

# -------------------------
# Drawing helpers
# -------------------------
def fill_rect(stdscr, y0, x0, h, w, attr=0):
    maxy, maxx = stdscr.getmaxyx()
    y1 = min(maxy, y0 + h)
    x1 = min(maxx, x0 + w)
    for y in range(max(0, y0), y1):
        try:
            stdscr.addnstr(
                y, max(0, x0),
                " " * max(0, x1 - max(0, x0)),
                max(0, x1 - max(0, x0)),
                attr
            )
        except Exception:
            pass

def draw_border_box(stdscr, y0, x0, h, w, attr=0):
    if h < 2 or w < 2:
        return
    y1 = y0 + h - 1
    x1 = x0 + w - 1
    try:
        stdscr.addch(y0, x0, curses.ACS_ULCORNER, attr)
        stdscr.addch(y0, x1, curses.ACS_URCORNER, attr)
        stdscr.addch(y1, x0, curses.ACS_LLCORNER, attr)
        stdscr.addch(y1, x1, curses.ACS_LRCORNER, attr)
    except Exception:
        return

    for x in range(x0 + 1, x1):
        try:
            stdscr.addch(y0, x, curses.ACS_HLINE, attr)
            stdscr.addch(y1, x, curses.ACS_HLINE, attr)
        except Exception:
            pass
    for y in range(y0 + 1, y1):
        try:
            stdscr.addch(y, x0, curses.ACS_VLINE, attr)
            stdscr.addch(y, x1, curses.ACS_VLINE, attr)
        except Exception:
            pass

def draw_vline_box(stdscr, y0, y1, x, attr=0):
    for y in range(y0, y1 + 1):
        try:
            stdscr.addch(y, x, curses.ACS_VLINE, attr)
        except Exception:
            pass

def draw_hline_box(stdscr, x0, x1, y, attr=0):
    for x in range(x0, x1 + 1):
        try:
            stdscr.addch(y, x, curses.ACS_HLINE, attr)
        except Exception:
            pass

def draw_cross_acs(stdscr, y, x, kind: str, attr=0):
    ch = curses.ACS_PLUS
    if kind == "ttee":
        ch = curses.ACS_TTEE
    elif kind == "btee":
        ch = curses.ACS_BTEE
    elif kind == "ltee":
        ch = curses.ACS_LTEE
    elif kind == "rtee":
        ch = curses.ACS_RTEE
    else:
        ch = curses.ACS_PLUS
    try:
        stdscr.addch(y, x, ch, attr)
    except Exception:
        pass

# -------------------------
# subprocess helpers
# -------------------------
def which(cmd: str) -> bool:
    for p in os.environ.get("PATH", "").split(os.pathsep):
        f = os.path.join(p, cmd)
        if os.path.isfile(f) and os.access(f, os.X_OK):
            return True
    return False

def run_cmd(cmd: List[str], timeout_s: float = 6.0) -> Tuple[int, str]:
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            out, _ = p.communicate(timeout=timeout_s)
            return p.returncode or 0, out or ""
        except subprocess.TimeoutExpired:
            try:
                p.kill()
            except Exception:
                pass
            out, _ = p.communicate(timeout=1)
            return 124, (out or "") + "\n[netdiag] timeout"
    except Exception as e:
        return 1, str(e)

# -------------------------
# Trace parsing (external) + MPLS parse (traceroute -e)
# -------------------------
def parse_tracepath(out: str) -> Tuple[List[str], Dict[str, str]]:
    ips: List[str] = []
    mpls_map: Dict[str, str] = {}
    for line in out.splitlines():
        m = re.match(r"^\s*\d+:\s+([0-9a-fA-F\.:]+)\s+", line)
        if m:
            ip = m.group(1)
            if ip not in ips:
                ips.append(ip)
    return ips, mpls_map

def parse_traceroute(out: str) -> Tuple[List[str], Dict[str, str]]:
    ips: List[str] = []
    mpls_map: Dict[str, str] = {}
    last_ip = None
    for line in out.splitlines():
        m = re.search(r"\(([\d\.]+)\)", line)
        if m:
            ip = m.group(1)
            last_ip = ip
            if ip not in ips:
                ips.append(ip)
        else:
            m2 = re.match(r"^\s*\d+\s+([\d\.]+)\s+", line)
            if m2:
                ip = m2.group(1)
                last_ip = ip
                if ip not in ips:
                    ips.append(ip)

        if last_ip and ("MPLS" in line or "Label" in line):
            seg = re.sub(r"\s+", " ", line.strip())
            mpls_map[last_ip] = seg[-80:]
    return ips, mpls_map

# -------------------------
# ASN lookup (Team Cymru WHOIS)
# -------------------------
def asn_lookup_whois(ip: str) -> Tuple[str, str]:
    try:
        s = socket.create_connection(("whois.cymru.com", 43), timeout=3)
        s.sendall(f" -v {ip}\n".encode("ascii", "ignore"))
        data = b""
        while True:
            ch = s.recv(4096)
            if not ch:
                break
            data += ch
        s.close()
        txt = data.decode("utf-8", "ignore")

        for line in txt.splitlines():
            if re.match(r"^\s*AS\s+\|", line):
                continue
            if "|" in line and ip in line:
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 7:
                    return (parts[0] or "?"), (parts[6] or "")
        return "?", ""
    except Exception:
        return "?", ""

# -------------------------
# RDAP NIC info (RIR) - best effort
# -------------------------
RDAP_BASES = [
    ("ARIN",     "https://rdap.arin.net/registry/ip/"),
    ("RIPE",     "https://rdap.db.ripe.net/ip/"),
    ("APNIC",    "https://rdap.apnic.net/ip/"),
    ("LACNIC",   "https://rdap.lacnic.net/rdap/ip/"),
    ("AFRINIC",  "https://rdap.afrinic.net/rdap/ip/"),
]

def _rdap_http_get(url: str, timeout_s: float = 2.2) -> Optional[dict]:
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/rdap+json, application/json"})
        with urllib.request.urlopen(req, timeout=timeout_s) as r:
            if getattr(r, "status", 200) != 200:
                return None
            data = r.read()
            return json.loads(data.decode("utf-8", "ignore"))
    except Exception:
        return None

def _extract_emails_from_vcard(vcard_array) -> List[str]:
    emails: List[str] = []
    try:
        if not vcard_array or len(vcard_array) < 2:
            return emails
        entries = vcard_array[1]
        for e in entries:
            if isinstance(e, list) and len(e) >= 4 and str(e[0]).lower() == "email":
                val = str(e[3]).strip()
                if val and val not in emails:
                    emails.append(val)
    except Exception:
        pass
    return emails

def rdap_lookup_ip(ip: str) -> Tuple[str, str, str, str]:
    if ip == "*" or not ip:
        return "?", "", "", ""

    doc = None
    rir = "?"
    for rir_name, base in RDAP_BASES:
        d = _rdap_http_get(base + ip)
        if d and isinstance(d, dict) and ("name" in d or "handle" in d or "startAddress" in d):
            doc = d
            rir = rir_name
            break
    if not doc:
        return "?", "", "", ""

    owner = ""
    email = ""
    rng = ""

    try:
        sa = doc.get("startAddress")
        ea = doc.get("endAddress")
        if sa and ea:
            rng = f"{sa} - {ea}"
        else:
            cidrs = []
            for c in (doc.get("cidr0_cidrs") or []):
                v = c.get("v4prefix") or c.get("v6prefix")
                ln = c.get("length")
                if v is not None and ln is not None:
                    cidrs.append(f"{v}/{ln}")
            if cidrs:
                rng = ", ".join(cidrs[:4])

        owner = str(doc.get("name") or doc.get("handle") or "").strip()

        emails: List[str] = []
        ents = doc.get("entities") or []
        for ent in ents:
            if not isinstance(ent, dict):
                continue
            vca = ent.get("vcardArray")
            emails += _extract_emails_from_vcard(vca)
            if not owner:
                fn = ""
                try:
                    if vca and len(vca) >= 2:
                        for e in vca[1]:
                            if isinstance(e, list) and len(e) >= 4 and str(e[0]).lower() == "fn":
                                fn = str(e[3]).strip()
                                break
                except Exception:
                    fn = ""
                if fn:
                    owner = fn
        if emails:
            email = emails[0]
    except Exception:
        pass

    return rir, owner, email, rng

# -------------------------
# ICMP checksum
# -------------------------
def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += (s >> 16)
    return (~s) & 0xFFFF

# -------------------------
# MPLS (RFC4950) parser - best effort (IPv4 ICMP only)
# -------------------------
def parse_mpls_rfc4950_from_icmp_v4(pkt: bytes) -> Optional[str]:
    try:
        if len(pkt) < 28:
            return None
        ihl = (pkt[0] & 0x0F) * 4
        if len(pkt) < ihl + 8:
            return None
        icmp_off = ihl
        icmp_type = pkt[icmp_off]
        if icmp_type not in (11, 3):
            return None

        tail = pkt[icmp_off + 8:]
        for pos in range(0, max(0, len(tail) - 8), 4):
            ext = tail[pos:]
            if len(ext) < 8:
                break
            v = (ext[0] >> 4) & 0x0F
            if v != 2:
                continue
            extlen_words = ((ext[0] & 0x0F) << 8) | ext[1]
            extlen = extlen_words * 4
            if extlen < 8 or extlen > len(ext):
                continue
            off = 4
            while off + 4 <= extlen:
                cls = (ext[off] << 8) | ext[off + 1]
                ctype = ext[off + 2]
                olen_words = ext[off + 3]
                olen = olen_words * 4
                if olen < 4 or off + olen > extlen:
                    break
                if cls == 1 and ctype == 1 and olen >= 8:
                    stack = ext[off + 4: off + olen]
                    if len(stack) >= 4:
                        v = struct.unpack("!I", stack[:4])[0]
                        label = (v >> 12) & 0xFFFFF
                        exp = (v >> 9) & 0x7
                        sbit = (v >> 8) & 0x1
                        ttl = v & 0xFF
                        return f"MPLS {label}/exp{exp}/s{sbit}/ttl{ttl}"
                off += olen
        return None
    except Exception:
        return None

# -------------------------
# ICMP ping (v4 raw) + ICMPv6 best-effort
# -------------------------
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0

def icmp_ping_v4_once(ip: str, ident: int, seq: int, timeout_s: float, tos: int) -> Tuple[bool, Optional[int]]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.settimeout(timeout_s)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, tos & 0xFF)
    except Exception:
        return False, None

    payload = struct.pack("!d", time.time()) + b"NETDIAG"
    hdr = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, ident & 0xFFFF, seq & 0xFFFF)
    csum = checksum(hdr + payload)
    hdr = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, csum, ident & 0xFFFF, seq & 0xFFFF)
    pkt = hdr + payload

    try:
        s.sendto(pkt, (ip, 0))
        data, _ = s.recvfrom(2048)
        if len(data) < 28:
            return False, None
        ttl_reply = data[8]
        icmp = data[20:28]
        itype, _, _, rid, rseq = struct.unpack("!BBHHH", icmp)
        ok = (itype == ICMP_ECHO_REPLY and rid == (ident & 0xFFFF) and rseq == (seq & 0xFFFF))
        return ok, ttl_reply
    except Exception:
        return False, None
    finally:
        try:
            s.close()
        except Exception:
            pass

def icmp_ping_v6_once(ip6: str, ident: int, seq: int, timeout_s: float, tclass: int) -> Tuple[bool, Optional[int]]:
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_ICMPV6)
        s.settimeout(timeout_s)
        try:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_TCLASS, tclass & 0xFF)
        except Exception:
            pass
    except Exception:
        return False, None

    ICMP6_ECHO_REQUEST = 128
    ICMP6_ECHO_REPLY = 129
    payload = struct.pack("!d", time.time()) + b"NETDIAG6"
    hdr = struct.pack("!BBHHH", ICMP6_ECHO_REQUEST, 0, 0, ident & 0xFFFF, seq & 0xFFFF)
    pkt = hdr + payload

    try:
        s.sendto(pkt, (ip6, 0, 0, 0))
        data, _ = s.recvfrom(2048)
        if len(data) < 8:
            return False, None
        itype = data[0]
        rid = struct.unpack("!H", data[4:6])[0]
        rseq = struct.unpack("!H", data[6:8])[0]
        ok = (itype == ICMP6_ECHO_REPLY and rid == (ident & 0xFFFF) and rseq == (seq & 0xFFFF))
        return ok, None
    except Exception:
        return False, None
    finally:
        try:
            s.close()
        except Exception:
            pass

# -------------------------
# TCP/UDP "ping" by port
# -------------------------
def tcp_port_ping_once(ip: str, port: int, timeout_s: float, tos: int) -> Tuple[bool, float]:
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    t0 = time.time()
    try:
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(timeout_s)
        if fam == socket.AF_INET:
            try:
                s.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, tos & 0xFF)
            except Exception:
                pass
        else:
            try:
                s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_TCLASS, tos & 0xFF)
            except Exception:
                pass

        r = s.connect_ex((ip, port, 0, 0) if fam == socket.AF_INET6 else (ip, port))
        s.close()
        rtt = (time.time() - t0) * 1000.0
        if r == 0 or r == 111:
            return True, rtt
        return False, rtt
    except Exception:
        rtt = (time.time() - t0) * 1000.0
        return False, rtt

def udp_port_ping_once(ip: str, port: int, timeout_s: float, tos: int) -> Tuple[bool, float]:
    t0 = time.time()
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    send = None
    recv = None
    try:
        if fam == socket.AF_INET:
            recv = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            recv.setblocking(False)
            send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                send.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, tos & 0xFF)
            except Exception:
                pass
            send.sendto(b"\x00", (ip, port))
            t_end = time.time() + timeout_s
            while time.time() < t_end:
                r, _, _ = select.select([recv], [], [], max(0.0, t_end - time.time()))
                if not r:
                    break
                pkt, addr = recv.recvfrom(4096)
                src = addr[0]
                if src != ip:
                    continue
                if len(pkt) >= 28:
                    itype = pkt[20]
                    if itype == 3:
                        rtt = (time.time() - t0) * 1000.0
                        return True, rtt
            rtt = (time.time() - t0) * 1000.0
            return False, rtt
        else:
            recv = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
            recv.setblocking(False)
            send = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            try:
                send.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_TCLASS, tos & 0xFF)
            except Exception:
                pass
            send.sendto(b"\x00", (ip, port, 0, 0))
            t_end = time.time() + timeout_s
            while time.time() < t_end:
                r, _, _ = select.select([recv], [], [], max(0.0, t_end - time.time()))
                if not r:
                    break
                pkt, addr = recv.recvfrom(4096)
                src = addr[0]
                if src != ip:
                    continue
                if len(pkt) >= 8:
                    itype = pkt[0]
                    if itype == 1:
                        rtt = (time.time() - t0) * 1000.0
                        return True, rtt
            rtt = (time.time() - t0) * 1000.0
            return False, rtt
    except Exception:
        rtt = (time.time() - t0) * 1000.0
        return False, rtt
    finally:
        try:
            if send:
                send.close()
        except Exception:
            pass
        try:
            if recv:
                recv.close()
        except Exception:
            pass

# -------------------------
# Python trace (fast, no DNS) + MPLS best-effort (IPv4)
# -------------------------
def pytrace_udp(dest: Tuple[int, str], max_hops: int, timeout_s: float, tos: int, base_port: int = 33434) -> Tuple[List[str], Dict[str, str], str]:
    fam, dip = dest
    hops: List[str] = []
    mpls_map: Dict[str, str] = {}

    if fam == socket.AF_INET:
        try:
            recv = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            recv.setblocking(False)
            send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            send.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, tos & 0xFF)
        except Exception:
            return [], {}, "pyudp init fail"
        done = False
        try:
            for ttl in range(1, max_hops + 1):
                send.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                try:
                    send.sendto(b"\x00", (dip, base_port + ttl))
                except Exception:
                    hops.append("*")
                    continue

                t_end = time.time() + timeout_s
                hop_ip = "*"
                hop_mpls = None
                while time.time() < t_end:
                    r, _, _ = select.select([recv], [], [], max(0.0, t_end - time.time()))
                    if not r:
                        break
                    pkt, addr = recv.recvfrom(4096)
                    src = addr[0]
                    if len(pkt) >= 28:
                        icmp_type = pkt[20]
                        if icmp_type in (11, 3):
                            hop_ip = src
                            hop_mpls = parse_mpls_rfc4950_from_icmp_v4(pkt)
                            if hop_mpls:
                                mpls_map[hop_ip] = hop_mpls
                            if src == dip and icmp_type == 3:
                                done = True
                            break
                hops.append(hop_ip)
                if done:
                    break
            return hops, mpls_map, "ok"
        finally:
            try:
                send.close()
            except Exception:
                pass
            try:
                recv.close()
            except Exception:
                pass

    if fam == socket.AF_INET6:
        try:
            recv = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
            recv.setblocking(False)
            send = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            try:
                send.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_TCLASS, tos & 0xFF)
            except Exception:
                pass
        except Exception:
            return [], {}, "pyudp6 init fail"

        done = False
        try:
            for ttl in range(1, max_hops + 1):
                try:
                    send.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, ttl)
                except Exception:
                    pass
                try:
                    send.sendto(b"\x00", (dip, base_port + ttl, 0, 0))
                except Exception:
                    hops.append("*")
                    continue

                t_end = time.time() + timeout_s
                hop_ip = "*"
                while time.time() < t_end:
                    r, _, _ = select.select([recv], [], [], max(0.0, t_end - time.time()))
                    if not r:
                        break
                    pkt, addr = recv.recvfrom(4096)
                    src = addr[0]
                    if len(pkt) >= 8:
                        icmp_type = pkt[0]
                        if icmp_type in (3, 1):
                            hop_ip = src
                            if src == dip and icmp_type == 1:
                                done = True
                            break
                hops.append(hop_ip)
                if done:
                    break
            return hops, {}, "ok"
        finally:
            try:
                send.close()
            except Exception:
                pass
            try:
                recv.close()
            except Exception:
                pass

    return [], {}, "unsupported family"

def pytrace_icmp_v4(dest_ip: str, max_hops: int, timeout_s: float, tos: int) -> Tuple[List[str], Dict[str, str], str]:
    hops: List[str] = []
    mpls_map: Dict[str, str] = {}
    ident = (os.getpid() ^ int(time.time())) & 0xFFFF
    seq = 0

    try:
        recv = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        recv.setblocking(False)
        send = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        send.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, tos & 0xFF)
    except Exception:
        return [], {}, "pyicmp init fail"

    try:
        for ttl in range(1, max_hops + 1):
            seq += 1
            send.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

            payload = struct.pack("!d", time.time()) + b"PYICMP"
            hdr = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, ident, seq)
            csum = checksum(hdr + payload)
            hdr = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, csum, ident, seq)
            pkt = hdr + payload

            try:
                send.sendto(pkt, (dest_ip, 0))
            except Exception:
                hops.append("*")
                continue

            t_end = time.time() + timeout_s
            hop_ip = "*"
            hop_mpls = None
            while time.time() < t_end:
                r, _, _ = select.select([recv], [], [], max(0.0, t_end - time.time()))
                if not r:
                    break
                rpkt, addr = recv.recvfrom(4096)
                src = addr[0]
                if len(rpkt) >= 28:
                    itype = rpkt[20]
                    if itype == 11:
                        hop_ip = src
                        hop_mpls = parse_mpls_rfc4950_from_icmp_v4(rpkt)
                        if hop_mpls:
                            mpls_map[hop_ip] = hop_mpls
                        break
                    if itype == 0 and src == dest_ip:
                        hop_ip = src
                        hops.append(hop_ip)
                        return hops, mpls_map, "ok"
            hops.append(hop_ip)
        return hops, mpls_map, "ok"
    finally:
        try:
            send.close()
        except Exception:
            pass
        try:
            recv.close()
        except Exception:
            pass

# -------------------------
# Port probes: TCP/UDP + RAW TCP SYN (IPv4) + SCTP best-effort
# -------------------------
def tcp_connect_probe(ip: str, port: int, timeout_s: float = 0.6) -> str:
    try:
        fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.settimeout(timeout_s)
        r = s.connect_ex((ip, port, 0, 0) if fam == socket.AF_INET6 else (ip, port))
        s.close()
        return "open" if r == 0 else "closed/filtered"
    except Exception:
        return "error"

def udp_send_probe(ip: str, port: int, timeout_s: float = 0.6) -> str:
    try:
        fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
        s = socket.socket(fam, socket.SOCK_DGRAM)
        s.settimeout(timeout_s)
        if fam == socket.AF_INET6:
            s.sendto(b"\x00", (ip, port, 0, 0))
        else:
            s.sendto(b"\x00", (ip, port))
        s.close()
        return "open|filtered"
    except Exception:
        return "error"

def sctp_connect_probe(ip: str, port: int, timeout_s: float = 0.8) -> str:
    try:
        proto = getattr(socket, "IPPROTO_SCTP", None)
        if proto is None:
            return "sctp n/a"
        fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
        s = socket.socket(fam, socket.SOCK_STREAM, proto)
        s.settimeout(timeout_s)
        r = s.connect_ex((ip, port, 0, 0) if fam == socket.AF_INET6 else (ip, port))
        s.close()
        return "open(sctp)" if r == 0 else "closed/filtered(sctp)"
    except Exception:
        return "error(sctp)"

def _tcp_checksum_v4(src_ip: str, dst_ip: str, tcp_hdr: bytes, payload: bytes = b"") -> int:
    pseudo = socket.inet_aton(src_ip) + socket.inet_aton(dst_ip) + struct.pack("!BBH", 0, socket.IPPROTO_TCP, len(tcp_hdr) + len(payload))
    return checksum(pseudo + tcp_hdr + payload)

def raw_tcp_syn_probe_v4(dst_ip: str, dst_port: int, timeout_s: float = 0.8, tos: int = 0) -> str:
    send = None
    recv = None
    try:
        tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tmp.connect((dst_ip, dst_port))
        src_ip = tmp.getsockname()[0]
        tmp.close()

        send = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        recv = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        recv.setblocking(False)

        ver_ihl = (4 << 4) | 5
        tos_b = tos & 0xFF
        total_len = 20 + 20
        ident = (os.getpid() ^ int(time.time() * 1000)) & 0xFFFF
        flags_frag = 0
        ttl = 64
        proto = socket.IPPROTO_TCP
        ip_checksum = 0
        ip_src = socket.inet_aton(src_ip)
        ip_dst = socket.inet_aton(dst_ip)
        ip_hdr = struct.pack("!BBHHHBBH4s4s", ver_ihl, tos_b, total_len, ident, flags_frag, ttl, proto, ip_checksum, ip_src, ip_dst)
        ip_checksum = checksum(ip_hdr)
        ip_hdr = struct.pack("!BBHHHBBH4s4s", ver_ihl, tos_b, total_len, ident, flags_frag, ttl, proto, ip_checksum, ip_src, ip_dst)

        src_port = ((ident % 30000) + 20000) & 0xFFFF
        seq = (ident << 16) | (dst_port & 0xFFFF)
        ack = 0
        data_offset = 5
        flags = 0x02
        window = 65535
        csum = 0
        urg = 0
        tcp_hdr = struct.pack("!HHLLBBHHH", src_port, dst_port, seq, ack, data_offset << 4, flags, window, csum, urg)
        csum = _tcp_checksum_v4(src_ip, dst_ip, tcp_hdr)
        tcp_hdr = struct.pack("!HHLLBBHHH", src_port, dst_port, seq, ack, data_offset << 4, flags, window, csum, urg)

        pkt = ip_hdr + tcp_hdr
        send.sendto(pkt, (dst_ip, 0))

        t_end = time.time() + timeout_s
        while time.time() < t_end:
            r, _, _ = select.select([recv], [], [], max(0.0, t_end - time.time()))
            if not r:
                break
            rpkt, _ = recv.recvfrom(4096)
            if len(rpkt) < 40:
                continue
            rip_src = socket.inet_ntoa(rpkt[12:16])
            if rip_src != dst_ip:
                continue
            rsrc_port, rdst_port, _, _, _, rflags, _, _, _ = struct.unpack("!HHLLBBHHH", rpkt[20:40])
            if rdst_port != src_port or rsrc_port != dst_port:
                continue
            if (rflags & 0x12) == 0x12:
                return "open(raw)"
            if (rflags & 0x04) == 0x04:
                return "closed(raw)"
        return "filtered(raw)"
    except Exception:
        return "error(raw)"
    finally:
        try:
            if send:
                send.close()
        except Exception:
            pass
        try:
            if recv:
                recv.close()
        except Exception:
            pass

# -------------------------
# DNS (kept)
# -------------------------
ROOT_HINTS_V4 = [
    "198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13", "192.203.230.10",
    "192.5.5.241", "192.112.36.4", "198.97.190.53", "192.36.148.17", "192.58.128.30",
    "193.0.14.129", "199.7.83.42", "202.12.27.33",
]

DNS_QTYPE = {
    "A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16,
    "AAAA": 28, "SRV": 33, "DS": 43, "RRSIG": 46, "DNSKEY": 48
}

def _dns_encode_name(name: str) -> bytes:
    parts = name.strip(".").split(".") if name.strip(".") else []
    out = b""
    for p in parts:
        b = p.encode("utf-8", "ignore")
        out += struct.pack("!B", len(b)) + b
    return out + b"\x00"

def build_dns_query(name: str, qtype: int, qid: int, rd: bool, do: bool) -> bytes:
    flags = 0x0100 if rd else 0x0000
    hdr = struct.pack("!HHHHHH", qid & 0xFFFF, flags, 1, 0, 0, 1 if do else 0)
    qname = _dns_encode_name(name)
    qclass = 1
    q = hdr + qname + struct.pack("!HH", qtype, qclass)
    if not do:
        return q
    opt = b"\x00" + struct.pack("!H", 41) + struct.pack("!H", 1232) + struct.pack("!BBH", 0, 0, 0x8000) + struct.pack("!H", 0)
    return q + opt

def _dns_read_name(msg: bytes, off: int) -> Tuple[str, int]:
    labels = []
    jumped = False
    start = off
    while True:
        if off >= len(msg):
            return ".", off
        ln = msg[off]
        if ln == 0:
            off += 1
            break
        if (ln & 0xC0) == 0xC0:
            if off + 1 >= len(msg):
                return ".", off + 1
            ptr = ((ln & 0x3F) << 8) | msg[off + 1]
            off += 2
            if not jumped:
                start = off
                jumped = True
            name, _ = _dns_read_name(msg, ptr)
            labels.append(name.strip("."))
            break
        else:
            off += 1
            labels.append(msg[off:off + ln].decode("utf-8", "ignore"))
            off += ln
    full = ".".join([x for x in labels if x])
    return (full + ".") if full else ".", (start if jumped else off)

def _dns_skip_rr(msg: bytes, off: int) -> int:
    _, off = _dns_read_name(msg, off)
    if off + 10 > len(msg):
        return len(msg)
    rdlen = struct.unpack("!H", msg[off + 8:off + 10])[0]
    return off + 10 + rdlen

def _dns_header(msg: bytes) -> Tuple[int, int, int, int, int, int, int]:
    if len(msg) < 12:
        return 0, 0, 0, 0, 0, 0, 0
    (qid, flags, qd, an, ns, ar) = struct.unpack("!HHHHHH", msg[:12])
    rcode = flags & 0x000F
    return qid, flags, qd, an, ns, ar, rcode

def _dns_parse_sections(msg: bytes) -> Dict[str, List[str]]:
    out = {"answer": [], "authority": [], "additional": []}
    _, _, qd, an, ns, ar, _ = _dns_header(msg)
    off = 12

    for _ in range(qd):
        _, off = _dns_read_name(msg, off)
        off += 4

    def parse_rr(count: int, bucket: str, off0: int) -> int:
        off = off0
        for _ in range(count):
            name, off2 = _dns_read_name(msg, off)
            if off2 + 10 > len(msg):
                return len(msg)
            rtype, rclass, ttl = struct.unpack("!HHI", msg[off2:off2 + 8])
            rdlen = struct.unpack("!H", msg[off2 + 8:off2 + 10])[0]
            rdata_off = off2 + 10
            rdata = msg[rdata_off:rdata_off + rdlen]
            tname = next((k for k, v in DNS_QTYPE.items() if v == rtype), str(rtype))

            rdata_txt = ""
            try:
                if rtype == 1 and rdlen == 4:
                    rdata_txt = socket.inet_ntoa(rdata)
                elif rtype == 28 and rdlen == 16:
                    rdata_txt = socket.inet_ntop(socket.AF_INET6, rdata)
                elif rtype in (2, 5):
                    rdata_txt, _ = _dns_read_name(msg, rdata_off)
                elif rtype == 6:
                    mname, p1 = _dns_read_name(msg, rdata_off)
                    rname, p2 = _dns_read_name(msg, p1)
                    if p2 + 20 <= len(msg):
                        serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", msg[p2:p2 + 20])
                        rdata_txt = f"mname={mname} rname={rname} serial={serial}"
                    else:
                        rdata_txt = f"mname={mname} rname={rname}"
                elif rtype == 15:
                    pref = struct.unpack("!H", rdata[:2])[0] if rdlen >= 2 else 0
                    exch, _ = _dns_read_name(msg, rdata_off + 2)
                    rdata_txt = f"{pref} {exch}"
                elif rtype == 16:
                    if rdlen >= 1:
                        ln = rdata[0]
                        rdata_txt = rdata[1:1 + ln].decode("utf-8", "ignore")
                    else:
                        rdata_txt = ""
                elif rtype == 48:
                    rdata_txt = f"DNSKEY len={rdlen}"
                elif rtype == 46:
                    rdata_txt = f"RRSIG len={rdlen}"
                elif rtype == 43:
                    rdata_txt = f"DS len={rdlen}"
                else:
                    rdata_txt = f"len={rdlen}"
            except Exception:
                rdata_txt = f"len={rdlen}"

            out[bucket].append(f"{name} {ttl} {tname} {rdata_txt}")
            off = off2 + 10 + rdlen
        return off

    off = parse_rr(an, "answer", off)
    off = parse_rr(ns, "authority", off)
    off = parse_rr(ar, "additional", off)
    return out

def _dns_parse_referral(msg: bytes) -> Tuple[List[str], List[str], bool]:
    _, _, qd, an, ns, ar, _ = _dns_header(msg)
    off = 12
    for _ in range(qd):
        _, off = _dns_read_name(msg, off)
        off += 4

    has_answer = (an > 0)
    for _ in range(an):
        off = _dns_skip_rr(msg, off)

    ns_names: List[str] = []
    for _ in range(ns):
        _, off2 = _dns_read_name(msg, off)
        if off2 + 10 > len(msg):
            break
        rtype = struct.unpack("!H", msg[off2:off2 + 2])[0]
        rdlen = struct.unpack("!H", msg[off2 + 8:off2 + 10])[0]
        rdata_off = off2 + 10
        if rtype == 2:
            nsname, _ = _dns_read_name(msg, rdata_off)
            ns_names.append(nsname)
        off = off2 + 10 + rdlen

    glue_ips: List[str] = []
    for _ in range(ar):
        _, off2 = _dns_read_name(msg, off)
        if off2 + 10 > len(msg):
            break
        rtype = struct.unpack("!H", msg[off2:off2 + 2])[0]
        rdlen = struct.unpack("!H", msg[off2 + 8:off2 + 10])[0]
        rdata = msg[off2 + 10:off2 + 10 + rdlen]
        if rtype == 1 and rdlen == 4:
            glue_ips.append(socket.inet_ntoa(rdata))
        elif rtype == 28 and rdlen == 16:
            glue_ips.append(socket.inet_ntop(socket.AF_INET6, rdata))
        off = off2 + 10 + rdlen

    def uniq(xs):
        s = set()
        out = []
        for x in xs:
            if x not in s:
                s.add(x)
                out.append(x)
        return out

    return uniq(ns_names), uniq(glue_ips), has_answer

def _dns_udp_query(server_ip: str, qname: str, qtype: int, timeout_s: float, rd: bool, do: bool) -> Tuple[bool, float, bytes]:
    qid = (os.getpid() ^ int(time.time() * 1000)) & 0xFFFF
    pkt = build_dns_query(qname, qtype, qid, rd=rd, do=do)
    t0 = time.time()
    try:
        fam = socket.AF_INET6 if ":" in server_ip else socket.AF_INET
        s = socket.socket(fam, socket.SOCK_DGRAM)
        s.settimeout(timeout_s)
        if fam == socket.AF_INET6:
            s.sendto(pkt, (server_ip, 53, 0, 0))
        else:
            s.sendto(pkt, (server_ip, 53))
        data, _ = s.recvfrom(8192)
        s.close()
        if len(data) >= 2 and struct.unpack("!H", data[:2])[0] == (qid & 0xFFFF):
            return True, (time.time() - t0) * 1000.0, data
        return False, 0.0, b""
    except Exception:
        return False, 0.0, b""

def dns_iterative_trace_one_per_level(qname: str, want_aaaa: bool = False) -> Tuple[List[Tuple[str, str, float]], Optional[str]]:
    qtype = 28 if want_aaaa else 1
    levels: List[Tuple[str, str, float]] = []
    candidates = list(ROOT_HINTS_V4)
    level_label = "Root"
    last_ip: Optional[str] = None

    for depth in range(0, 12):
        chosen_ip = None
        chosen_rtt = 0.0
        chosen_msg = b""

        for ip in candidates:
            ok, rtt, msg = _dns_udp_query(ip, qname, qtype, timeout_s=0.9, rd=False, do=False)
            if ok:
                chosen_ip = ip
                chosen_rtt = rtt
                chosen_msg = msg
                break

        if chosen_ip is None:
            levels.append((level_label, "(no response)", 0.0))
            return levels, last_ip

        levels.append((level_label, chosen_ip, chosen_rtt))
        last_ip = chosen_ip

        ns_names, glue_ips, has_answer = _dns_parse_referral(chosen_msg)
        if has_answer:
            return levels, last_ip

        if glue_ips:
            candidates = glue_ips
        else:
            resolved = []
            for ns in ns_names[:8]:
                try:
                    infos = socket.getaddrinfo(ns.strip("."), 53)
                    for fam, _, _, _, sa in infos:
                        resolved.append(sa[0])
                except Exception:
                    pass
            if not resolved:
                levels.append(("NS", "(no glue/resolve)", 0.0))
                return levels, last_ip
            candidates = resolved

        parts = qname.strip(".").split(".")
        if len(parts) >= 2:
            if depth == 0:
                level_label = f"TLD (.{parts[-1]})"
            elif depth == 1 and len(parts) >= 2:
                level_label = f"Zone ({parts[-2]}.{parts[-1]})"
            else:
                level_label = "Auth"
        else:
            level_label = "Auth"

    return levels, last_ip

def dns_query(server_ip: str, qname: str, qtype_name: str, rd: bool = True, do: bool = False) -> Tuple[bool, str, Dict[str, List[str]]]:
    qt = DNS_QTYPE.get(qtype_name.upper(), 1)
    ok, _, msg = _dns_udp_query(server_ip, qname, qt, timeout_s=1.2, rd=rd, do=do)
    if not ok:
        return False, "no-response", {"answer": [], "authority": [], "additional": []}
    _, _, _, an, _, _, rcode = _dns_header(msg)
    st = "ok"
    if rcode == 3:
        st = "NXDOMAIN"
    elif rcode != 0:
        st = f"RCODE={rcode}"
    elif an == 0:
        st = "NODATA"
    return True, st, _dns_parse_sections(msg)

def dns_authoritative_info(qname: str) -> List[str]:
    lines: List[str] = []
    path, auth_ip = dns_iterative_trace_one_per_level(qname, want_aaaa=False)
    if not auth_ip or auth_ip.startswith("("):
        lines.append("authoritative: unknown (trace failed)")
        return lines
    lines.append(f"authoritative-server: {auth_ip}")

    ok, st, sec = dns_query(auth_ip, qname, "NS", rd=False, do=False)
    ns_list = [l for l in sec["answer"] if " NS " in l]
    lines.append(f"NS status: {st}")
    for l in ns_list[:12]:
        lines.append("  " + l)

    ok, st, sec = dns_query(auth_ip, qname, "SOA", rd=False, do=False)
    soa_list = [l for l in sec["answer"] if " SOA " in l]
    primary = None
    if soa_list:
        lines.append(f"SOA status: {st}")
        lines.append("  " + soa_list[0])
        m = re.search(r"mname=([^\s]+)", soa_list[0])
        if m:
            primary = m.group(1)
    else:
        lines.append(f"SOA status: {st} (no SOA in answer)")

    if ns_list:
        ns_hosts = []
        for l in ns_list:
            m = re.search(r"\sNS\s(.+)$", l)
            if m:
                ns_hosts.append(m.group(1).strip())
        ns_hosts = list(dict.fromkeys(ns_hosts))
        if primary:
            secondaries = [x for x in ns_hosts if x != primary]
            lines.append(f"Primary (SOA mname): {primary}")
            lines.append(f"Secondaries (NS != primary): {', '.join(secondaries) if secondaries else '(none)'}")
            lines.append("has-secondaries: " + ("YES" if len(secondaries) > 0 else "no"))
        else:
            lines.append("has-secondaries: " + ("YES" if len(ns_hosts) > 1 else "no"))

    ok, st, sec = dns_query(auth_ip, qname, "DNSKEY", rd=False, do=True)
    dnskey = [l for l in sec["answer"] if " DNSKEY " in l]
    rrsig = [l for l in sec["answer"] if " RRSIG " in l]
    dnssec = "YES" if (len(dnskey) > 0 and len(rrsig) > 0) else "no"
    lines.append(f"DNSSEC: {dnssec} (DNSKEY={len(dnskey)} RRSIG={len(rrsig)} status={st})")
    return lines

# -------------------------
# Colors
# -------------------------
def init_colors():
    curses.start_color()
    try:
        curses.use_default_colors()
    except Exception:
        pass
    curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)  # base
    curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)    # flap

def attr_base():
    return curses.color_pair(1)

def attr_selected():
    return curses.color_pair(1) | curses.A_REVERSE

def attr_dim():
    return curses.color_pair(1) | curses.A_DIM

def attr_bold():
    return curses.color_pair(1) | curses.A_BOLD

def attr_flap():
    return curses.color_pair(2) | curses.A_BOLD

# -------------------------
# Popups / modal inputs (OPAQUE)
# -------------------------
def popup_list(stdscr, title: str, lines: List[str]):
    maxy, maxx = stdscr.getmaxyx()
    h = min(maxy - 4, max(10, min(30, len(lines) + 4)))
    w = min(maxx - 4, 120)
    y0 = (maxy - h) // 2
    x0 = (maxx - w) // 2
    stdscr.nodelay(False)
    while True:
        fill_rect(stdscr, y0, x0, h, w, attr_base())
        draw_border_box(stdscr, y0, x0, h, w, attr_base())
        stdscr.addnstr(y0, x0 + 2, f" {title} ", w - 4, curses.A_BOLD | attr_base())
        view = lines[: h - 4]
        for i, ln in enumerate(view):
            stdscr.addnstr(y0 + 2 + i, x0 + 2, ln, w - 4, attr_base())
        stdscr.addnstr(y0 + h - 2, x0 + 2, "Esc/Enter to close", w - 4, curses.A_DIM | attr_base())
        stdscr.refresh()
        ch = stdscr.getch()
        if ch in (27, 10, 13):
            break
    stdscr.nodelay(True)

def prompt_modal(stdscr, title: str, prompt: str, initial: str) -> Optional[str]:
    maxy, maxx = stdscr.getmaxyx()
    h, w = 7, min(90, maxx - 4)
    y0 = (maxy - h) // 2
    x0 = (maxx - w) // 2

    buf = list(initial)
    pos = len(buf)
    stdscr.nodelay(False)
    while True:
        fill_rect(stdscr, y0, x0, h, w, attr_base())
        draw_border_box(stdscr, y0, x0, h, w, attr_base())
        stdscr.addnstr(y0, x0 + 2, f" {title} ", w - 4, curses.A_BOLD | attr_base())
        stdscr.addnstr(y0 + 2, x0 + 2, prompt, w - 4, attr_base())
        stdscr.addnstr(y0 + 3, x0 + 2, "".join(buf).ljust(w - 4), w - 4, attr_base())
        stdscr.addnstr(y0 + 5, x0 + 2, "Enter=OK  Esc=Cancel", w - 4, curses.A_DIM | attr_base())
        stdscr.move(y0 + 3, x0 + 2 + pos)
        stdscr.refresh()

        ch = stdscr.getch()
        if ch == 27:
            stdscr.nodelay(True)
            return None
        if ch in (10, 13):
            stdscr.nodelay(True)
            return "".join(buf).strip()
        if ch == curses.KEY_LEFT:
            pos = max(0, pos - 1)
        elif ch == curses.KEY_RIGHT:
            pos = min(len(buf), pos + 1)
        elif ch in (curses.KEY_BACKSPACE, 127, 8):
            if pos > 0:
                buf.pop(pos - 1)
                pos -= 1
        elif 32 <= ch <= 126:
            buf.insert(pos, chr(ch))
            pos += 1

def parse_ports(s: str) -> List[int]:
    s = s.strip()
    if not s:
        return []
    out: List[int] = []
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            a = int(a); b = int(b)
            for p in range(min(a, b), max(a, b) + 1):
                if 1 <= p <= 65535:
                    out.append(p)
        else:
            p = int(part)
            if 1 <= p <= 65535:
                out.append(p)
    seen = set()
    uniq = []
    for p in out:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq

# -------------------------
# Config + model
# -------------------------
@dataclass
class PingStats:
    sent: int = 0
    lost: int = 0
    ttl_best: Optional[int] = None
    ttl_worst: Optional[int] = None
    rtt_last_ms: Optional[float] = None

    @property
    def loss_pct(self) -> float:
        return 0.0 if self.sent == 0 else (self.lost * 100.0 / self.sent)

@dataclass
class Hop:
    idx: int
    ip: str
    host: str = ""
    asn: str = "?"
    org: str = ""
    flap: bool = False

    mpls: str = ""
    rir: str = "?"
    owner: str = ""
    email: str = ""
    ip_range: str = ""

    stats: PingStats = field(default_factory=PingStats)
    ports: Dict[str, Dict[int, str]] = field(default_factory=lambda: {"tcp": {}, "udp": {}, "raw": {}, "sctp": {}})

@dataclass
class PortConfig:
    mode: str = "tcp"
    ports: List[int] = field(default_factory=lambda: [22, 80, 443, 53])

@dataclass
class TraceConfig:
    method: str = "pyudp"
    max_hops: int = 30
    timeout_s: float = 0.6
    port: int = 33434  # base port for pyudp/traceroute-udp/tcp selection

@dataclass
class PingConfig:
    mode: str = "icmp"
    port: int = 443
    timeout_s: float = 1.0

@dataclass
class NetConfig:
    family: str = "auto"
    tos: int = 0

# -------------------------
# Menus helpers
# -------------------------
def cycle_port_mode(cur: str) -> str:
    order = ["tcp", "udp", "raw", "sctp"]
    try:
        i = order.index(cur)
    except ValueError:
        i = 0
    return order[(i + 1) % len(order)]

def cycle_ping_mode(cur: str) -> str:
    order = ["icmp", "tcp", "udp"]
    try:
        i = order.index(cur)
    except ValueError:
        i = 0
    return order[(i + 1) % len(order)]

def cycle_trace_method(cur: str) -> str:
    order = ["off", "pyudp", "pyicmp", "tracepath", "traceroute", "traceroute-udp", "traceroute-tcp", "mtr-sctp", "raw6"]
    try:
        i = order.index(cur)
    except ValueError:
        i = 0
    return order[(i + 1) % len(order)]

def ports_menu(stdscr, port_cfg: PortConfig) -> Optional[PortConfig]:
    maxy, maxx = stdscr.getmaxyx()
    h, w = 10, min(86, maxx - 4)
    y0 = (maxy - h) // 2
    x0 = (maxx - w) // 2

    tmp = PortConfig(mode=port_cfg.mode, ports=list(port_cfg.ports))
    ports_str = ",".join(str(p) for p in tmp.ports)

    stdscr.nodelay(False)
    while True:
        fill_rect(stdscr, y0, x0, h, w, attr_base())
        draw_border_box(stdscr, y0, x0, h, w, attr_base())
        stdscr.addnstr(y0, x0 + 2, " PORTS MENU ", w - 4, curses.A_BOLD | attr_base())
        stdscr.addnstr(y0 + 2, x0 + 2, f"Mode: {tmp.mode}   (M cycle tcp/udp/raw/sctp)", w - 4, attr_base())
        stdscr.addnstr(y0 + 3, x0 + 2, f"Ports: {ports_str}", w - 4, attr_base())
        stdscr.addnstr(y0 + 5, x0 + 2, "E edit ports (22,80,443 or 20-25)", w - 4, curses.A_DIM | attr_base())
        stdscr.addnstr(y0 + 7, x0 + 2, "Enter=Apply  Esc=Cancel", w - 4, curses.A_DIM | attr_base())
        stdscr.refresh()

        ch = stdscr.getch()
        if ch == 27:
            stdscr.nodelay(True)
            return None
        if ch in (10, 13):
            tmp.ports = parse_ports(ports_str) or tmp.ports
            stdscr.nodelay(True)
            return tmp
        if ch in (ord('m'), ord('M')):
            tmp.mode = cycle_port_mode(tmp.mode)
        if ch in (ord('e'), ord('E')):
            s = prompt_modal(stdscr, "Edit Ports", "Ports:", ports_str)
            if s is not None:
                ports_str = s

def tos_menu(stdscr, current: int) -> Optional[int]:
    s = prompt_modal(stdscr, "TOS / Traffic Class", "Value 0-255:", str(current))
    if s is None:
        return None
    try:
        v = int(s)
        if 0 <= v <= 255:
            return v
    except Exception:
        pass
    return None

def ping_menu(stdscr, ping_cfg: PingConfig) -> Optional[PingConfig]:
    maxy, maxx = stdscr.getmaxyx()
    h, w = 10, min(86, maxx - 4)
    y0 = (maxy - h) // 2
    x0 = (maxx - w) // 2
    tmp = PingConfig(mode=ping_cfg.mode, port=ping_cfg.port, timeout_s=ping_cfg.timeout_s)

    stdscr.nodelay(False)
    while True:
        fill_rect(stdscr, y0, x0, h, w, attr_base())
        draw_border_box(stdscr, y0, x0, h, w, attr_base())
        stdscr.addnstr(y0, x0 + 2, " PING MENU ", w - 4, curses.A_BOLD | attr_base())
        stdscr.addnstr(y0 + 2, x0 + 2, f"Mode: {tmp.mode}   (P cycle icmp/tcp/udp)", w - 4, attr_base())
        stdscr.addnstr(y0 + 3, x0 + 2, f"Port: {tmp.port}   (only for tcp/udp)", w - 4, attr_base())
        stdscr.addnstr(y0 + 4, x0 + 2, f"Timeout(s): {tmp.timeout_s:.1f}", w - 4, attr_base())
        stdscr.addnstr(y0 + 6, x0 + 2, "E edit port  S edit timeout", w - 4, curses.A_DIM | attr_base())
        stdscr.addnstr(y0 + 7, x0 + 2, "Enter=Apply  Esc=Cancel", w - 4, curses.A_DIM | attr_base())
        stdscr.refresh()
        ch = stdscr.getch()
        if ch == 27:
            stdscr.nodelay(True)
            return None
        if ch in (10, 13):
            stdscr.nodelay(True)
            return tmp
        if ch in (ord('p'), ord('P')):
            tmp.mode = cycle_ping_mode(tmp.mode)
        if ch in (ord('e'), ord('E')):
            s = prompt_modal(stdscr, "Edit Port", "Port 1-65535:", str(tmp.port))
            if s is not None:
                try:
                    v = int(s)
                    if 1 <= v <= 65535:
                        tmp.port = v
                except Exception:
                    pass
        if ch in (ord('s'), ord('S')):
            s = prompt_modal(stdscr, "Edit Timeout", "Seconds (e.g. 1.0):", str(tmp.timeout_s))
            if s is not None:
                try:
                    v = float(s)
                    if 0.1 <= v <= 10.0:
                        tmp.timeout_s = v
                except Exception:
                    pass

def dns_query_menu(stdscr) -> Optional[Tuple[str, str, str]]:
    ip = prompt_modal(stdscr, "DNS Query", "DNS server IP:", "8.8.8.8")
    if ip is None:
        return None
    name = prompt_modal(stdscr, "DNS Query", "Name (domain):", "")
    if name is None or not name:
        return None
    qt = prompt_modal(stdscr, "DNS Query", "Type (A/AAAA/NS/SOA/MX/TXT/CNAME/DNSKEY):", "A")
    if qt is None or not qt:
        return None
    return ip.strip(), name.strip(), qt.strip().upper()

def trace_port_menu(stdscr, cur_port: int) -> Optional[int]:
    s = prompt_modal(stdscr, "Trace probe base port", "Port (1-65535):", str(cur_port))
    if s is None:
        return None
    try:
        v = int(s)
        if 1 <= v <= 65535:
            return v
    except Exception:
        pass
    return None

def web_probe_menu(stdscr) -> Optional[Tuple[str, str]]:
    """
    Returns (tool, base_url) where base_url like https://example.com or http://1.2.3.4:8080
    """
    tool = prompt_modal(stdscr, "Web Probe", "Tool (curl/wget):", "curl")
    if tool is None:
        return None
    tool = tool.strip().lower()
    if tool not in ("curl", "wget"):
        tool = "curl"
    url = prompt_modal(stdscr, "Web Probe", "Base URL (e.g. https://example.com):", "")
    if url is None or not url.strip():
        return None
    return tool, url.strip()

def main_menu(stdscr, trace_cfg: TraceConfig, port_cfg: PortConfig, ping_cfg: PingConfig) -> Optional[Tuple[TraceConfig, PortConfig, PingConfig, str]]:
    maxy, maxx = stdscr.getmaxyx()
    h, w = 18, min(98, maxx - 4)
    y0 = (maxy - h) // 2
    x0 = (maxx - w) // 2

    ttmp = TraceConfig(method=trace_cfg.method, max_hops=trace_cfg.max_hops, timeout_s=trace_cfg.timeout_s, port=trace_cfg.port)
    ptmp = PortConfig(mode=port_cfg.mode, ports=list(port_cfg.ports))
    gtmp = PingConfig(mode=ping_cfg.mode, port=ping_cfg.port, timeout_s=ping_cfg.timeout_s)

    sel = 0
    items = [
        "Trace method",
        "Trace port (base)",
        "Ping mode/port",
        "Ports config",
        "DNS trace popup",
        "DNS auth info popup",
        "DNS query popup",
        "Web server probe (curl/wget)",
    ]

    stdscr.nodelay(False)
    while True:
        fill_rect(stdscr, y0, x0, h, w, attr_base())
        draw_border_box(stdscr, y0, x0, h, w, attr_base())
        stdscr.addnstr(y0, x0 + 2, " MENU ", w - 4, curses.A_BOLD | attr_base())

        for i, it in enumerate(items):
            mark = ">" if i == sel else " "
            if it == "Trace method":
                line = f"{mark} 1) {it}: {ttmp.method}"
            elif it == "Trace port (base)":
                line = f"{mark} 2) {it}: {ttmp.port}"
            elif it == "Ping mode/port":
                line = f"{mark} 3) {it}: {gtmp.mode} port={gtmp.port} to={gtmp.timeout_s:.1f}s"
            elif it == "Ports config":
                line = f"{mark} 4) {it}: {ptmp.mode} [{','.join(str(p) for p in ptmp.ports)}]"
            elif it == "DNS trace popup":
                line = f"{mark} 5) {it}"
            elif it == "DNS auth info popup":
                line = f"{mark} 6) {it}"
            elif it == "DNS query popup":
                line = f"{mark} 7) {it}"
            else:
                line = f"{mark} 8) {it}"
            stdscr.addnstr(y0 + 2 + i, x0 + 2, line.ljust(w - 4), w - 4, attr_base())

        stdscr.addnstr(y0 + h - 3, x0 + 2, "Keys: ↑/↓ select  Enter  T cycle-trace  Esc cancel", w - 4, curses.A_DIM | attr_base())
        stdscr.refresh()

        ch = stdscr.getch()
        if ch == 27:
            stdscr.nodelay(True)
            return None
        if ch in (curses.KEY_UP, ord('k')):
            sel = max(0, sel - 1)
        elif ch in (curses.KEY_DOWN, ord('j')):
            sel = min(len(items) - 1, sel + 1)
        elif ch in (ord('t'), ord('T')):
            ttmp.method = cycle_trace_method(ttmp.method)
        elif ch in (10, 13):
            if sel == 0:
                stdscr.nodelay(True)
                return ttmp, ptmp, gtmp, ""
            if sel == 1:
                v = trace_port_menu(stdscr, ttmp.port)
                if v is not None:
                    ttmp.port = v
            if sel == 2:
                sub = ping_menu(stdscr, gtmp)
                if sub is not None:
                    gtmp = sub
            if sel == 3:
                sub = ports_menu(stdscr, ptmp)
                if sub is not None:
                    ptmp = sub
            if sel == 4:
                stdscr.nodelay(True)
                return ttmp, ptmp, gtmp, "dns_trace"
            if sel == 5:
                stdscr.nodelay(True)
                return ttmp, ptmp, gtmp, "dns_info"
            if sel == 6:
                stdscr.nodelay(True)
                return ttmp, ptmp, gtmp, "dns_query"
            if sel == 7:
                stdscr.nodelay(True)
                return ttmp, ptmp, gtmp, "web_probe"

# -------------------------
# PDF report (current screen state)
# -------------------------
def safe_pdf_name(name: str) -> str:
    name = name.strip()
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name)
    if not name.lower().endswith(".pdf"):
        name += ".pdf"
    return name

def gen_pdf_report(filename: str, target: str, dest_v4: str, dest_v6: str, use_ip: str,
                   trace_method: str, trace_port: int, ping_enabled: bool, ping_mode: str, ping_port: int, tos: int,
                   hops: List[Hop], selected_idx: int, dest_ports: Dict[str, Dict[int, str]], port_cfg: PortConfig) -> Tuple[bool, str]:
    if not REPORTLAB_OK:
        return False, "reportlab not installed (python3-reportlab)"

    try:
        fn = safe_pdf_name(filename)
        c = rl_canvas.Canvas(fn, pagesize=A4)
        w, h = A4

        y = h - 40
        c.setFont("Helvetica-Bold", 14)
        c.drawString(40, y, "netdiag report (current screen)")
        y -= 18

        c.setFont("Helvetica", 10)
        c.drawString(40, y, f"Target: {target}   v4={dest_v4 or '-'}   v6={dest_v6 or '-'}   use={use_ip}")
        y -= 14
        c.drawString(40, y, f"Trace: {trace_method}  base-port={trace_port}   Ping: {'on' if ping_enabled else 'off'}  ({ping_mode}:{ping_port})   TOS={tos}")
        y -= 18

        c.setFont("Helvetica-Bold", 11)
        c.drawString(40, y, "Hops (visible state)")
        y -= 12

        c.setFont("Helvetica", 8)
        header = "idx  ip/host                     ASN      RIR     MPLS  loss% sent ttlB ttlW owner/email(range)"
        c.drawString(40, y, header)
        y -= 10

        for i, hop in enumerate(hops[:120]):
            host = hop.host or hop.ip
            host = (host[:26] + "…") if len(host) > 27 else host
            loss = f"{hop.stats.loss_pct:5.1f}"
            sent = str(hop.stats.sent)
            tb = "-" if hop.stats.ttl_best is None else str(hop.stats.ttl_best)
            tw = "-" if hop.stats.ttl_worst is None else str(hop.stats.ttl_worst)
            mpls = "Y" if hop.mpls else "-"
            owner = hop.owner or "-"
            email = hop.email or "-"
            rng = hop.ip_range or "-"
            tail = f"{owner} / {email} ({rng})"
            if len(tail) > 55:
                tail = tail[:54] + "…"
            line = f"{hop.idx:>3}  {host:<27}  AS{hop.asn:<6}  {hop.rir:<6}  {mpls:<4}  {loss:>5}  {sent:<4} {tb:<4} {tw:<4} {tail}"
            if i == selected_idx:
                c.setFont("Helvetica-Bold", 8)
                c.drawString(40, y, ">> " + line)
                c.setFont("Helvetica", 8)
            else:
                c.drawString(40, y, "   " + line)
            y -= 9
            if y < 90:
                c.showPage()
                y = h - 40
                c.setFont("Helvetica", 8)

        c.showPage()
        y = h - 40
        c.setFont("Helvetica-Bold", 11)
        c.drawString(40, y, "Destination ports (current mode)")
        y -= 14
        c.setFont("Helvetica", 10)
        c.drawString(40, y, f"Mode: {port_cfg.mode}   Ports: {','.join(str(p) for p in port_cfg.ports)}")
        y -= 14
        c.setFont("Helvetica", 9)
        dmap = dest_ports.get(port_cfg.mode, {}) if dest_ports else {}
        if not dmap:
            c.drawString(40, y, "(no dest scan data)")
            y -= 12
        else:
            for p in port_cfg.ports:
                if y < 60:
                    c.showPage()
                    y = h - 40
                    c.setFont("Helvetica", 9)
                st = dmap.get(p, "-")
                c.drawString(40, y, f"{p:>5}/{port_cfg.mode:<4} {st}")
                y -= 12

        c.save()
        return True, fn
    except Exception as e:
        return False, str(e)

# -------------------------
# Web server probe (curl/wget) to non-existing endpoint
# -------------------------
def build_nonexist_url(base_url: str) -> str:
    base = base_url.strip()
    if not (base.startswith("http://") or base.startswith("https://")):
        base = "http://" + base
    base = base.rstrip("/")
    token = f"__netdiag_probe__{int(time.time())}_{os.getpid()}"
    return base + "/" + token

def web_probe(tool: str, base_url: str, timeout_s: float = 3.0) -> Tuple[str, List[str]]:
    url = build_nonexist_url(base_url)
    lines: List[str] = []
    lines.append(f"URL: {url}")
    lines.append("")

    if tool == "wget":
        if not which(WGET_BIN):
            return "web probe", ["wget not found"]
        # wget prints headers with -S; use --spider for no body
        cmd = [WGET_BIN, "-S", "--spider", "-T", str(int(timeout_s)), url]
        rc, out = run_cmd(cmd, timeout_s=timeout_s + 2.0)
        lines.append(f"cmd: {' '.join(cmd)}")
        lines.append(f"rc: {rc}")
        lines.append("")
        for ln in out.splitlines()[:220]:
            lines.append(ln)
        return "web probe (wget)", lines

    # default curl
    if not which(CURL_BIN):
        return "web probe", ["curl not found"]
    # HEAD + headers only
    cmd = [CURL_BIN, "-I", "-sS", "--max-time", f"{timeout_s:.1f}", "-L", url]
    rc, out = run_cmd(cmd, timeout_s=timeout_s + 2.0)
    lines.append(f"cmd: {' '.join(cmd)}")
    lines.append(f"rc: {rc}")
    lines.append("")
    for ln in out.splitlines()[:220]:
        lines.append(ln)
    return "web probe (curl)", lines

# -------------------------
# Engine (async)
# -------------------------
class Engine:
    def __init__(self, target: str, trace_cfg: TraceConfig, port_cfg: PortConfig, ping_cfg: PingConfig, net_cfg: NetConfig, ping_enabled: bool):
        self.target = target
        self.trace_cfg = trace_cfg
        self.port_cfg = port_cfg
        self.ping_cfg = ping_cfg
        self.net_cfg = net_cfg
        self.ping_enabled = ping_enabled

        self.dest_v4, self.dest_v6 = self._resolve_dualstack(target)
        self.dest_family, self.dest_ip = self._pick_dest()

        self.hops: List[Hop] = []
        self.selected = 0

        self.dest_ports: Dict[str, Dict[int, str]] = {"tcp": {}, "udp": {}, "raw": {}, "sctp": {}}

        self._q: "queue.Queue[tuple]" = queue.Queue()
        self._stop = threading.Event()
        self._trace_inflight = threading.Event()

        self._ping_ident = os.getpid() & 0xFFFF
        self._ping_seq = 0

        self._last_asn_by_idx: Dict[int, str] = {}
        self.last_dns_path: List[Tuple[str, str, float]] = []
        self.last_dns_auth_ip: Optional[str] = None

        self._rdap_cache: Dict[str, Tuple[str, str, str, str]] = {}

    def _resolve_dualstack(self, target: str) -> Tuple[Optional[str], Optional[str]]:
        v4 = None
        v6 = None
        try:
            infos = socket.getaddrinfo(target, None)
            for fam, _, _, _, sa in infos:
                if fam == socket.AF_INET and v4 is None:
                    v4 = sa[0]
                if fam == socket.AF_INET6 and v6 is None:
                    v6 = sa[0]
        except Exception:
            pass
        return v4, v6

    def _pick_dest(self) -> Tuple[int, str]:
        if self.net_cfg.family == "v6" and self.dest_v6:
            return socket.AF_INET6, self.dest_v6
        if self.net_cfg.family == "v4" and self.dest_v4:
            return socket.AF_INET, self.dest_v4
        if self.dest_v4:
            return socket.AF_INET, self.dest_v4
        if self.dest_v6:
            return socket.AF_INET6, self.dest_v6
        return socket.AF_INET, self.target

    def set_family(self, fam: str):
        self.net_cfg.family = fam
        self.dest_family, self.dest_ip = self._pick_dest()

    def stop(self):
        self._stop.set()

    def enqueue(self, ev: tuple):
        try:
            self._q.put_nowait(ev)
        except Exception:
            pass

    def poll_events(self, max_n: int = 900) -> List[tuple]:
        evs = []
        for _ in range(max_n):
            try:
                evs.append(self._q.get_nowait())
            except queue.Empty:
                break
        return evs

    def request_trace(self, force: bool = False):
        if self.trace_cfg.method == "off":
            self.hops = []
            self.selected = 0
            self.enqueue(("status", "trace off"))
            return
        if self._trace_inflight.is_set() and not force:
            return
        self._trace_inflight.set()
        threading.Thread(target=self._trace_worker, daemon=True).start()

    def _trace_worker(self):
        self.enqueue(("status", f"tracing ({self.trace_cfg.method})..."))
        ips: List[str] = []
        mpls_map: Dict[str, str] = {}
        status = "n/a"
        try:
            m = self.trace_cfg.method
            if m == "pyudp":
                ips, mpls_map, status = pytrace_udp(
                    (self.dest_family, self.dest_ip),
                    self.trace_cfg.max_hops,
                    self.trace_cfg.timeout_s,
                    self.net_cfg.tos,
                    base_port=self.trace_cfg.port
                )
            elif m == "pyicmp":
                if self.dest_family != socket.AF_INET:
                    ips, mpls_map, status = [], {}, "pyicmp only ipv4"
                else:
                    ips, mpls_map, status = pytrace_icmp_v4(self.dest_ip, self.trace_cfg.max_hops, self.trace_cfg.timeout_s, self.net_cfg.tos)
            elif m == "tracepath":
                if which(TRACEPATH_BIN):
                    rc, out = run_cmd([TRACEPATH_BIN, "-n", "-m", str(self.trace_cfg.max_hops), self.target], timeout_s=6.0)
                    ips, mpls_map = parse_tracepath(out)
                    status = "ok" if ips else f"tracepath rc={rc}"
                else:
                    status = "tracepath missing"
            elif m == "traceroute":
                if which(TRACEROUTE_BIN):
                    rc, out = run_cmd([TRACEROUTE_BIN, "-e", "-n", "-q", "1", "-w", "1", "-N", "1", "-m", str(self.trace_cfg.max_hops), self.target], timeout_s=7.5)
                    ips, mpls_map = parse_traceroute(out)
                    status = "ok" if ips else f"traceroute rc={rc}"
                else:
                    status = "traceroute missing"
            elif m == "traceroute-udp":
                if which(TRACEROUTE_BIN):
                    rc, out = run_cmd([TRACEROUTE_BIN, "-e", "-n", "-U", "-p", str(self.trace_cfg.port), "-q", "1", "-w", "1", "-N", "1", "-m", str(self.trace_cfg.max_hops), self.target], timeout_s=9.0)
                    ips, mpls_map = parse_traceroute(out)
                    status = "ok" if ips else f"tr-udp rc={rc}"
                else:
                    status = "traceroute missing"
            elif m == "traceroute-tcp":
                if which(TRACEROUTE_BIN):
                    rc, out = run_cmd([TRACEROUTE_BIN, "-e", "-n", "-T", "-p", str(self.trace_cfg.port), "-q", "1", "-w", "1", "-N", "1", "-m", str(self.trace_cfg.max_hops), self.target], timeout_s=9.0)
                    ips, mpls_map = parse_traceroute(out)
                    status = "ok" if ips else f"tr-tcp rc={rc}"
                else:
                    status = "traceroute missing"
            elif m == "mtr-sctp":
                ips, mpls_map, status = [], {}, "mtr-sctp: not implemented (yet)"
            elif m == "raw6":
                ips, mpls_map, status = [], {}, "raw ipv6: not implemented (yet)"
            else:
                status = "bad method"
        except Exception:
            ips, mpls_map, status = [], {}, "trace error"

        self.enqueue(("trace_done", ips, mpls_map, status))

        for ip in ips:
            if self._stop.is_set():
                break
            host = ""
            try:
                host = socket.gethostbyaddr(ip)[0]
            except Exception:
                host = ""
            asn, org = ("?", "")
            if ip != "*" and ip:
                asn, org = asn_lookup_whois(ip)
            self.enqueue(("hop_meta", ip, host, asn, org))

            if ip in mpls_map:
                self.enqueue(("hop_mpls", ip, mpls_map[ip]))

            if ip != "*" and ip:
                threading.Thread(target=self._rdap_worker_one, args=(ip,), daemon=True).start()

        self._trace_inflight.clear()
        self.enqueue(("status", f"trace {status}"))

    def _rdap_worker_one(self, ip: str):
        if ip in self._rdap_cache:
            rir, owner, email, rng = self._rdap_cache[ip]
            self.enqueue(("hop_rdap", ip, rir, owner, email, rng))
            return
        rir, owner, email, rng = rdap_lookup_ip(ip)
        self._rdap_cache[ip] = (rir, owner, email, rng)
        self.enqueue(("hop_rdap", ip, rir, owner, email, rng))

    def start_ping_loop(self):
        threading.Thread(target=self._ping_loop, daemon=True).start()

    def _ping_loop(self):
        while not self._stop.is_set():
            if not self.ping_enabled or not self.hops:
                time.sleep(0.2)
                continue
            mode = self.ping_cfg.mode
            port = self.ping_cfg.port
            to = self.ping_cfg.timeout_s

            for h in list(self.hops):
                if self._stop.is_set() or not self.ping_enabled:
                    break
                if h.ip == "*" or not h.ip:
                    continue

                self._ping_seq += 1
                ok = False
                ttl = None
                rtt = None

                if mode == "icmp":
                    if ":" in h.ip:
                        ok, ttl = icmp_ping_v6_once(h.ip, self._ping_ident, self._ping_seq, timeout_s=to, tclass=self.net_cfg.tos)
                    else:
                        ok, ttl = icmp_ping_v4_once(h.ip, self._ping_ident, self._ping_seq, timeout_s=to, tos=self.net_cfg.tos)
                elif mode == "tcp":
                    ok, rtt = tcp_port_ping_once(h.ip, port, timeout_s=to, tos=self.net_cfg.tos)
                elif mode == "udp":
                    ok, rtt = udp_port_ping_once(h.ip, port, timeout_s=to, tos=self.net_cfg.tos)

                self.enqueue(("ping_result", h.ip, ok, ttl, rtt))
            time.sleep(0.2)

    def request_ports_scan(self):
        threading.Thread(target=self._ports_worker, daemon=True).start()

    def _ports_worker(self):
        mode = self.port_cfg.mode
        ports = list(self.port_cfg.ports)
        dip = self.dest_ip

        self.enqueue(("status", f"ports(dest) {mode} {ports} ..."))
        for p in ports:
            if self._stop.is_set():
                break
            st = self._probe_one(dip, mode, p)
            self.enqueue(("port_result", "dest", dip, mode, p, st))

        self.enqueue(("status", f"ports(hops) {mode} {ports} ..."))
        for h in list(self.hops):
            if self._stop.is_set():
                break
            if h.ip == "*" or not h.ip:
                continue
            for p in ports:
                st = self._probe_one(h.ip, mode, p)
                self.enqueue(("port_result", "hop", h.ip, mode, p, st))

        self.enqueue(("status", "ports done"))

    def _probe_one(self, ip: str, mode: str, port: int) -> str:
        if mode == "tcp":
            return tcp_connect_probe(ip, port)
        if mode == "udp":
            return udp_send_probe(ip, port)
        if mode == "raw":
            if ":" in ip:
                return "raw(v6) n/a"
            return raw_tcp_syn_probe_v4(ip, port, tos=self.net_cfg.tos)
        if mode == "sctp":
            return sctp_connect_probe(ip, port)
        return "badmode"

    def request_dns_trace(self):
        threading.Thread(target=self._dns_trace_worker, daemon=True).start()

    def _dns_trace_worker(self):
        self.enqueue(("status", "dns trace(iterative)..."))
        path, auth_ip = dns_iterative_trace_one_per_level(self.target, want_aaaa=False)
        self.last_dns_path = path
        self.last_dns_auth_ip = auth_ip
        self.enqueue(("dns_path", path, auth_ip))
        self.enqueue(("status", "dns trace done"))

    def request_dns_info(self):
        threading.Thread(target=self._dns_info_worker, daemon=True).start()

    def _dns_info_worker(self):
        self.enqueue(("status", "dns auth info..."))
        lines = dns_authoritative_info(self.target)
        self.enqueue(("dns_info", lines))
        self.enqueue(("status", "dns auth info done"))

    def request_dns_query(self, server_ip: str, name: str, qtype: str):
        threading.Thread(target=self._dns_query_worker, args=(server_ip, name, qtype), daemon=True).start()

    def _dns_query_worker(self, server_ip: str, name: str, qtype: str):
        self.enqueue(("status", f"dns query {server_ip} {name} {qtype}..."))
        ok, st, sec = dns_query(server_ip, name, qtype, rd=True, do=True)
        lines = [f"status: {st}", ""]
        lines.append("[Answer]")
        lines += (sec["answer"] or ["(none)"])
        lines.append("")
        lines.append("[Authority]")
        lines += (sec["authority"] or ["(none)"])
        lines.append("")
        lines.append("[Additional]")
        lines += (sec["additional"] or ["(none)"])
        self.enqueue(("dns_query_res", f"DNS Query {server_ip} {qtype} {name}", lines))
        self.enqueue(("status", "dns query done"))

    def request_web_probe(self, tool: str, base_url: str):
        threading.Thread(target=self._web_probe_worker, args=(tool, base_url), daemon=True).start()

    def _web_probe_worker(self, tool: str, base_url: str):
        self.enqueue(("status", f"web probe ({tool})..."))
        title, lines = web_probe(tool, base_url, timeout_s=3.0)
        self.enqueue(("web_probe_res", title, lines))
        self.enqueue(("status", "web probe done"))

# -------------------------
# UI drawing
# -------------------------
def draw_ui(stdscr, eng: Engine, status_line: str):
    stdscr.erase()
    maxy, maxx = stdscr.getmaxyx()

    fam = eng.net_cfg.family
    v4 = eng.dest_v4 or "-"
    v6 = eng.dest_v6 or "-"
    header = (
        f"netdiag target={eng.target} v4={v4} v6={v6} use={fam}:{eng.dest_ip} "
        f"trace={eng.trace_cfg.method}:{eng.trace_cfg.port} ping={'on' if eng.ping_enabled else 'off'} "
        f"pingmode={eng.ping_cfg.mode}:{eng.ping_cfg.port} tos={eng.net_cfg.tos}"
    )
    stdscr.addnstr(0, 0, header, maxx - 1, attr_bold())

    y0, x0 = 1, 0
    h, w = maxy - 2, maxx
    draw_border_box(stdscr, y0, x0, h, w, attr_base())

    dest_h = max(7, (maxy // 4))
    top_h = h - dest_h - 1
    dest_y0 = y0 + top_h

    draw_hline_box(stdscr, x0 + 1, x0 + w - 2, dest_y0, attr_base())

    left_w = max(52, w // 2)
    split_x = x0 + left_w
    draw_vline_box(stdscr, y0 + 1, dest_y0 - 1, split_x, attr_base())

    draw_cross_acs(stdscr, dest_y0, x0, "ltee", attr_base())
    draw_cross_acs(stdscr, dest_y0, x0 + w - 1, "rtee", attr_base())
    draw_cross_acs(stdscr, y0, split_x, "ttee", attr_base())
    draw_cross_acs(stdscr, dest_y0, split_x, "plus", attr_base())

    stdscr.addnstr(y0 + 1, x0 + 2, "HOPS", left_w - 4, attr_bold())
    stdscr.addnstr(y0 + 1, split_x + 2, "DETAIL", w - left_w - 4, attr_bold())
    stdscr.addnstr(dest_y0 + 1, x0 + 2, "DEST PORTS", w - 4, attr_bold())

    list_top = y0 + 2
    list_h = (dest_y0 - 1) - list_top
    start = 0
    if eng.selected >= list_h:
        start = eng.selected - list_h + 1

    for row in range(max(0, list_h)):
        idx = start + row
        if idx >= len(eng.hops):
            break
        hop = eng.hops[idx]
        sel = (idx == eng.selected)

        host_show = hop.host if hop.host else hop.ip
        loss = hop.stats.loss_pct
        sent = hop.stats.sent
        rtt = "-" if hop.stats.rtt_last_ms is None else f"{hop.stats.rtt_last_ms:6.1f}ms"

        asn_txt = f"AS{hop.asn:<7}"
        asn_attr = attr_flap() if hop.flap else attr_base()

        rir_txt = f"{hop.rir:<6}" if hop.rir else "?:    "
        mpls_txt = "MPLS" if hop.mpls else "    "

        prefix = f"{hop.idx:>2} {host_show:<24.24} "
        mid = f"{asn_txt} {rir_txt} {mpls_txt} "
        suffix = f" loss={loss:>5.1f}% sent={sent:<4} rtt={rtt}"

        attr_line = attr_selected() if sel else attr_base()
        stdscr.addnstr(list_top + row, x0 + 2, prefix, left_w - 4, attr_line)

        x = x0 + 2 + len(prefix)
        stdscr.addnstr(list_top + row, x, asn_txt, min(len(asn_txt), left_w - 4 - len(prefix)), asn_attr)

        x2 = x + len(asn_txt) + 1
        stdscr.addnstr(list_top + row, x2, rir_txt, min(len(rir_txt), left_w - 4 - (x2 - (x0 + 2))), attr_line)

        x3 = x2 + len(rir_txt) + 1
        stdscr.addnstr(list_top + row, x3, mpls_txt, min(len(mpls_txt), left_w - 4 - (x3 - (x0 + 2))), attr_line)

        x4 = x3 + len(mpls_txt) + 1
        stdscr.addnstr(list_top + row, x4, suffix, left_w - 4 - (x4 - (x0 + 2)), attr_line)

    if eng.hops:
        hop = eng.hops[eng.selected]
        s = hop.stats
        ttl_best = "-" if s.ttl_best is None else str(s.ttl_best)
        ttl_worst = "-" if s.ttl_worst is None else str(s.ttl_worst)

        detail_lines = [
            f"Hop: {hop.idx}",
            f"IP:  {hop.ip}",
            f"Host: {hop.host or '-'}",
            f"ASN:  AS{hop.asn} {hop.org}",
            f"FLAP: {'YES' if hop.flap else 'no'}",
            f"MPLS: {hop.mpls or 'no'}",
            "",
            "NIC / RDAP:",
            f"  RIR:   {hop.rir}",
            f"  Owner: {hop.owner or '-'}",
            f"  Email: {hop.email or '-'}",
            f"  Range: {hop.ip_range or '-'}",
            "",
            f"Ping mode: {eng.ping_cfg.mode} port={eng.ping_cfg.port} to={eng.ping_cfg.timeout_s:.1f}s",
            f"  sent: {s.sent}",
            f"  lost: {s.lost} ({s.loss_pct:.1f}%)",
            f"  TTL best:  {ttl_best}",
            f"  TTL worst: {ttl_worst}",
            f"  RTT last:  {'-' if s.rtt_last_ms is None else f'{s.rtt_last_ms:.1f} ms'}",
            "",
            "Ports (hop):",
        ]
        mode = eng.port_cfg.mode
        ports_map = hop.ports.get(mode, {})
        if ports_map:
            for p in eng.port_cfg.ports[:10]:
                if p in ports_map:
                    detail_lines.append(f"  {p:>5}/{mode:<4} {ports_map[p]}")
        else:
            detail_lines.append("  (no data)")

        detail_lines += [
            "",
            "Keys:",
            "  ↑/↓ select | r trace | t cycle-trace | p toggle ping",
            "  M menu | m ports | o TOS | 4/6/a family",
            "  Y set trace port | P pdf report",
            "  X dns-trace | I dns-info | y dns-query | w web-probe | q quit",
        ]

        ry = y0 + 2
        rx = split_x + 2
        for line in detail_lines:
            if ry >= dest_y0 - 1:
                break
            stdscr.addnstr(ry, rx, line, w - left_w - 4, attr_base())
            ry += 1

    mode = eng.port_cfg.mode
    dp = eng.dest_ports.get(mode, {})
    dy = dest_y0 + 2
    stdscr.addnstr(dy, x0 + 2, f"Mode: {mode}   Ports: {','.join(str(p) for p in eng.port_cfg.ports)}", w - 4, attr_base())
    dy += 1
    if not dp:
        stdscr.addnstr(dy, x0 + 2, "(no dest scan yet) open Ports Menu and apply", w - 4, attr_dim())
    else:
        for p in eng.port_cfg.ports:
            if dy >= y0 + h - 1:
                break
            if p in dp:
                stdscr.addnstr(dy, x0 + 2, f"{p:>5}/{mode:<4} {dp[p]}", w - 4, attr_base())
                dy += 1

    stdscr.addnstr(maxy - 1, 0, status_line.ljust(maxx - 1), maxx - 1, attr_dim())
    stdscr.refresh()

# -------------------------
# App loop
# -------------------------
def app(stdscr, target: str, trace_method: str, ping_enabled: bool, tos: int, family: str, trace_port: int):
    init_colors()
    try:
        curses.curs_set(0)
    except Exception:
        pass
    stdscr.nodelay(True)
    stdscr.keypad(True)

    trace_cfg = TraceConfig(method=trace_method, max_hops=30, timeout_s=0.6, port=trace_port)
    port_cfg = PortConfig(mode="tcp", ports=[22, 80, 443, 53])
    ping_cfg = PingConfig(mode="icmp", port=443, timeout_s=1.0)
    net_cfg = NetConfig(family=family, tos=tos)

    eng = Engine(target, trace_cfg=trace_cfg, port_cfg=port_cfg, ping_cfg=ping_cfg, net_cfg=net_cfg, ping_enabled=ping_enabled)

    status = "ready"
    eng.request_trace(force=True)
    eng.start_ping_loop()
    eng.request_ports_scan()

    dns_path_cache: List[Tuple[str, str, float]] = []
    dns_info_cache: List[str] = []

    last_ui = 0.0
    while True:
        for ev in eng.poll_events():
            et = ev[0]
            if et == "status":
                status = ev[1]
            elif et == "trace_done":
                ips, mpls_map, st = ev[1], ev[2], ev[3]
                eng.hops = [Hop(idx=i + 1, ip=ip) for i, ip in enumerate(ips)]
                eng.selected = 0
                status = f"trace {st}"
                for h in eng.hops:
                    if h.ip in mpls_map:
                        h.mpls = mpls_map[h.ip]
                eng.request_ports_scan()
            elif et == "hop_meta":
                ip, host, asn, org = ev[1], ev[2], ev[3], ev[4]
                for h in eng.hops:
                    if h.ip == ip:
                        h.host = host or h.host
                        if asn and asn != "?":
                            old = eng._last_asn_by_idx.get(h.idx)
                            h.flap = (old is not None and old != asn)
                            eng._last_asn_by_idx[h.idx] = asn
                        h.asn = asn or h.asn
                        h.org = org or h.org
                        break
            elif et == "hop_mpls":
                ip, mpls_txt = ev[1], ev[2]
                for h in eng.hops:
                    if h.ip == ip:
                        h.mpls = mpls_txt
                        break
            elif et == "hop_rdap":
                ip, rir, owner, email, rng = ev[1], ev[2], ev[3], ev[4], ev[5]
                for h in eng.hops:
                    if h.ip == ip:
                        h.rir = rir or h.rir
                        h.owner = owner or h.owner
                        h.email = email or h.email
                        h.ip_range = rng or h.ip_range
                        break
            elif et == "ping_result":
                ip, ok, ttl, rtt = ev[1], ev[2], ev[3], ev[4]
                for h in eng.hops:
                    if h.ip == ip:
                        h.stats.sent += 1
                        if not ok:
                            h.stats.lost += 1
                        else:
                            if ttl is not None:
                                if h.stats.ttl_best is None or ttl < h.stats.ttl_best:
                                    h.stats.ttl_best = ttl
                                if h.stats.ttl_worst is None or ttl > h.stats.ttl_worst:
                                    h.stats.ttl_worst = ttl
                        if rtt is not None:
                            h.stats.rtt_last_ms = rtt
                        break
            elif et == "port_result":
                scope, ip, mode, port, stt = ev[1], ev[2], ev[3], ev[4], ev[5]
                if scope == "dest":
                    eng.dest_ports.setdefault(mode, {})[port] = stt
                else:
                    for h in eng.hops:
                        if h.ip == ip:
                            h.ports.setdefault(mode, {})[port] = stt
                            break
            elif et == "dns_path":
                dns_path_cache = ev[1]
                eng.last_dns_auth_ip = ev[2]
            elif et == "dns_info":
                dns_info_cache = ev[1]
            elif et == "dns_query_res":
                title, lines = ev[1], ev[2]
                popup_list(stdscr, title, lines)
            elif et == "web_probe_res":
                title, lines = ev[1], ev[2]
                popup_list(stdscr, title, lines)

        ch = -1
        try:
            ch = stdscr.getch()
        except Exception:
            ch = -1

        if ch != -1:
            if ch in (ord('q'), 27):
                eng.stop()
                break
            elif ch in (curses.KEY_UP, ord('k')):
                eng.selected = max(0, eng.selected - 1)
            elif ch in (curses.KEY_DOWN, ord('j')):
                if eng.hops:
                    eng.selected = min(len(eng.hops) - 1, eng.selected + 1)
            elif ch == ord('r'):
                eng.request_trace(force=True)
            elif ch == ord('t'):
                eng.trace_cfg.method = cycle_trace_method(eng.trace_cfg.method)
                status = f"trace -> {eng.trace_cfg.method}"
                eng.request_trace(force=True)
            elif ch == ord('p'):
                eng.ping_enabled = not eng.ping_enabled
                status = f"ping -> {'on' if eng.ping_enabled else 'off'}"
            elif ch == ord('4'):
                eng.set_family("v4")
                status = f"family -> v4 ({eng.dest_ip})"
                eng.request_trace(force=True)
            elif ch == ord('6'):
                eng.set_family("v6")
                status = f"family -> v6 ({eng.dest_ip})"
                eng.request_trace(force=True)
            elif ch == ord('a'):
                eng.set_family("auto")
                status = f"family -> auto ({eng.dest_ip})"
                eng.request_trace(force=True)
            elif ch == ord('m'):
                stdscr.nodelay(False)
                new_pc = ports_menu(stdscr, eng.port_cfg)
                stdscr.nodelay(True)
                if new_pc is not None:
                    eng.port_cfg = new_pc
                    eng.dest_ports.setdefault(new_pc.mode, {}).clear()
                    for h in eng.hops:
                        h.ports.setdefault(new_pc.mode, {}).clear()
                    status = f"ports -> {new_pc.mode} {new_pc.ports}"
                    eng.request_ports_scan()
            elif ch == ord('o'):
                stdscr.nodelay(False)
                new_tos = tos_menu(stdscr, eng.net_cfg.tos)
                stdscr.nodelay(True)
                if new_tos is not None:
                    eng.net_cfg.tos = new_tos
                    status = f"tos -> {new_tos}"
                    eng.request_trace(force=True)
                    eng.request_ports_scan()
            elif ch in (ord('Y'),):
                stdscr.nodelay(False)
                v = trace_port_menu(stdscr, eng.trace_cfg.port)
                stdscr.nodelay(True)
                if v is not None:
                    eng.trace_cfg.port = v
                    status = f"trace port -> {v}"
                    eng.request_trace(force=True)
            elif ch in (ord('P'),):
                stdscr.nodelay(False)
                name = prompt_modal(stdscr, "PDF report", "Filename:", f"netdiag_{int(time.time())}.pdf")
                stdscr.nodelay(True)
                if name:
                    status = "generating pdf..."
                    ok, msg = gen_pdf_report(
                        name,
                        eng.target,
                        eng.dest_v4 or "",
                        eng.dest_v6 or "",
                        eng.dest_ip,
                        eng.trace_cfg.method,
                        eng.trace_cfg.port,
                        eng.ping_enabled,
                        eng.ping_cfg.mode,
                        eng.ping_cfg.port,
                        eng.net_cfg.tos,
                        list(eng.hops),
                        eng.selected,
                        dict(eng.dest_ports),
                        eng.port_cfg
                    )
                    status = f"pdf: {msg}" if ok else f"pdf error: {msg}"
            elif ch in (ord('w'), ord('W')):
                stdscr.nodelay(False)
                req = web_probe_menu(stdscr)
                stdscr.nodelay(True)
                if req is not None:
                    tool, url = req
                    eng.request_web_probe(tool, url)
                    status = f"web probe requested ({tool})"
            elif ch in (ord('x'), ord('X')):
                if not dns_path_cache:
                    eng.request_dns_trace()
                    status = "dns trace requested..."
                else:
                    lines = [f"{lvl:<12} {ip:<40} {rtt:7.1f} ms" for (lvl, ip, rtt) in dns_path_cache]
                    popup_list(stdscr, "DNS trace (one responder per level)", lines)
            elif ch in (ord('i'), ord('I')):
                eng.request_dns_info()
            elif ch in (ord('y'),):
                stdscr.nodelay(False)
                req = dns_query_menu(stdscr)
                stdscr.nodelay(True)
                if req is not None:
                    server_ip, name, qt = req
                    eng.request_dns_query(server_ip, name, qt)
            elif ch in (ord('M'),):
                stdscr.nodelay(False)
                res = main_menu(stdscr, eng.trace_cfg, eng.port_cfg, eng.ping_cfg)
                stdscr.nodelay(True)
                if res is not None:
                    tcfg, pcfg, gcfg, action = res
                    eng.trace_cfg = tcfg
                    eng.port_cfg = pcfg
                    eng.ping_cfg = gcfg
                    status = f"menu applied: trace={tcfg.method}:{tcfg.port} ping={gcfg.mode}:{gcfg.port}"
                    if action == "dns_trace":
                        eng.request_dns_trace()
                    elif action == "dns_info":
                        eng.request_dns_info()
                    elif action == "dns_query":
                        req = dns_query_menu(stdscr)
                        if req is not None:
                            server_ip, name, qt = req
                            eng.request_dns_query(server_ip, name, qt)
                    elif action == "web_probe":
                        req = web_probe_menu(stdscr)
                        if req is not None:
                            tool, url = req
                            eng.request_web_probe(tool, url)
                    eng.request_trace(force=True)
                    eng.request_ports_scan()

        if dns_info_cache:
            popup_list(stdscr, "DNS Authoritative Info", dns_info_cache)
            dns_info_cache = []

        now = time.time()
        if now - last_ui >= 0.05:
            draw_ui(stdscr, eng, status)
            last_ui = now

        time.sleep(0.01)

def main():
    ap = argparse.ArgumentParser(prog="netdiag")
    ap.add_argument("target")
    ap.add_argument("--trace", choices=["off", "pyudp", "pyicmp", "tracepath", "traceroute", "traceroute-udp", "traceroute-tcp", "mtr-sctp", "raw6"], default="pyudp")
    ap.add_argument("--ping", choices=["on", "off"], default="on")
    ap.add_argument("--tos", type=int, default=0)
    ap.add_argument("--family", choices=["auto", "v4", "v6"], default="auto")
    ap.add_argument("--trace-port", type=int, default=33434)
    args = ap.parse_args()

    try:
        curses.wrapper(app, args.target, args.trace, args.ping == "on", args.tos, args.family, args.trace_port)
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()

