# netdiag — Network Troubleshooting TUI

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE.md)

> **Disclaimer:**  
> This tool is provided "as is" without any warranty. Use at your own risk.  
> Ensure you have proper authorization before running network probes on any target.
> [Link to formal disclaimer document](DISCLAIMER.md)

**netdiag** is a console-based network troubleshooting tool (ncurses TUI) designed for network and infrastructure engineers.  
It combines the functionality of multiple classic tools into a single, asynchronous, self-contained interface:

- `mtr`
- `traceroute` / `tracepath`
- `ping`
- `nmap` (partial, port-oriented)
- `dig` / DNS trace
- `curl` / `wget` (HTTP probing)

Built for Linux servers, bastion hosts, and SSH environments, with no GUI dependencies.

---

## 1. Dependencies

**Operating System:** RHEL / Rocky / Alma Linux 9.x  
**Kernel:** with RAW socket support (default)

**System packages:**
```sh
dnf install -y \
    python3 \
    python3-devel \
    ncurses \
    ncurses-devel \
    traceroute \
    iputils \
    curl \
    wget
```
*`traceroute` and `tracepath` are optional. The core engine works without them using RAW sockets.*

**Python (pip):**
```sh
pip install --upgrade pip
pip install pyinstaller
```

**Optional (PDF reports):**
```sh
pip install reportlab
```
*RHEL 9.x does not provide python3-reportlab via dnf.
PDF export is disabled automatically if reportlab is missing.*

---

## 2. Building the Executable

### 2.1 Direct Execution (Development Mode)
```sh
sudo python3 cli.py google.com
```
*Requires sudo for:*
- ICMP RAW
- UDP tracing
- TCP SYN RAW probes
- ICMPv6

### 2.2 Building a Self-contained Binary
```sh
pyinstaller \
    --onefile \
    --name netdiag \
    cli.py
```
**Result:**  
`dist/netdiag`

**Run:**  
```sh
sudo ./dist/netdiag google.com
```

---

## 3. Usage

**Basic syntax:**
```sh
netdiag <host|ip>
```

**Examples:**
```sh
netdiag google.com
netdiag 8.8.8.8
netdiag ipv6.google.com
```

### Navigation

| Key      | Action                       |
|----------|-----------------------------|
| ↑ / ↓    | Select hop                   |
| q        | Quit                         |
| r        | Re-run trace                 |
| t        | Cycle trace method           |
| 4        | Force IPv4                   |
| 6        | Force IPv6                   |
| a        | Auto (IPv4/IPv6)             |

#### Ping / RTT

| Key | Action                |
|-----|-----------------------|
| p   | Toggle ping           |
| o   | Change TOS / Traffic Class |
| P   | Generate PDF report   |

**Reports**

- P : Generate PDF report (current screen)

**PDF Report**

Generated from current UI state

**Includes**:

- Target information

- Trace configuration

- Visible hops

- Selected hop highlight

- RDAP / ASN / MPLS data

**Destination port scan results**

- If reportlab is not installed:

``` PDF export disabled: missing module 'reportlab' ```

**Install with**

```pip install reportlab```

**Ping modes:**
- ICMP
- TCP (by port)
- UDP (by port)

#### Trace

| Key | Action                  |
|-----|-------------------------|
| t   | Cycle trace method      |
| Y   | Change trace base port  |
| M   | Open main menu          |

**Available trace methods:**
- pyudp (fast, no DNS)
- pyicmp
- tracepath
- traceroute
- traceroute-udp
- traceroute-tcp
- raw6 (placeholder)

#### Ports

| Key | Action              |
|-----|---------------------|
| m   | Configure ports     |
| M   | Menu → Ports        |

**Supported probes:**
- TCP
- UDP
- RAW TCP (SYN)
- SCTP (best-effort)

*Ports are tested against:*
- Final destination
- Each hop in the path

#### DNS

| Key | Action                                         |
|-----|------------------------------------------------|
| X   | Iterative DNS trace (one responder per level)  |
| I   | Authoritative DNS info (SOA / NS / DNSSEC)     |
| y   | DNS query to a specific server                 |

**Includes:**
- DNSSEC detection (DNSKEY / RRSIG)
- Primary and secondary name servers
- Glue record analysis
- Manual queries (dig-like)

#### Web / HTTP

| Key | Action         |
|-----|----------------|
| w   | HTTP/HTTPS probe |

*Uses curl or wget. Requests a non-existing endpoint (404 probe). Useful for validating:*
- Reverse proxies
- Layer-7 firewalls
- Load balancers
- CDNs

---

## 4. Interface

- ncurses TUI
- Borders drawn with ACS (safe over SSH / tmux)
- Opaque modal windows

**Color scheme:**
- Green: normal state
- Red: ASN flapping detected
- Reverse: current selection

---

## 5. Hop-level Information

For each hop, netdiag provides:
- IP address / hostname
- ASN and organization
- RIR (ARIN / RIPE / LACNIC / APNIC / AFRINIC)
- Owner information
- Contact email (if available)
- Assigned IP range
- MPLS detection (best-effort)
- Packet loss
- RTT and TTL (best / worst)

---

## 6. Practical Use Cases

**Real-world scenarios:**
- Packet loss analysis per hop
- Detection of ASN flapping
- MPLS presence identification
- IP allocation and ownership analysis
- Deep DNS troubleshooting
- Per-hop port reachability testing
- Real IPv4 / IPv6 path validation
- TOS / DSCP path testing
- HTTP service diagnostics

*All from a single tool, without external scripts.*

---

## 7. Runtime Requirements

```sh
sudo netdiag <target>
```

*Without sudo, ICMP RAW, UDP trace, and TCP SYN RAW will not function correctly.*

---

## 8. Roadmap (optional)

- PNG export
- Route history tracking
- JSON output
- Prometheus exporter
- BGP / RPKI integration
- Plugin system

---

## 9. Design Philosophy

netdiag prioritizes:
- Speed
- Determinism
- Complete path visibility
- Compatibility with locked-down environments
- Classic nc / mtr workflow

*Built for engineers, not GUIs.*
