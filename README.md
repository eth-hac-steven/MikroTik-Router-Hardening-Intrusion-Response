# MikroTik Router Hardening & Intrusion Response

**Platform:** MikroTik RouterOS (RB2011UiAS-2HnD) managed via Winbox

**Category:** Network Security / Firewall Engineering / Incident Response

## Overview

This project covers hardening a MikroTik router against unwanted outbound content access and unauthorized inbound remote-management access, followed by detecting and containing a live brute-force intrusion attempt observed in the router's system logs.

The work is split into four phases:
1. Outbound content filtering (DNS/firewall based)
2. Inbound attack-surface reduction (management service exposure)
3. How attackers discover exposed devices with no prior information
4. Log-based incident detection and response

---

## Phase 2: Inbound Attack Surface Reduction

**Goal:** Reduce exposure of remote management services (SSH, FTP, Telnet, Winbox, HTTP/S) to the public internet.

### Key principle
A device does **not** need to share a network with the router to attempt an SSH/FTP/Telnet connection, if a management port is open on the WAN interface, it is reachable and scannable from anywhere on the internet. This is the mechanism behind the brute-force event in Phase 3.

### Configuration
On the terminal 
```rril
/interface list member
add interface=ether1 list=WAN

/ip firewall filter
add chain=input in-interface-list=WAN protocol=tcp dst-port=22,21,23,8291,80,443 action=drop comment="Block management ports from WAN"
```
on Winbox/Webconfig 

select ip > Firewall > filter > 

**Recommended long-term control:** replace direct WAN exposure of SSH/Winbox with VPN-gated access (WireGuard), so management interfaces are only reachable from inside an authenticated tunnel, never directly from the public internet.

![Interface List showing `ether1` added to the `WAN` list](https://github.com/eth-hac-steven/MikroTik-Router-Hardening-Intrusion-Response/blob/main/Block%20rule%20on%20WAN%20port.png)

---

## Phase 3: How Attackers Discover Exposed Devices

A natural question: remote login requires `username@host` so how does an attacker obtain the *host* (public IP) in the first place, with no prior information about the target?

**The short answer: they don't need any inside knowledge. Discovery and login are two separate steps.**

- **Mass internet scanning** Tools like Masscan or ZMap can sweep the entire IPv4 address space (~4.3 billion addresses) for open ports in minutes to hours. Every public IP, including a home/office router's WAN address, is a candidate no targeting required, just a response on a scanned port.
- **Scanning search engines (Shodan, Censys)** These continuously index every internet-facing device that responds on common ports, often including the service banner (e.g. "MikroTik RouterOS"). An attacker can search by port, country, or device fingerprint and get a ready-made list of exposed IPs.
- **ISP range sweeps** ISP-owned IP blocks are publicly known (WHOIS/RIR records). Attackers often sweep entire ISP ranges systematically, since a percentage of consumer/business routers in any given range will have something open.
- **No credentials needed to *find* the target** The `username@host` syntax only applies to the login attempt itself. Determining that a host exists and has FTP/SSH open is just a connectivity probe zero authentication involved. Once discovered, automated tools cycle through common usernames (`admin`, `web`, `root`, `ftp`, `user`...) against that IP, which is exactly the pattern captured in the Phase 4 logs below.

This is the practical justification for Phase 2: blocking one attacking IP after the fact stops that one attempt, but closing the exposed port stops the router from ever appearing as a live target to the next scan.

---

## Phase 4:  Incident Detection & Response

**Trigger:** Routine log review (`Log` window, filtered by `critical` / `account` topics) surfaced a burst of repeated authentication failures.

### Evidence

![Mal-ip-1](https://github.com/eth-hac-steven/MikroTik-Router-Hardening-Intrusion-Response/blob/main/Mal-sus%20ip%20attempting%20connections%20via%20ssh.png)

![Mal-ip-1pt2](https://github.com/eth-hac-steven/MikroTik-Router-Hardening-Intrusion-Response/blob/main/REd-flag%20on%20small%20mkiro%20tik.png)

![Mal-ip2](https://github.com/eth-hac-steven/MikroTik-Router-Hardening-Intrusion-Response/blob/main/Red-flag%20number%202.png)

![Mal-ip1pt2](https://github.com/eth-hac-steven/MikroTik-Router-Hardening-Intrusion-Response/blob/main/another%20mal%20ip%20attempting%20connction%20%20via%20ssh.png)


**Analysis:**
- Multiple source IP (`202.77.96.130`,`176.53.159.198`,`2.57.121.211`), Multiple username (`web`,`admin`, `rpc`, `root`, `ftp`, `user`,`postgres`), rapid repeated 5 times attempts consistent with an automated/scripted brute-force or credential-stuffing tool rather than manual login attempts
- Cross-referenced a nearby log entry (`user admin logged in from 192.168.88.x via winbox`) to rule out that this was a legitimate but misremembered login confirmed as the administrator's own known device
- Cross-referenced with [IPAbuseDB](https://github.com/eth-hac-steven/MikroTik-Router-Hardening-Intrusion-Response/blob/main/redflag3.png) and [Virustotal](https://github.com/eth-hac-steven/MikroTik-Router-Hardening-Intrusion-Response/blob/main/soc-VT%20reports.png) to verify history of malicious attempt with this ip 
- **5 times** burst attempt is very important here as this is the grace/max attempt that legitimate user can enter and get their password wrong before an account lock-out after 5 times the user name changes as seen, so this would normally go undetected.

This is a prime example of Threat actors exploiting "Standard" IT/Cyber Procedures.

- The Automated script being run here has a dictionary list of Default/common username and password 
  
### Containment

```rril
/ip firewall address-list
add list=blacklist address=202.77.96.130 comment="Malicious brute force Attempt"
add list=blacklist address=176.53.159.198 comment="Malicious brute force Attempt"
add list=blacklist address=2.57.121.211 comment="Malicious brute force Attempt"

/ip firewall filter
add chain=input src-address-list=blacklist action=drop place-before=0 comment="Drop blocked IPs"
```
By creating the Address list blacklist  any other identified Mal ip will be added to that list and the  firewall rule will applied to it.

Rule placed at the top of the `input` chain to ensure it is evaluated before any accept rules(First-match-wins principle).

![Blocking-malicious-ip](https://github.com/eth-hac-steven/MikroTik-Router-Hardening-Intrusion-Response/blob/main/Blocking%20Mal-ips.png)

### Follow-up hardening (recommended)
- Disable the FTP service entirely under `IP → Services` if not actively required
- Restrict Winbox `Available From` to a trusted management subnet only
- Consider an automated brute-force protection rule set (auto-blacklist on repeated failure, timed expiry).
- Introduction of IDS

---

## Skills Demonstrated

- RouterOS firewall rule design (`filter`, `nat`, `address-list`)
- DNS-based access control and its bypass vectors (DoH/DoT)
- Attack-surface reduction for exposed management services
- Log-based threat detection and triage
- Incident containment (blacklist-based IP blocking)
- Root-cause troubleshooting of inconsistent firewall behavior (DNS caching / TTL)
