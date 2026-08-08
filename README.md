# Void Finder 🔎

**Void Finder** is an OSINT tool for uncovering the **origin IP address** of a
website hidden behind a CDN, WAF, or reverse proxy (Cloudflare, Akamai, Fastly,
CloudFront, Sucuri, Imperva, and friends).

Most "origin finder" scripts just dump a pile of IPs and leave you guessing.
Void Finder goes further: it pulls candidate IPs from many independent sources,
throws away the ones that provably belong to a CDN, and then **actively
confirms** the real origin by connecting to each candidate directly — presenting
the target's SNI and `Host` header — and comparing the response against a
baseline of the live site (TLS certificate, page title, and body content).

If a candidate serves the real site directly, Void Finder tells you, with a
confidence score.

---

## Why it's different

| Capability | Typical scripts | Void Finder |
|---|---|---|
| Candidate discovery | A records + a few subdomains | A/AAAA, MX, NS, **SPF/TXT chains**, **Certificate Transparency**, subdomain brute force, HTTP leak headers, Shodan |
| CDN awareness | none | Live Cloudflare ranges + static ranges for 8 major providers |
| **Origin confirmation** | none — just lists IPs | Direct SNI+Host probe, TLS-SAN / title / body comparison with a confidence score |
| Speed | sequential | Concurrent (configurable thread pool) |
| Robustness | crashes on null-MX, wildcards | Wildcard-DNS filtering, hardened error handling |
| Output | print only | Colored report **+ machine-readable JSON** |

---

## How it works

1. **DNS records** — apex `A`/`AAAA`, `MX` (mail servers often live on the
   origin), `NS`, and `SPF`/`TXT` records (recursively following `include:` and
   `redirect=` chains, harvesting `ip4:`/`ip6:`/`a:`/`mx:` mechanisms).
2. **HTTP header inspection** — flags leaked `X-Real-IP`, `X-Backend-Server`,
   `True-Client-IP`, and similar headers.
3. **Certificate Transparency** — enumerates subdomains from `crt.sh`; forgotten
   or dev subdomains frequently point straight at the origin.
4. **Subdomain brute force** — concurrent resolution of a bundled wordlist
   (biased toward panels, mail, dev/staging, and direct-connect hosts), with
   **wildcard-DNS detection** so catch-all records don't create fake hits.
5. **Shodan pivots** *(optional)* — `hostname:`, `ssl.cert.subject.cn:`, and
   **favicon-hash** searches to find servers exposing the same site.
6. **Classification & enrichment** — every IP is tagged CDN vs non-CDN and
   enriched with reverse DNS + WHOIS/ASN ownership.
7. **Active origin verification** — for each non-CDN candidate, Void Finder
   connects directly to the IP with the target's SNI + `Host` header and scores
   the match against a baseline (cert SAN coverage, `<title>`, body similarity,
   status code). Anything ≥ 60% is reported as a **confirmed origin**.

---

## Installation

```bash
git clone https://github.com/CypherNova1337/Void_Finder
cd Void_Finder
pip install -r requirements.txt
```

Core dependencies: `dnspython`, `requests`, `urllib3`, `ipwhois`.
Optional (auto-detected): `shodan` and `mmh3` (favicon hashing).

---

## Usage

```bash
python void_finder.py <domain> [more domains ...]
```

### Examples

```bash
# Full investigation
python void_finder.py example.com

# Multiple targets at once
python void_finder.py example.com example.org acme.test

# Bulk scan from a file (one domain per line, # comments allowed)
python void_finder.py --targets scope.txt

# Use a Shodan key for extra pivots
python void_finder.py example.com --shodan-key YOUR_KEY
#   ...or:  export SHODAN_API_KEY=YOUR_KEY

# Save machine-readable results
python void_finder.py example.com -o results.json
python void_finder.py example.com --csv results.csv
python void_finder.py example.com --json | jq .

# Faster / bigger custom wordlist
python void_finder.py example.com -t 80 -w /path/to/subdomains.txt

# DNS-only, no outbound HTTP
python void_finder.py example.com --offline

# Skip individual phases
python void_finder.py example.com --no-brute --no-ct --no-verify
```

### Key options

| Option | Description |
|---|---|
| `--targets FILE` | Bulk scan targets from a file (one per line) |
| `-o, --output FILE` | Write full results as JSON |
| `--csv FILE` | Write candidate rows as CSV |
| `--json` | Print JSON to stdout (machine mode) |
| `-w, --wordlist FILE` | Custom subdomain wordlist |
| `-t, --threads N` | Concurrent workers (default 40) |
| `--shodan-key KEY` | Shodan API key (or `SHODAN_API_KEY` env var) |
| `--resolver IP[,IP]` | Custom DNS resolver(s) |
| `--verify-all` | Verify all non-CDN IPs, including apex IPs |
| `--no-ct` / `--no-brute` / `--no-verify` | Skip a phase |
| `--offline` | DNS only, no outbound HTTP |
| `--dns-timeout` / `--http-timeout` | Per-operation timeouts |
| `-q, --quiet` / `-v, --verbose` | Output verbosity |

Configuration is done entirely via flags and environment variables — **no API
keys are stored in source**.

---

## Reading the report

- **★ Confirmed origin candidates** — IPs that served the real site directly.
  Start here.
- **CDN / WAF / public-facing IPs** — the edge; not the origin.
- **Other non-CDN candidates** — worth manual investigation. A score like `55%`
  usually means the TLS certificate matches the target but the served content
  differed (e.g. a redirect or a different vhost).

Void Finder also surfaces useful side-findings, such as **RFC1918 internal IPs
leaked into public DNS**.

---

## Disclaimer

This tool is intended for **authorized security assessment and educational use
only**. Only run it against systems you own or have explicit written permission
to test. You are responsible for how you use it.
