#!/usr/bin/env python3
"""
Void Finder - OSINT origin-IP discovery for CDN/proxy-fronted websites.

Void Finder enumerates candidate IPs for a target domain from many independent
sources, filters out addresses that belong to known CDN/WAF providers, and then
actively *confirms* which candidate is the real origin by connecting to each IP
directly (with the target's SNI + Host header) and comparing the response to a
baseline of the live site.

Sources of candidate IPs:
  * A / AAAA records of the apex domain
  * MX (mail) records          -> resolved to IPs
  * SPF / TXT records          -> ip4:/ip6:/a:/mx: mechanisms + include chains
  * NS (name server) records   -> resolved to IPs
  * Certificate Transparency   -> crt.sh subdomain enumeration
  * Subdomain brute force       -> concurrent wordlist resolution
  * Shodan                      -> hostname / ssl.cert / favicon-hash pivots
  * HTTP response headers       -> leaked X-Real-IP / X-Backend / etc.

Every candidate is enriched with reverse DNS + WHOIS/ASN ownership, tagged as
CDN or non-CDN, and non-CDN candidates are actively probed for an origin match.

This tool is for authorized security assessment and educational use only.
Only run it against assets you own or are explicitly permitted to test.
"""

from __future__ import annotations

import argparse
import concurrent.futures as futures
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import time
from dataclasses import dataclass, field, asdict
from typing import Iterable

# --- Third-party dependencies (guarded so we can print a helpful message) ---
_MISSING: list[str] = []
try:
    import dns.resolver
    import dns.exception
except Exception:  # pragma: no cover
    _MISSING.append("dnspython")
try:
    import requests
    import urllib3
    from urllib3.exceptions import InsecureRequestWarning
except Exception:  # pragma: no cover
    _MISSING.append("requests")
try:
    from ipwhois import IPWhois
except Exception:  # pragma: no cover
    _MISSING.append("ipwhois")

# Optional dependencies (features degrade gracefully if absent).
try:
    import shodan  # noqa: F401
    _HAVE_SHODAN = True
except Exception:
    _HAVE_SHODAN = False
try:
    import mmh3  # noqa: F401
    _HAVE_MMH3 = True
except Exception:
    _HAVE_MMH3 = False

if _MISSING:
    sys.stderr.write(
        "Missing required dependencies: %s\n"
        "Install everything with:\n    pip install -r requirements.txt\n"
        % ", ".join(sorted(set(_MISSING)))
    )
    sys.exit(1)

urllib3.disable_warnings(InsecureRequestWarning)

VERSION = "2.0.0"

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

# ---------------------------------------------------------------------------
# Console / logging
# ---------------------------------------------------------------------------


class Console:
    """Minimal ANSI console that degrades to plain text automatically."""

    def __init__(self, use_color: bool | None = None, quiet: bool = False,
                 verbose: bool = False):
        if use_color is None:
            use_color = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
        self.color = use_color
        self.quiet = quiet
        self.verbose = verbose

    def _c(self, text: str, code: str) -> str:
        if not self.color:
            return text
        return f"\033[{code}m{text}\033[0m"

    def dim(self, t):    return self._c(t, "2")
    def bold(self, t):   return self._c(t, "1")
    def red(self, t):    return self._c(t, "31")
    def green(self, t):  return self._c(t, "32")
    def yellow(self, t): return self._c(t, "33")
    def blue(self, t):   return self._c(t, "34")
    def cyan(self, t):   return self._c(t, "36")
    def magenta(self, t): return self._c(t, "35")

    def step(self, msg: str):
        if not self.quiet:
            print(f"\n{self.cyan('▸')} {self.bold(msg)}")

    def info(self, msg: str):
        if not self.quiet:
            print(f"  {msg}")

    def good(self, msg: str):
        if not self.quiet:
            print(f"  {self.green('✔')} {msg}")

    def warn(self, msg: str):
        if not self.quiet:
            print(f"  {self.yellow('⚠')} {msg}")

    def bad(self, msg: str):
        if not self.quiet:
            print(f"  {self.red('✗')} {msg}")

    def hit(self, msg: str):
        if not self.quiet:
            print(f"  {self.magenta('★')} {msg}")

    def vinfo(self, msg: str):
        if self.verbose and not self.quiet:
            print(f"    {self.dim(msg)}")

    def err(self, msg: str):
        print(f"{self.red('error:')} {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class Candidate:
    ip: str
    sources: set[str] = field(default_factory=set)
    ptr: str | None = None
    org: str | None = None
    asn: str | None = None
    is_cdn: bool = False
    cdn_name: str | None = None
    verified: bool = False
    confidence: int = 0          # 0-100 origin-match confidence
    verify_detail: str = ""
    version: int = 4             # 4 or 6

    def to_dict(self) -> dict:
        d = asdict(self)
        d["sources"] = sorted(self.sources)
        return d


class Registry:
    """Collects and de-duplicates candidate IPs across all sources."""

    def __init__(self):
        self._by_ip: dict[str, Candidate] = {}

    def add(self, ip: str, source: str) -> Candidate | None:
        ip = (ip or "").strip()
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError:
            return None
        # Skip useless addresses.
        if parsed.is_loopback or parsed.is_unspecified or parsed.is_multicast:
            return None
        c = self._by_ip.get(ip)
        if c is None:
            c = Candidate(ip=ip, version=parsed.version)
            self._by_ip[ip] = c
        c.sources.add(source)
        return c

    def all(self) -> list[Candidate]:
        return list(self._by_ip.values())

    def get(self, ip: str) -> Candidate | None:
        return self._by_ip.get(ip)


# ---------------------------------------------------------------------------
# Domain validation / normalization
# ---------------------------------------------------------------------------

_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
_DOMAIN_RE = re.compile(rf"^(?:{_LABEL}\.)+[A-Za-z]{{2,63}}$")


def normalize_domain(raw: str) -> str:
    """Strip scheme/path/port/creds and validate a hostname. Raises ValueError."""
    if not raw:
        raise ValueError("empty domain")
    d = raw.strip()
    d = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", d)  # scheme
    d = d.split("/")[0]                                  # path
    d = d.split("@")[-1]                                 # userinfo
    d = d.split("?")[0].split("#")[0]
    if d.startswith("[") and "]" in d:                   # bracketed IPv6 (reject)
        raise ValueError("expected a domain, not an IP literal")
    d = d.split(":")[0]                                  # port
    d = d.rstrip(".").lower()
    try:
        d = d.encode("idna").decode("ascii")            # IDN -> punycode
    except Exception:
        pass
    if not _DOMAIN_RE.match(d):
        raise ValueError(f"'{raw}' does not look like a valid domain name")
    return d


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------


class Dns:
    def __init__(self, console: Console, timeout: float = 5.0,
                 nameservers: list[str] | None = None):
        self.con = console
        self.resolver = dns.resolver.Resolver(configure=True)
        self.resolver.lifetime = timeout
        self.resolver.timeout = timeout
        if nameservers:
            self.resolver.nameservers = nameservers

    def query(self, name: str, rtype: str) -> list:
        try:
            return list(self.resolver.resolve(name, rtype))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, dns.exception.DNSException):
            return []
        except Exception:
            return []

    def resolve_host(self, name: str) -> list[str]:
        """A + AAAA records for a hostname -> list of IP strings."""
        ips: list[str] = []
        for rec in self.query(name, "A"):
            ips.append(rec.address)
        for rec in self.query(name, "AAAA"):
            ips.append(rec.address)
        return ips


# ---------------------------------------------------------------------------
# CDN / WAF range detection
# ---------------------------------------------------------------------------

# Static fallback ranges for the most common providers. Cloudflare ranges are
# refreshed live from cloudflare.com when the network allows it.
STATIC_CDN_RANGES: dict[str, list[str]] = {
    "Cloudflare": [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
        "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
        "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
        "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
        "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29",
        "2c0f:f248::/32",
    ],
    "Akamai": [
        "23.32.0.0/11", "23.0.0.0/12", "104.64.0.0/10", "184.24.0.0/13",
        "2.16.0.0/13", "88.221.0.0/16", "95.100.0.0/15", "96.16.0.0/15",
        "72.246.0.0/15", "173.222.0.0/15", "184.50.0.0/15", "184.84.0.0/14",
    ],
    "Fastly": [
        "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24",
        "103.245.222.0/23", "103.245.224.0/24", "104.156.80.0/20",
        "140.248.64.0/18", "140.248.128.0/17", "146.75.0.0/17",
        "151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17",
        "185.31.16.0/22", "199.27.72.0/21", "199.232.0.0/16",
    ],
    "Amazon CloudFront": [
        "13.32.0.0/15", "13.35.0.0/16", "18.64.0.0/14", "52.46.0.0/18",
        "52.84.0.0/15", "54.182.0.0/16", "54.192.0.0/16", "54.230.0.0/16",
        "54.239.128.0/18", "99.84.0.0/16", "205.251.192.0/19", "120.52.22.96/27",
    ],
    "Sucuri": [
        "192.88.134.0/23", "185.93.228.0/22", "66.248.200.0/22",
        "208.109.0.0/22",
    ],
    "Imperva/Incapsula": [
        "199.83.128.0/21", "198.143.32.0/19", "149.126.72.0/21",
        "103.28.248.0/22", "45.64.64.0/22", "185.11.124.0/22",
        "192.230.64.0/18", "45.60.0.0/16", "45.223.0.0/16", "107.154.0.0/16",
    ],
    "StackPath/Highwinds": [
        "151.139.0.0/19", "205.185.192.0/18", "192.16.0.0/16",
    ],
    "Google": [
        "34.64.0.0/10", "35.184.0.0/13", "35.192.0.0/14", "35.196.0.0/15",
        "130.211.0.0/22", "35.191.0.0/16", "108.170.192.0/18",
    ],
}


class CdnClassifier:
    def __init__(self, console: Console, offline: bool = False):
        self.con = console
        self.networks: list[tuple[ipaddress._BaseNetwork, str]] = []
        for name, cidrs in STATIC_CDN_RANGES.items():
            for cidr in cidrs:
                try:
                    self.networks.append((ipaddress.ip_network(cidr), name))
                except ValueError:
                    pass
        if not offline:
            self._refresh_cloudflare()

    def _refresh_cloudflare(self):
        for url in ("https://www.cloudflare.com/ips-v4",
                    "https://www.cloudflare.com/ips-v6"):
            try:
                r = requests.get(url, timeout=8)
                if r.status_code == 200:
                    added = 0
                    for line in r.text.splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            self.networks.append(
                                (ipaddress.ip_network(line), "Cloudflare"))
                            added += 1
                        except ValueError:
                            pass
                    self.con.vinfo(f"loaded {added} live Cloudflare ranges "
                                   f"from {url}")
            except Exception:
                self.con.vinfo(f"could not refresh Cloudflare ranges from {url}")

    def classify(self, ip: str) -> tuple[bool, str | None]:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False, None
        for net, name in self.networks:
            if addr.version == net.version and addr in net:
                return True, name
        return False, None


# ---------------------------------------------------------------------------
# Source: SPF / TXT parsing
# ---------------------------------------------------------------------------


def parse_spf(dnsc: Dns, domain: str, reg: Registry, con: Console,
              _depth: int = 0, _seen: set[str] | None = None):
    """Recursively parse SPF records; collect ip4/ip6 and resolve a:/mx:/include."""
    if _seen is None:
        _seen = set()
    if _depth > 5 or domain in _seen:
        return
    _seen.add(domain)

    for rec in dnsc.query(domain, "TXT"):
        txt = "".join(
            s.decode() if isinstance(s, bytes) else str(s)
            for s in getattr(rec, "strings", [str(rec)])
        )
        if "v=spf1" not in txt.lower():
            continue
        con.vinfo(f"SPF({domain}): {txt}")
        for token in txt.split():
            token = token.strip()
            low = token.lower()
            if low.startswith("ip4:") or low.startswith("ip6:"):
                val = token.split(":", 1)[1]
                try:
                    net = ipaddress.ip_network(val, strict=False)
                except ValueError:
                    continue
                # Only enumerate small nets; add the base for large ones.
                if net.num_addresses <= 256:
                    for host in net.hosts():
                        reg.add(str(host), "spf")
                else:
                    reg.add(str(net.network_address), "spf")
            elif low.startswith("a:"):
                host = token.split(":", 1)[1].split("/")[0]
                for ip in dnsc.resolve_host(host):
                    reg.add(ip, "spf")
            elif low.startswith("mx:"):
                host = token.split(":", 1)[1]
                for mx in dnsc.query(host, "MX"):
                    for ip in dnsc.resolve_host(str(mx.exchange).rstrip(".")):
                        reg.add(ip, "spf")
            elif low.startswith("include:") or low.startswith("redirect="):
                sep = ":" if ":" in token else "="
                inc = token.split(sep, 1)[1]
                parse_spf(dnsc, inc, reg, con, _depth + 1, _seen)


# ---------------------------------------------------------------------------
# Source: Certificate Transparency (crt.sh)
# ---------------------------------------------------------------------------


def crtsh_subdomains(domain: str, con: Console, timeout: float = 20.0) -> set[str]:
    subs: set[str] = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    for attempt in range(2):
        try:
            r = requests.get(url, timeout=timeout,
                             headers={"User-Agent": DEFAULT_UA})
            if r.status_code != 200 or not r.text.strip():
                con.vinfo(f"crt.sh returned status {r.status_code}")
                time.sleep(1.5)
                continue
            data = r.json()
            for entry in data:
                name = entry.get("name_value", "")
                for line in name.splitlines():
                    line = line.strip().lstrip("*.").lower()
                    if line.endswith(domain) and _DOMAIN_RE.match(line):
                        subs.add(line)
            break
        except json.JSONDecodeError:
            con.vinfo("crt.sh returned non-JSON output")
            break
        except Exception as e:
            con.vinfo(f"crt.sh attempt {attempt + 1} failed: {e}")
            time.sleep(1.5)
    return subs


# ---------------------------------------------------------------------------
# Source: subdomain brute force
# ---------------------------------------------------------------------------


def load_wordlist(path: str | None, con: Console) -> list[str]:
    """Load a subdomain wordlist; fall back to the bundled list, then embedded."""
    candidates: list[str] = []
    search = []
    if path:
        search.append(path)
    here = os.path.dirname(os.path.abspath(__file__))
    search.append(os.path.join(here, "wordlists", "subdomains.txt"))

    for p in search:
        if p and os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            candidates.append(line.lower())
                con.vinfo(f"loaded {len(candidates)} words from {p}")
                return sorted(set(candidates))
            except Exception as e:
                con.vinfo(f"could not read wordlist {p}: {e}")

    embedded = [
        "www", "mail", "webmail", "smtp", "pop", "imap", "ns1", "ns2", "ftp",
        "cpanel", "whm", "webdisk", "admin", "panel", "direct", "direct-connect",
        "origin", "dev", "staging", "test", "qa", "beta", "api", "app", "portal",
        "vpn", "remote", "gateway", "secure", "internal", "intranet", "blog",
        "shop", "store", "git", "gitlab", "jenkins", "ci", "db", "sql", "mysql",
        "backup", "old", "new", "mobile", "m", "cdn", "static", "assets", "media",
        "support", "help", "status", "monitor", "grafana", "kibana",
    ]
    con.vinfo(f"using embedded wordlist ({len(embedded)} words)")
    return embedded


def detect_wildcard(dnsc: Dns, domain: str, con: Console) -> set[str]:
    """Return the set of IPs a wildcard record resolves to (empty if none).

    Probes several random labels that should never exist; any IP returned is
    a wildcard/catch-all answer that would otherwise poison brute results."""
    import random
    import string
    wildcard_ips: set[str] = set()
    for _ in range(3):
        label = "".join(random.choices(string.ascii_lowercase + string.digits, k=18))
        for ip in dnsc.resolve_host(f"{label}.{domain}"):
            wildcard_ips.add(ip)
    if wildcard_ips:
        con.warn(f"wildcard DNS detected ({', '.join(sorted(wildcard_ips))}); "
                 "brute hits matching only these are ignored")
    return wildcard_ips


def brute_subdomains(dnsc: Dns, domain: str, words: list[str], reg: Registry,
                     con: Console, threads: int) -> list[str]:
    """Resolve <word>.<domain> concurrently; register found IPs.

    Wildcard answers are filtered so a catch-all record does not create a
    fake hit for every word in the list."""
    found_hosts: list[str] = []
    wildcard_ips = detect_wildcard(dnsc, domain, con)
    hosts = [f"{w}.{domain}" for w in words]

    def _resolve(host: str) -> tuple[str, list[str]]:
        return host, dnsc.resolve_host(host)

    with futures.ThreadPoolExecutor(max_workers=threads) as ex:
        for host, ips in ex.map(_resolve, hosts):
            if not ips:
                continue
            real_ips = [ip for ip in ips if ip not in wildcard_ips]
            if not real_ips:
                con.vinfo(f"{host} -> wildcard only, ignored")
                continue
            found_hosts.append(host)
            for ip in real_ips:
                reg.add(ip, "subdomain")
            con.good(f"{host} -> {', '.join(real_ips)}")
    return found_hosts


def resolve_hosts_concurrent(dnsc: Dns, hosts: Iterable[str], reg: Registry,
                             source: str, con: Console, threads: int):
    hosts = list(dict.fromkeys(hosts))
    if not hosts:
        return

    def _resolve(host: str) -> tuple[str, list[str]]:
        return host, dnsc.resolve_host(host)

    with futures.ThreadPoolExecutor(max_workers=threads) as ex:
        for host, ips in ex.map(_resolve, hosts):
            for ip in ips:
                reg.add(ip, source)
            if ips:
                con.vinfo(f"{host} -> {', '.join(ips)}")


# ---------------------------------------------------------------------------
# Source: HTTP headers (leak inspection + baseline capture)
# ---------------------------------------------------------------------------

LEAK_HEADERS = {
    "x-real-ip", "x-originating-ip", "x-forwarded-for", "x-backend-server",
    "x-backend", "x-served-by", "x-host", "x-origin-server", "x-served-ip",
    "true-client-ip", "x-client-ip", "x-cache-key",
}


def inspect_headers(domain: str, reg: Registry, con: Console, timeout: float):
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            r = requests.get(url, timeout=timeout, allow_redirects=True,
                             headers={"User-Agent": DEFAULT_UA}, verify=False)
        except requests.exceptions.RequestException as e:
            con.warn(f"{url} unreachable ({type(e).__name__})")
            continue
        server = r.headers.get("Server", "?")
        con.good(f"{url} (status {r.status_code}, Server: {server})")
        for key, value in r.headers.items():
            if key.lower() in LEAK_HEADERS:
                con.hit(f"leak header {key}: {value}")
                for ip in re.findall(r"\d{1,3}(?:\.\d{1,3}){3}", value):
                    reg.add(ip, "http-header")


# ---------------------------------------------------------------------------
# Source: Shodan
# ---------------------------------------------------------------------------


def shodan_search(domain: str, api_key: str | None, favicon: str | None,
                  reg: Registry, con: Console):
    if not _HAVE_SHODAN:
        con.warn("shodan library not installed; skipping Shodan pivots")
        return
    if not api_key:
        con.warn("no Shodan API key (use --shodan-key or SHODAN_API_KEY); skipping")
        return
    try:
        api = shodan.Shodan(api_key)
        queries = [f"hostname:{domain}", f"ssl.cert.subject.cn:{domain}",
                   f"ssl:{domain}"]
        if favicon:
            queries.append(f"http.favicon.hash:{favicon}")
        seen = set()
        for q in queries:
            try:
                results = api.search(q, limit=100)
            except shodan.APIError as e:
                con.vinfo(f"Shodan query '{q}' failed: {e}")
                continue
            for match in results.get("matches", []):
                ip = match.get("ip_str")
                if not ip or ip in seen:
                    continue
                seen.add(ip)
                reg.add(ip, "shodan")
                con.hit(f"Shodan: {ip} :{match.get('port')} "
                        f"({match.get('org', 'N/A')}) via '{q}'")
    except shodan.APIError as e:
        con.bad(f"Shodan API error: {e}")


# ---------------------------------------------------------------------------
# Favicon hash (Shodan-compatible mmh3)
# ---------------------------------------------------------------------------


def favicon_hash(domain: str, con: Console, timeout: float) -> str | None:
    if not _HAVE_MMH3:
        con.vinfo("mmh3 not installed; skipping favicon-hash pivot")
        return None
    import base64
    for url in (f"https://{domain}/favicon.ico", f"http://{domain}/favicon.ico"):
        try:
            r = requests.get(url, timeout=timeout,
                             headers={"User-Agent": DEFAULT_UA}, verify=False)
            if r.status_code == 200 and r.content:
                b64 = base64.encodebytes(r.content)
                h = mmh3.hash(b64)
                con.vinfo(f"favicon hash = {h}")
                return str(h)
        except requests.exceptions.RequestException:
            continue
    return None


# ---------------------------------------------------------------------------
# Origin verification
# ---------------------------------------------------------------------------


@dataclass
class Baseline:
    ok: bool = False
    scheme: str = "https"
    status: int = 0
    title: str | None = None
    length: int = 0
    body: str = ""
    cert_names: set[str] = field(default_factory=set)


_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def _extract_title(html: str) -> str | None:
    m = _TITLE_RE.search(html)
    if not m:
        return None
    return re.sub(r"\s+", " ", m.group(1)).strip() or None


def get_baseline(domain: str, con: Console, timeout: float) -> Baseline:
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}/"
        try:
            r = requests.get(url, timeout=timeout, allow_redirects=True,
                             headers={"User-Agent": DEFAULT_UA}, verify=False)
        except requests.exceptions.RequestException:
            continue
        body = r.text or ""
        bl = Baseline(ok=True, scheme=scheme, status=r.status_code,
                      title=_extract_title(body), length=len(body),
                      body=body[:20000])
        bl.cert_names = cert_names_for_host(domain, 443, timeout)
        con.vinfo(f"baseline via {scheme}: status={bl.status} "
                  f"title={bl.title!r} len={bl.length}")
        return bl
    return Baseline(ok=False)


def cert_names_for_host(host: str, port: int, timeout: float,
                        connect_ip: str | None = None) -> set[str]:
    """Return CN + SANs from the TLS certificate. connect_ip overrides the
    connection target while keeping SNI=host (for probing a candidate IP)."""
    names: set[str] = set()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    target = connect_ip or host
    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                bin_cert = ss.getpeercert(binary_form=True)
    except Exception:
        return names
    if cert:
        for tup in cert.get("subject", ()):
            for k, v in tup:
                if k == "commonName":
                    names.add(v.lower())
        for typ, val in cert.get("subjectAltName", ()):
            if typ == "DNS":
                names.add(val.lower())
    if not names and bin_cert:
        # Fallback: scrape DNS names out of the DER blob.
        for m in re.findall(rb"[a-z0-9\.\-\*]+\.[a-z]{2,}", bin_cert.lower()):
            try:
                names.add(m.decode())
            except Exception:
                pass
    return names


def _cert_covers(names: set[str], domain: str) -> bool:
    for n in names:
        if n == domain:
            return True
        if n.startswith("*.") and domain.endswith(n[1:]):
            return True
    return False


def _similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    from difflib import SequenceMatcher
    return SequenceMatcher(None, a, b).quick_ratio()


def verify_origin(cand: Candidate, domain: str, baseline: Baseline,
                  con: Console, timeout: float) -> None:
    """Probe a candidate IP directly (SNI+Host=domain) and score the match."""
    if not baseline.ok:
        return
    port = 443 if baseline.scheme == "https" else 80
    body = ""
    status = 0
    got = False
    try:
        if baseline.scheme == "https":
            pool = urllib3.HTTPSConnectionPool(
                cand.ip, port=port, cert_reqs="CERT_NONE",
                assert_hostname=False, server_hostname=domain,
                timeout=urllib3.Timeout(connect=timeout, read=timeout),
                retries=False,
            )
        else:
            pool = urllib3.HTTPConnectionPool(
                cand.ip, port=port,
                timeout=urllib3.Timeout(connect=timeout, read=timeout),
                retries=False,
            )
        resp = pool.request("GET", "/", headers={"Host": domain,
                            "User-Agent": DEFAULT_UA}, redirect=False,
                            preload_content=True)
        status = resp.status
        body = resp.data.decode("utf-8", "ignore")
        got = True
    except Exception as e:
        con.vinfo(f"{cand.ip}: direct probe failed ({type(e).__name__})")

    score = 0
    reasons: list[str] = []

    # Certificate SAN match (strong).
    if baseline.scheme == "https":
        cnames = cert_names_for_host(domain, port, timeout, connect_ip=cand.ip)
        if _cert_covers(cnames, domain):
            score += 55
            reasons.append("cert covers domain")

    if got:
        title = _extract_title(body)
        if baseline.title and title and title == baseline.title:
            score += 45
            reasons.append("title match")
        ratio = _similarity(baseline.body, body[:20000])
        if ratio >= 0.90:
            score += 45
            reasons.append(f"body {int(ratio*100)}% match")
        elif ratio >= 0.60:
            score += 20
            reasons.append(f"body {int(ratio*100)}% match")
        if status and status == baseline.status:
            score += 5
            reasons.append(f"status {status}")

    cand.confidence = min(score, 100)
    cand.verify_detail = ", ".join(reasons) if reasons else "no match"
    cand.verified = cand.confidence >= 60
    if cand.verified:
        con.hit(f"ORIGIN MATCH {cand.ip} "
                f"(confidence {cand.confidence}%: {cand.verify_detail})")
    elif cand.confidence > 0:
        con.vinfo(f"{cand.ip}: partial ({cand.confidence}%: {cand.verify_detail})")


# ---------------------------------------------------------------------------
# Enrichment: reverse DNS + WHOIS/ASN
# ---------------------------------------------------------------------------


def enrich(cand: Candidate, timeout: float, whois: bool = True):
    try:
        cand.ptr = socket.gethostbyaddr(cand.ip)[0]
    except Exception:
        cand.ptr = None
    if not whois:
        return
    try:
        addr = ipaddress.ip_address(cand.ip)
        if addr.is_private:
            cand.org = "Private / RFC1918"
            return
        obj = IPWhois(cand.ip)
        res = obj.lookup_rdap(depth=1)
        cand.asn = res.get("asn")
        cand.org = (res.get("asn_description")
                    or res.get("network", {}).get("name") or "N/A")
    except Exception as e:
        cand.org = f"whois failed ({type(e).__name__})"


def enrich_all(cands: list[Candidate], con: Console, timeout: float, threads: int,
               whois: bool = True):
    with futures.ThreadPoolExecutor(max_workers=min(threads, 16)) as ex:
        list(ex.map(lambda c: enrich(c, timeout, whois), cands))


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def run(args, domain: str, cdn: "CdnClassifier", con: "Console") -> dict:
    started = time.time()

    reg = Registry()
    dnsc = Dns(con, timeout=args.dns_timeout,
               nameservers=args.resolver.split(",") if args.resolver else None)

    if not args.quiet:
        print(con.bold(f"\n╔══ Void Finder v{VERSION} ══╗"))
        print(con.dim(f"  target: {domain}   started: "
                      f"{time.strftime('%Y-%m-%d %H:%M:%S')}"))

    # --- Step 1: base + DNS records ---
    con.step("[1] Base DNS records (A / AAAA / MX / NS / TXT-SPF)")
    base_ips: set[str] = set()
    for ip in dnsc.resolve_host(domain):
        base_ips.add(ip)
        reg.add(ip, "base")
    if base_ips:
        con.good(f"apex {domain}: {', '.join(sorted(base_ips))}")
    else:
        con.warn(f"no A/AAAA records for apex {domain}")

    # MX (null-MX safe).
    mx_hosts = []
    for mx in dnsc.query(domain, "MX"):
        host = str(mx.exchange).rstrip(".")
        if host and host != "." and _DOMAIN_RE.match(host):
            mx_hosts.append(host)
    if mx_hosts:
        con.info(f"MX: {', '.join(mx_hosts)}")
        resolve_hosts_concurrent(dnsc, mx_hosts, reg, "mx", con, args.threads)
    else:
        con.info("no usable MX records")

    # NS.
    ns_hosts = [str(ns.target).rstrip(".") for ns in dnsc.query(domain, "NS")]
    ns_hosts = [h for h in ns_hosts if h and _DOMAIN_RE.match(h)]
    if ns_hosts:
        con.info(f"NS: {', '.join(ns_hosts)}")
        resolve_hosts_concurrent(dnsc, ns_hosts, reg, "ns", con, args.threads)

    # SPF / TXT.
    parse_spf(dnsc, domain, reg, con)

    # --- Step 2: HTTP header leak inspection ---
    if not args.offline:
        con.step("[2] HTTP header inspection")
        inspect_headers(domain, reg, con, args.http_timeout)
    else:
        con.step("[2] HTTP header inspection (skipped: offline)")

    # --- Step 3: Certificate Transparency (crt.sh) ---
    ct_hosts: set[str] = set()
    if not args.offline and not args.no_ct:
        con.step("[3] Certificate Transparency (crt.sh)")
        ct_hosts = crtsh_subdomains(domain, con, timeout=args.http_timeout * 3)
        con.good(f"crt.sh returned {len(ct_hosts)} unique names")
        resolve_hosts_concurrent(dnsc, ct_hosts, reg, "crt.sh", con, args.threads)
    else:
        con.step("[3] Certificate Transparency (skipped)")

    # --- Step 4: subdomain brute force ---
    if not args.no_brute:
        words = load_wordlist(args.wordlist, con)
        con.step(f"[4] Subdomain brute force ({len(words)} words, "
                 f"{args.threads} threads)")
        brute_subdomains(dnsc, domain, words, reg, con, args.threads)
    else:
        con.step("[4] Subdomain brute force (skipped)")

    # --- Step 5: favicon + Shodan ---
    con.step("[5] Shodan pivots")
    fhash = None
    if not args.offline:
        fhash = favicon_hash(domain, con, args.http_timeout)
    key = args.shodan_key or os.environ.get("SHODAN_API_KEY")
    if args.offline:
        con.warn("offline mode; skipping Shodan")
    else:
        shodan_search(domain, key, fhash, reg, con)

    # --- Classify + enrich ---
    con.step("[6] Classification + WHOIS/ASN enrichment")
    cands = reg.all()
    for c in cands:
        c.is_cdn, c.cdn_name = cdn.classify(c.ip)
    enrich_all(cands, con, args.http_timeout, args.threads, whois=not args.offline)
    con.good(f"{len(cands)} unique IPs collected "
             f"({sum(1 for c in cands if c.is_cdn)} CDN / "
             f"{sum(1 for c in cands if not c.is_cdn)} non-CDN)")

    # --- Origin verification (non-CDN, non-base first) ---
    baseline = None
    if not args.no_verify and not args.offline:
        con.step("[7] Active origin verification")
        baseline = get_baseline(domain, con, args.http_timeout)
        if not baseline.ok:
            con.warn("could not fetch a baseline; skipping verification")
        else:
            targets = [c for c in cands
                       if not c.is_cdn and c.ip not in base_ips]
            if args.verify_all:
                targets = [c for c in cands if not c.is_cdn]
            if not targets:
                con.info("no non-CDN candidates to verify")
            for c in targets:
                verify_origin(c, domain, baseline, con, args.http_timeout)
    else:
        con.step("[7] Active origin verification (skipped)")

    elapsed = round(time.time() - started, 1)
    result = build_result(domain, cands, base_ips, elapsed, fhash)
    if not getattr(args, "json", False):
        report(con, result, cands, base_ips)
    return result


def build_result(domain, cands, base_ips, elapsed, fhash) -> dict:
    confirmed = sorted([c for c in cands if c.verified],
                       key=lambda c: -c.confidence)
    return {
        "tool": "void_finder",
        "version": VERSION,
        "target": domain,
        "elapsed_seconds": elapsed,
        "favicon_hash": fhash,
        "base_ips": sorted(base_ips),
        "total_candidates": len(cands),
        "confirmed_origins": [c.to_dict() for c in confirmed],
        "candidates": [c.to_dict() for c in sorted(
            cands, key=lambda c: (c.is_cdn, -c.confidence, c.ip))],
    }


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def report(con: Console, result: dict, cands: list[Candidate], base_ips: set):
    line = "═" * 64
    print(f"\n{con.bold(line)}")
    print(con.bold(f"  VOID FINDER REPORT — {result['target']}"))
    print(con.dim(f"  {result['total_candidates']} candidate IPs in "
                  f"{result['elapsed_seconds']}s"))
    print(con.bold(line))

    confirmed = [c for c in cands if c.verified]
    if confirmed:
        print(f"\n{con.green(con.bold('★ CONFIRMED ORIGIN CANDIDATES'))}")
        for c in sorted(confirmed, key=lambda x: -x.confidence):
            print(f"  {con.green(con.bold(c.ip)):<28} "
                  f"{con.bold(str(c.confidence) + '%')}  "
                  f"{c.org or '?'}")
            print(con.dim(f"      {c.verify_detail}  "
                          f"[{', '.join(sorted(c.sources))}]"
                          + (f"  ptr={c.ptr}" if c.ptr else "")))
    else:
        print(f"\n{con.yellow('No origin confirmed.')} "
              "The site appears well-hidden, or origin access is filtered.")

    # CDN / public-facing.
    cdn_ips = [c for c in cands if c.is_cdn]
    if cdn_ips:
        print(f"\n{con.blue('CDN / WAF / public-facing IPs')}")
        for c in sorted(cdn_ips, key=lambda x: x.ip):
            print(f"  {c.ip:<40} {con.dim(c.cdn_name or 'CDN')}  "
                  f"{con.dim('[' + ', '.join(sorted(c.sources)) + ']')}")

    # Other non-CDN candidates that were not confirmed.
    others = [c for c in cands if not c.is_cdn and not c.verified]
    if others:
        print(f"\n{con.yellow('Other non-CDN candidates (unconfirmed — investigate)')}")
        for c in sorted(others, key=lambda x: (-x.confidence, x.ip)):
            tag = f"{c.confidence}%" if c.confidence else "—"
            print(f"  {c.ip:<24} {tag:<5} {c.org or '?'}")
            print(con.dim(f"      [{', '.join(sorted(c.sources))}]"
                          + (f"  ptr={c.ptr}" if c.ptr else "")))
    print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="void_finder.py",
        description="Void Finder - discover the origin IP behind a CDN/proxy.",
        epilog="For authorized security assessment and educational use only.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("domain", nargs="*",
                   help="One or more target domains, e.g. example.com")
    p.add_argument("--targets", metavar="FILE",
                   help="File with one target domain per line (# comments ok)")
    p.add_argument("-o", "--output", metavar="FILE",
                   help="Write full results as JSON to FILE")
    p.add_argument("--csv", metavar="FILE",
                   help="Write candidate rows as CSV to FILE")
    p.add_argument("--json", action="store_true",
                   help="Print JSON results to stdout (implies --quiet console)")
    p.add_argument("-w", "--wordlist", metavar="FILE",
                   help="Custom subdomain wordlist (defaults to bundled list)")
    p.add_argument("-t", "--threads", type=int, default=40,
                   help="Concurrent DNS/probe workers")
    p.add_argument("--dns-timeout", type=float, default=5.0,
                   help="Per-query DNS timeout (seconds)")
    p.add_argument("--http-timeout", type=float, default=8.0,
                   help="HTTP/probe timeout (seconds)")
    p.add_argument("--resolver", metavar="IP[,IP]",
                   help="Custom DNS resolver(s), comma-separated")
    p.add_argument("--shodan-key", metavar="KEY",
                   help="Shodan API key (or set SHODAN_API_KEY)")
    p.add_argument("--no-ct", action="store_true",
                   help="Skip Certificate Transparency (crt.sh)")
    p.add_argument("--no-brute", action="store_true",
                   help="Skip subdomain brute force")
    p.add_argument("--no-verify", action="store_true",
                   help="Skip active origin verification")
    p.add_argument("--verify-all", action="store_true",
                   help="Verify all non-CDN IPs (including apex IPs)")
    p.add_argument("--offline", action="store_true",
                   help="Disable all outbound HTTP (DNS only)")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI color")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="Only print the final report")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Verbose progress output")
    p.add_argument("-V", "--version", action="version",
                   version=f"Void Finder {VERSION}")
    return p


def _collect_targets(args, con: Console) -> list[str]:
    """Gather + validate targets from positional args and/or --targets file."""
    raw: list[str] = list(args.domain or [])
    if args.targets:
        try:
            with open(args.targets, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        raw.append(line)
        except OSError as e:
            con.err(f"could not read targets file {args.targets}: {e}")

    targets: list[str] = []
    seen: set[str] = set()
    for item in raw:
        try:
            d = normalize_domain(item)
        except ValueError as e:
            con.err(str(e))
            continue
        if d not in seen:
            seen.add(d)
            targets.append(d)
    return targets


def write_csv(path: str, results: list[dict], con: Console):
    import csv
    try:
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["target", "ip", "version", "is_cdn", "cdn_name",
                        "confirmed", "confidence", "sources", "ptr", "org",
                        "asn", "verify_detail"])
            for res in results:
                for c in res.get("candidates", []):
                    w.writerow([
                        res.get("target", ""), c["ip"], c["version"],
                        c["is_cdn"], c.get("cdn_name") or "", c["verified"],
                        c["confidence"], "|".join(c["sources"]),
                        c.get("ptr") or "", c.get("org") or "",
                        c.get("asn") or "", c.get("verify_detail") or "",
                    ])
        if not con.quiet:
            print(f"CSV written to {path}")
    except OSError as e:
        con.err(f"could not write {path}: {e}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.json:
        args.quiet = True

    con = Console(quiet=args.quiet, verbose=args.verbose,
                  use_color=False if args.no_color else None)

    targets = _collect_targets(args, con)
    if not targets:
        con.err("no valid target domain supplied (pass a domain or --targets FILE)")
        return 2

    # One CDN classifier shared across all targets (fetch ranges once).
    cdn = CdnClassifier(con, offline=args.offline)

    results: list[dict] = []
    exit_code = 0
    for i, domain in enumerate(targets):
        if len(targets) > 1 and not args.quiet:
            print(con.magenta(con.bold(
                f"\n########## target {i + 1}/{len(targets)}: {domain} ##########")))
        try:
            results.append(run(args, domain, cdn, con))
        except KeyboardInterrupt:
            print("\nInterrupted by user.", file=sys.stderr)
            return 130
        except Exception as e:
            con.err(f"[{domain}] unexpected failure: {type(e).__name__}: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            exit_code = 1

    if not results:
        return exit_code or 1

    # JSON payload: single object for one target, list for many.
    payload = results[0] if len(results) == 1 else {
        "tool": "void_finder", "version": VERSION, "results": results}

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2)
            if not args.quiet:
                print(f"Results written to {args.output}")
        except OSError as e:
            con.err(f"could not write {args.output}: {e}")

    if args.csv:
        write_csv(args.csv, results, con)

    if args.json:
        print(json.dumps(payload, indent=2))

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
