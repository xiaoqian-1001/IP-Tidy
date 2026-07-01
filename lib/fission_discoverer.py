import socket
import re
import time
import concurrent.futures
from typing import Optional
import urllib.request
import urllib.error


REVERSE_SOURCES = [
    "https://site.ip138.com/{ip}",
    "https://dnsdblookup.com/?ip={ip}",
    "https://ipchaxun.com/{ip}",
]
LOOKUP_TIMEOUT = 15
DNS_TIMEOUT = 10
BACKOFF_BASE = 1.0
MAX_BACKOFF = 8.0


def _reverse_lookup(ip: str, timeout: int = LOOKUP_TIMEOUT) -> list[str]:
    domains: set[str] = set()
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    for attempt, template in enumerate(REVERSE_SOURCES):
        try:
            url = template.format(ip=ip)
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                html = resp.read().decode("utf-8", errors="replace")
            found = re.findall(r'(?:https?://)?([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}', html)
            for d in found:
                d = d.lower().strip()
                if d.count(".") >= 1 and not d.startswith("www."):
                    # 过滤纯数字标签的伪域名（如 123.456.789.abc）
                    if not re.match(r'^\d+(?:\.\d+)+$', d):
                        domains.add(d)
            if domains:
                break
        except (urllib.error.URLError, urllib.error.HTTPError, OSError):
            backoff = min(BACKOFF_BASE * (2 ** attempt), MAX_BACKOFF)
            time.sleep(backoff)
            continue
    return list(domains)


def _resolve_domains(domains: list[str], timeout: int = DNS_TIMEOUT) -> list[str]:
    ips: set[str] = set()
    orig_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        for d in domains:
            try:
                infos = socket.getaddrinfo(d, 443, socket.AF_INET, socket.SOCK_STREAM)
                for info in infos:
                    ip = info[4][0]
                    if ip and not ip.startswith("127.") and not ip.startswith("10.") and not ip.startswith("192.168.") and not ip.startswith("172.16."):
                        ips.add(ip)
            except (socket.gaierror, OSError):
                continue
    finally:
        socket.setdefaulttimeout(orig_timeout)
    return list(ips)


def fission_discover(
    seed_ips: list[str],
    max_depth: int = 2,
    max_ips: int = 1000,
    concurrency: int = 20,
) -> list[str]:
    discovered: set[str] = set(seed_ips)
    current_round: set[str] = set(seed_ips)

    for depth in range(max_depth):
        if len(discovered) >= max_ips:
            break

        round_ips = list(current_round)[:max_ips - len(discovered)]
        if not round_ips:
            break

        all_domains: list[str] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
            futs = {executor.submit(_reverse_lookup, ip): ip for ip in round_ips}
            for f in concurrent.futures.as_completed(futs):
                try:
                    all_domains.extend(f.result())
                except (OSError, socket.gaierror):
                    pass

        if not all_domains:
            break

        new_ips = _resolve_domains(list(set(all_domains)))
        added = 0
        for ip in new_ips:
            if ip not in discovered:
                discovered.add(ip)
                added += 1

        if added == 0:
            break
        current_round = set(new_ips)

    return [ip for ip in discovered if ip not in set(seed_ips)]