#!/usr/bin/env python3
"""
API 精筛 -- CF 反代节点二次验证
用法: python3 verify.py --input cf_hits.txt --output verified.txt [--api URL] [--chunk N] [--concurrent N]
"""

import argparse
import json
import os
import sys
import time
import threading
import random
import string
import ssl
import socket
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional

from lib.utils import write_progress, write_progress_done
from lib.scanner_utils import CSV_HEADER

MAX_RETRIES = 2
RETRY_CODES = frozenset({429, 502, 503, 504})

_write_lock = threading.Lock()


def _check_honeypot(ip: str, port: int, timeout: float = 5.0) -> bool:
    """用随机垃圾 SNI 握手，若仍返回 CF 头 → 蜜罐"""
    random_sni = "".join(random.choices(string.ascii_lowercase, k=10)) + ".org"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        with ctx.wrap_socket(sock, server_hostname=random_sni) as ssock:
            ssock.settimeout(timeout)
            req = f"GET / HTTP/1.1\r\nHost: {random_sni}\r\nConnection: close\r\n\r\n"
            ssock.sendall(req.encode())
            resp = ssock.read(1024).decode("utf-8", errors="ignore").lower()
            if "server: cloudflare" in resp or "cf-ray" in resp:
                return True
    except Exception:
        pass
    return False


def _check_one(ip_port: str, api_url: str, honeypot_check: bool = True) -> Optional[str]:
    headers = {
        "User-Agent": "Mozilla/5.0",
        "Accept": "application/json",
        "Origin": "https://090227.xyz",
    }
    for attempt in range(MAX_RETRIES + 1):
        try:
            url = f"{api_url}?proxyip={ip_port}"
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code in RETRY_CODES:
                time.sleep(min(2 ** attempt, 8))
                continue
            return None
        except (urllib.error.URLError, OSError):
            time.sleep(min(2 ** attempt, 8))
            continue
        except json.JSONDecodeError:
            return None

        if not isinstance(data, dict) or not data.get("success"):
            return None

        pr = data.get("probe_results") or {}
        probe = pr.get("ipv4") or pr.get("ipv6") or {}
        ei = probe.get("exit") or {}
        colo = ei.get("colo", data.get("colo", ""))
        country = ei.get("country", "")
        region = ei.get("region", "")
        asn = ei.get("asn", data.get("asn", ""))

        api_latency = ""
        try:
            cm = probe.get("connect_ms")
            tm = probe.get("tls_ms")
            hm = probe.get("http_ms")
            if cm is not None and tm is not None and hm is not None:
                api_latency = int(cm) + int(tm) + int(hm)
        except (TypeError, ValueError):
            api_latency = data.get("responseTime", "")

        ip, port = ip_port.rsplit(":", 1)
        if honeypot_check and _check_honeypot(ip, int(port)):
            return None
        proto = "IPv6" if ":" in ip else "IPv4"
        return f"{ip},{port},TRUE,{colo},{country},{region},{api_latency},,AS{asn},{proto}"
    return None


def _read_input(path: str) -> list[str]:
    lines: list[str] = []
    if not os.path.isfile(path):
        print(f"  输入文件不存在: {path}")
        return lines
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            lines.append(parts[0] if parts else line)
    return lines


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CF 反代节点 API 精筛（含自动重试）")
    parser.add_argument("--input", required=True, help="输入文件 (cf_hits.txt)")
    parser.add_argument("--output", required=True, help="输出文件 (verified.txt)")
    parser.add_argument("--api", default="https://api.090227.xyz/check")
    parser.add_argument("--chunk", type=int, default=5000, help="分片大小")
    parser.add_argument("--concurrent", type=int, default=32, help="并发数")
    parser.add_argument("--append", action="store_true",
                        help="追加模式（不覆盖已有结果）")
    parser.add_argument("--follow", action="store_true",
                        help="流式模式（从 stdin 读取，EOF 为结束）")
    parser.add_argument("--honeypot-check", default=True, action=argparse.BooleanOptionalAction,
                        help="反蜜罐检测：随机 SNI 验证 (默认开启)")
    args = parser.parse_args()

    if args.follow:
        lines = [l.strip() for l in sys.stdin if l.strip()]
    else:
        lines = _read_input(args.input)
    total = len(lines)
    if total == 0:
        sys.exit(0)

    passed = 0
    start = time.time()

    mode = "a" if args.append else "w"
    with open(args.output, mode) as out:
        if args.append:
            existing = Path(args.output).exists() and Path(args.output).stat().st_size > 0
            if not existing:
                out.write(CSV_HEADER + "\n")
        else:
            out.write(CSV_HEADER + "\n")
        with ThreadPoolExecutor(max_workers=args.concurrent) as ex:
            for i in range(0, total, args.chunk):
                chunk = lines[i:i + args.chunk]
                futures = [ex.submit(_check_one, ip, args.api, args.honeypot_check) for ip in chunk]
                for f in as_completed(futures):
                    try:
                        r = f.result()
                    except Exception:
                        continue
                    if r:
                        with _write_lock:
                            out.write(r + "\n")
                        passed += 1
                        if passed % 100 == 0:
                            out.flush()
                out.flush()

                elapsed = time.time() - start
                done = i + len(chunk)
                rate = done / elapsed if elapsed > 0 else 0
                eta_min = (total - done) / rate / 60 if rate > 0 else 0
                eta_m, eta_s = divmod(int(eta_min * 60), 60)
                last_extra = f" | 通过 {passed}/{total} | ETA {eta_m}分{eta_s}秒 | API精筛"
                write_progress(done / total * 100, last_extra)

    elapsed = int(time.time() - start)
    ep = f"{elapsed // 60}分{elapsed % 60}秒"
    done_extra = f" | 通过 {passed}/{total} | {ep} | API精筛"
    if len(done_extra) < len(last_extra):
        done_extra = done_extra + " " * (len(last_extra) - len(done_extra))
    write_progress_done(done_extra)


if __name__ == "__main__":
    main()