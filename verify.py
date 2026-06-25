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
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from lib.utils import write_progress, write_progress_done

MAX_RETRIES = 2
RETRY_CODES = frozenset({429, 502, 503, 504})


def _check_one(ip_port: str, api_url: str) -> Optional[str]:
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
            if attempt < MAX_RETRIES:
                time.sleep(min(2 ** attempt, 8))
                continue
            return None
        except json.JSONDecodeError:
            return None

        if not data.get("success"):
            return None

        pr = data.get("probe_results") or {}
        ei = (pr.get("ipv4") or {}).get("exit") or (pr.get("ipv6") or {}).get("exit") or {}
        colo = ei.get("colo", data.get("colo", ""))
        country = ei.get("country", "")
        region = ei.get("region", "")
        asn = ei.get("asn", data.get("asn", ""))
        ip, port = ip_port.rsplit(":", 1)
        return f"{ip},{port},TRUE,{colo},{country},{region},,,AS{asn}"
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
    header = "IP地址,端口,TLS,数据中心,地区,城市,网络延迟,下载速度,ASN\n"
    with open(args.output, mode) as out:
        if args.append:
            existing = Path(args.output).exists() and Path(args.output).stat().st_size > 0
            if not existing:
                out.write(header)
        else:
            out.write(header)
        for i in range(0, total, args.chunk):
            chunk = lines[i:i + args.chunk]
            with ThreadPoolExecutor(max_workers=args.concurrent) as ex:
                futures = [ex.submit(_check_one, ip, args.api) for ip in chunk]
                for f in as_completed(futures):
                    r = f.result()
                    if r:
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
            write_progress(done / total * 100,
                           f" | 通过 {passed} | {rate:.1f}/s | ETA {eta_m}分{eta_s}秒")

    elapsed = int(time.time() - start)
    write_progress_done(f" | 通过 {passed}/{total} | {elapsed // 60}分{elapsed % 60}秒")


if __name__ == "__main__":
    main()
