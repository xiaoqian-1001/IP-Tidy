#!/usr/bin/env python3
"""
API 精筛 -- 调用 api.090227.xyz/check 验证 CF 节点可用性
分片流式，默认并发 32，每次请求最多重试 2 次
"""
import argparse
import json
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from lib.utils import write_progress, write_progress_done

MAX_RETRIES = 2


def check_single(line: str, api_url: str) -> Optional[str]:
    """检查单个 IP:port 是否为可用 CF 反代节点，失败重试 MAX_RETRIES 次"""
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    parts = line.split()
    ip_port = parts[0] if parts else line

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
            if not data.get("success"):
                return None

            pr = data.get("probe_results", {})
            exit_info = (
                pr.get("ipv4", {}).get("exit")
                or pr.get("ipv6", {}).get("exit")
                or {}
            )
            colo = exit_info.get("colo", data.get("colo", ""))
            country = exit_info.get("country", "")
            region = exit_info.get("region", "")
            asn = exit_info.get("asn", data.get("asn", ""))
            ip, port = ip_port.rsplit(":", 1)
            return f"{ip},{port},TRUE,{colo},{country},{region},,,AS{asn}"

        except urllib.error.HTTPError as e:
            if e.code in (429, 503):
                time.sleep(min(2 ** attempt, 8))
                continue
            return None
        except (urllib.error.URLError, OSError, json.JSONDecodeError, ValueError):
            if attempt < MAX_RETRIES:
                time.sleep(min(2 ** attempt, 8))
                continue
            return None

    return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--api", default="https://api.090227.xyz/check")
    parser.add_argument("--chunk", type=int, default=5000)
    parser.add_argument("--concurrent", type=int, default=32)
    args = parser.parse_args()

    with open(args.input) as f:
        all_lines = [line for line in f if line.strip() and not line.startswith("#")]

    total = len(all_lines)
    passed = 0
    failed = 0
    start = time.time()

    with open(args.output, "w") as out:
        out.write("IP地址,端口,TLS,数据中心,地区,城市,网络延迟,下载速度,ASN\n")

        for i in range(0, total, args.chunk):
            chunk = all_lines[i : i + args.chunk]
            with ThreadPoolExecutor(max_workers=args.concurrent) as ex:
                futures_map = {
                    ex.submit(check_single, line, args.api): line
                    for line in chunk
                }
                for f in as_completed(futures_map):
                    result = f.result()
                    if result:
                        out.write(result + "\n")
                        out.flush()
                        passed += 1
                    else:
                        failed += 1

            elapsed = time.time() - start
            done = i + len(chunk)
            rate = done / elapsed if elapsed > 0 else 0
            eta_min = (total - done) / rate / 60 if rate > 0 else 0
            pct = done / total * 100
            write_progress(
                pct, f" | 通过 {passed} | {rate:.1f}/s | ETA {eta_min:.1f}m"
            )

    elapsed = int(time.time() - start)
    msg = f" | 通过 {passed}/{total} | {elapsed // 60}min"
    write_progress_done(msg)


if __name__ == "__main__":
    main()
