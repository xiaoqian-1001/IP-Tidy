#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""公共工具模块：进度条、网络检测、端口解析"""

import os
import re
import sys
import time
import signal
import socket
import subprocess
import urllib.request
import json
from pathlib import Path
from typing import Optional, Callable


BAR_WIDTH = 30


def render_progress(pct: float, extra: str = "") -> str:
    """渲染单行进度条字符串"""
    filled = int(BAR_WIDTH * pct / 100)
    bar = "\u2588" * filled + "\u2591" * (BAR_WIDTH - filled)
    return f"  [{bar}] {pct:.1f}%{extra}"


def write_progress(pct: float, extra: str = "") -> None:
    """写入进度条到 stderr（\r 覆盖式）"""
    sys.stderr.write(f"\r{render_progress(pct, extra)}")
    sys.stderr.flush()


def write_progress_done(extra: str = "") -> None:
    """写入 100% 完成进度条"""
    filled = "\u2588" * BAR_WIDTH
    sys.stderr.write(f"\r  [{filled}] 100.0%{extra}\n")
    sys.stderr.flush()


def progress_reader(stream, total: int, name: str = "Scanned",
                    done_callback: Optional[Callable] = None) -> None:
    """从流中读取 masscan/cf-scanner 进度输出并渲染进度条"""
    last_pct = -1
    patterns = [
        re.compile(r"(\d+\.?\d*)%\s*done"),
        re.compile(r"Scanned\s+\d+/(\d+)\s+\((\d+\.?\d*)%\)"),
    ]
    for line in stream:
        for pat in patterns:
            m = pat.search(line)
            if m:
                pct = min(float(m.group(1) if "%" in pat.pattern else m.group(2)), 100)
                if abs(pct - last_pct) >= 0.5:
                    write_progress(pct)
                    last_pct = pct
                break
    if done_callback:
        done_callback()
    else:
        write_progress_done()


def get_public_ip() -> str:
    """获取公网出口 IP，HTTP API + DNS 多重兜底"""
    apis = [
        ("https://api.ipify.org", 5),
        ("https://api-ipv4.ip.sb/ip", 5),
        ("https://ifconfig.me/ip", 5),
        ("https://icanhazip.com", 5),
    ]
    for url, timeout_sec in apis:
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
                return resp.read().decode("utf-8").strip()
        except Exception:
            continue

    dns_queries = [
        (["dig", "+short", "myip.opendns.com", "@resolver1.opendns.com"], 5),
        (["dig", "TXT", "+short", "o-o.myaddr.l.google.com", "@ns1.google.com"], 5),
        (["dig", "+short", "whoami.akamai.net", "@ns1-1.akamaitech.net"], 5),
    ]
    for cmd, timeout_sec in dns_queries:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
            out = r.stdout.strip().strip('"')
            if out and "." in out and out.count(".") == 3:
                parts = out.split(".")
                if all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                    return out
        except Exception:
            continue
    return "127.0.0.1"


def get_lan_ip() -> str:
    """获取本机局域网 IP"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        pass
    return "127.0.0.1"


def detect_isp(ip: str) -> tuple[str, str, str]:
    """检测本机运营商信息，返回 (ip, country, isp_name)"""
    if ip == "127.0.0.1":
        print("  (无法获取公网 IP，请检查网络连接，跳过运营商检测)")
        return ip, "", ""
    try:
        token = None
        token_file = Path("/root/.ipinfo_token")
        if token_file.is_file():
            token = token_file.read_text().strip()
        url = f"https://ipinfo.io/{ip}/json"
        if token:
            url += f"?token={token}"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            country = data.get("country", "")
            org = data.get("org", "")
            city = data.get("city", "")
            if country == "CN":
                isp_name = org.split(" ", 1)[-1] if org else "\u672a\u77e5"
                print(f"  \u5730\u533a: {city}, {country}  \u4e2d\u56fd  \u8fd0\u8425\u5546: {isp_name}")
            else:
                print(f"  \u5730\u533a: {city}, {country}  \u673a\u6784: {org}")
            return ip, country, org
    except Exception as e:
        print(f"  (\u65e0\u6cd5\u83b7\u53d6\u8be6\u60c5: {e})")
    return ip, "", ""


def parse_ports(port_str: str) -> str:
    """解析端口字符串: 443 或 8443-8550 或 443,8443,2053-2096"""
    ports: set[str] = set()
    for part in port_str.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                a, b = part.split("-", 1)
                pa, pb = int(a), int(b)
                if pa < 1 or pb > 65535 or pa > pb:
                    continue
                ports.update(str(p) for p in range(pa, pb + 1))
            elif part.isdigit():
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(part)
        except ValueError:
            continue
    return ",".join(sorted(ports, key=int)) if ports else ""


def port_is_free(port: int) -> bool:
    """检测端口是否空闲"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(1)
        return sock.connect_ex(("127.0.0.1", port)) != 0
    finally:
        sock.close()


def kill_port_process(port: int) -> bool:
    """杀掉占用指定端口的进程"""
    try:
        out = subprocess.run(
            ["ss", "-tlnp", f"sport = :{port}"],
            capture_output=True, text=True, timeout=5
        )
        for line in out.stdout.split("\n"):
            if f":{port}" in line and "users:" in line:
                m = re.search(r"pid=(\d+)", line)
                if m:
                    os.kill(int(m.group(1)), signal.SIGTERM)
                    time.sleep(0.5)
                    return True
    except Exception:
        pass
    return False
