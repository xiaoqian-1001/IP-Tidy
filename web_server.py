"""IP-Tidy WEB Mode -- Flask + SSE 前端，核心逻辑由共享模块提供"""

import os
import sys
import re
import json
import time
import queue
import socket
import random
import threading
import subprocess
import urllib.request
import ipaddress
import argparse
from pathlib import Path
from datetime import datetime
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import Flask, request, jsonify, Response, send_from_directory

sys.path.insert(0, str(Path(__file__).parent))
from lib.utils import parse_ports
from lib.scanner_utils import (
    BASE, CF_SCANNER, WIDE_PORTS, _MASSCAN_BATCH,
    port_count, split_port_batches,
    masscan_adapter_ip, masscan_bin, probe_masscan_rate_fast,
    tcp_latency as _tcp_latency_util,
    read_default_ports, random_ports, expand_cidrs,
    finalize_results, build_dc_list,
    SUBNET_SPLIT, SUBNET_PROBE, SUBNET_THRESHOLD, SUBNET_PORT, SUBNET_TIMEOUT,
)
from lib.scanner_pipeline import (
    resolve_asn_cidrs, run_masscan, run_cf_scanner, verify_batch,
    smart_subnet_probe, cert_enum, ensure_cf_scanner,
    enrich_geoip, run_speed_test, geo_available as pipeline_geo_available,
)

API_URL = "https://api.090227.xyz/check"
MASSCAN_BIN = "/usr/local/bin/masscan"
_masscan_available = os.path.exists(MASSCAN_BIN) or (os.system("which masscan >/dev/null 2>&1") == 0)
PORTS_FILE = BASE / "ports.txt"

app = Flask(__name__, static_folder="web", static_url_path="")

_V4_URL = "https://www.cloudflare.com/ips-v4"
_V6_URL = "https://www.cloudflare.com/ips-v6"

_ASN_CACHE = BASE / ".asn_cache.json"
_ASN_CACHE_TTL = 7 * 86400

_SPEED_URLS = [
    ("https://speed.cloudflare.com/__down?bytes=1048576", 1),
    ("https://speed.cloudflare.com/__down?bytes=10485760", 10),
    ("https://speed.cloudflare.com/__down?bytes=100000000", 100),
    ("https://cloudflare.cdn.openbsd.org/pub/OpenBSD/7.3/src.tar.gz", 0),
]

_EVENT_QUEUES: dict[str, queue.Queue] = {}
_QUEUE_LOCK = threading.Lock()
_SCAN_RESULTS: dict[str, list[dict]] = {}
_RESULTS_LOCK = threading.Lock()
_CANCEL_FLAGS: dict[str, threading.Event] = {}
_CANCEL_LOCK = threading.Lock()
_CIDR_CACHE: dict[str, list[str]] = {}
_CIDR_LOCK = threading.Lock()
_TMP_DIR = BASE / ".web_tmp"


def _ensure_tmp() -> None:
    _TMP_DIR.mkdir(parents=True, exist_ok=True)


def _gen_session_id() -> str:
    import uuid
    return uuid.uuid4().hex[:12]


def _get_or_create_queue(sid: str) -> queue.Queue:
    with _QUEUE_LOCK:
        if sid not in _EVENT_QUEUES:
            _EVENT_QUEUES[sid] = queue.Queue()
        return _EVENT_QUEUES[sid]


def _emit(sid: str, typ: str, data: object) -> None:
    try:
        _get_or_create_queue(sid).put_nowait({"type": typ, "data": data})
    except Exception:
        pass


def _cancel_get(sid: str) -> threading.Event:
    with _CANCEL_LOCK:
        f = threading.Event()
        _CANCEL_FLAGS[sid] = f
        return f


def _cancel_is(sid: str) -> bool:
    with _CANCEL_LOCK:
        f = _CANCEL_FLAGS.get(sid)
        return f.is_set() if f else False


def _resolve_port_list(port_mode: str, custom_ports: str) -> str:
    if port_mode == "default":
        return read_default_ports(PORTS_FILE)
    elif port_mode == "wide":
        return WIDE_PORTS
    elif port_mode == "random":
        return random_ports()
    elif port_mode == "custom":
        parsed = parse_ports(custom_ports)
        return parsed or read_default_ports(PORTS_FILE)
    else:
        return read_default_ports(PORTS_FILE)


def _fetch_cf_ips(ip_type: int) -> list[str]:
    url = _V4_URL if ip_type == 4 else _V6_URL
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ip-tidy/2.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return [l.strip() for l in resp.read().decode().splitlines()
                    if l.strip() and not l.startswith("#")]
    except Exception:
        return []


def _measure_latencies(results: list[dict], sid: str, threads: int = 100) -> None:
    if not results:
        return
    _emit(sid, "log", f"正在测量 {len(results)} 个节点 TCP 延迟...")
    total = len(results)
    done = 0
    with ThreadPoolExecutor(max_workers=min(threads, 200)) as ex:
        fmap = {ex.submit(_tcp_latency_util, r["ip"], r["port"], 3): i
                for i, r in enumerate(results)}
        for future in as_completed(fmap):
            if _cancel_is(sid):
                return
            i = fmap[future]
            try:
                lat = future.result()
            except Exception:
                lat = 0
            results[i]["latency"] = lat
            results[i]["latency_str"] = f"{lat}ms" if lat > 0 else "N/A"
            done += 1
            if done % 100 == 0 or done == total:
                _emit(sid, "scan_progress", {
                    "current": done, "total": total, "stage": "延迟测量",
                })


def _stream_and_save(results: list[dict], sid: str) -> None:
    with _RESULTS_LOCK:
        _SCAN_RESULTS[sid] = results
    for r in results:
        _emit(sid, "scan_result", r)


def run_scan(sid: str, params: dict) -> None:
    mode = params.get("mode", "asn_cidr")
    port_mode = params.get("port_mode", "default")
    custom_ports = params.get("custom_ports", "")
    threads = int(params.get("threads", 100))
    delay_ms = int(params.get("delay", 500))
    do_speed = params.get("speed", False)
    do_cert = params.get("cert", False)
    do_smart = params.get("smart", False)
    ip_mode = params.get("ip_mode", "all")

    def _cb(typ, data):
        if typ in ("log", "error"):
            _emit(sid, typ, data)
        elif typ in ("scan_progress",):
            _emit(sid, typ, data)
        elif typ == "masscan_progress":
            _emit(sid, "scan_progress", data)

    _cancel_get(sid)

    ports_str = _resolve_port_list(port_mode, custom_ports)
    _emit(sid, "log", f"端口模式: {port_mode} -> {ports_str[:80]}{'...' if len(ports_str)>80 else ''} ({port_count(ports_str)} 个)")

    targets: list[str] = []
    masscan_hits: list[str] = []

    if mode == "asn_cidr":
        _emit(sid, "log", "=== ASN/CIDR 扫描模式 ===")
        asns = [s.strip() for s in params.get("asns", "").split(",") if s.strip().isdigit()]
        v4_cidrs = []
        v6_cidrs = []
        for s in params.get("cidrs", "").replace("，", ",").split(","):
            s = s.strip()
            if not s or "/" not in s:
                continue
            try:
                net = ipaddress.ip_network(s, strict=False)
                if net.version == 6:
                    v6_cidrs.append(str(net))
                else:
                    v4_cidrs.append(str(net))
            except ValueError:
                pass

        if not asns and not v4_cidrs and not v6_cidrs:
            _emit(sid, "error", "请输入 ASN 或 CIDR")
            return

        resolved_v4, resolved_v6 = resolve_asn_cidrs(asns, v4_cidrs, v6_cidrs, progress_callback=_cb)
        if ip_mode == "v4":
            cidrs = resolved_v4
            v4_final, v6_final = resolved_v4, []
        elif ip_mode == "v6":
            cidrs = resolved_v6
            v4_final, v6_final = [], resolved_v6
        else:
            cidrs = resolved_v4 + resolved_v6
            v4_final, v6_final = resolved_v4, resolved_v6

        if not cidrs:
            _emit(sid, "error", "无可用 CIDR")
            return

        _emit(sid, "log", f"解析得到 {len(cidrs)} 个 CIDR 段 (v4: {len(v4_final)}, v6: {len(v6_final)})")

        with _CIDR_LOCK:
            _CIDR_CACHE[sid] = cidrs

        if do_smart and v4_final:
            v4_probed = smart_subnet_probe(v4_final, progress_callback=_cb, sid=sid, threads=threads)
            _emit(sid, "log", f"智能探活后: {len(v4_probed)} IPv4 子段")
            v4_final = v4_probed

        if v4_final and _masscan_available:
            masscan_rate = probe_masscan_rate_fast()
            cidr_file = _TMP_DIR / f"cidrs_v4_{sid}.txt"
            cidr_file.write_text("\n".join(v4_final) + "\n")
            _emit(sid, "log", f"masscan 扫描 IPv4 CIDR ({port_count(ports_str)} 端口, {masscan_rate} pps)...")
            masscan_hits = run_masscan(cidr_file, ports_str, masscan_rate,
                                       progress_callback=_cb, sid=sid)
            try:
                cidr_file.unlink()
            except OSError:
                pass
        elif v4_final:
            _emit(sid, "log", "masscan 不可用，回退到直接 cf-scanner 扫描")
            ips = expand_cidrs(v4_final, max_ips=5000)
            port_list = [p.strip() for p in ports_str.split(",") if p.strip().isdigit()]
            for ip in ips:
                for p in port_list:
                    targets.append(f"{ip}:{p}")

        if v6_final:
            ip_list = expand_cidrs(v6_final, max_ips=500)
            port_list = [p.strip() for p in ports_str.split(",") if p.strip().isdigit()]
            for ip in ip_list:
                for p in port_list:
                    targets.append(f"{ip}:{p}")

    elif mode == "custom":
        _emit(sid, "log", "=== 自定义扫描模式 ===")
        port_list = ports_str.split(",")
        for line in params.get("ips", "").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            ip = parts[0]
            if len(parts) > 1 and parts[1].isdigit():
                targets.append(f"{ip}:{parts[1]}")
            else:
                for p in port_list:
                    p = p.strip()
                    if p:
                        targets.append(f"{ip}:{p}")
        if not targets:
            _emit(sid, "error", "未提供有效 IP")
            return
        _emit(sid, "log", f"解析到 {len(targets)} 个 IP:port 目标")
    else:
        _emit(sid, "error", f"未知模式: {mode}")
        return

    _ensure_tmp()
    cf_in = _TMP_DIR / f"cf_in_{sid}.txt"
    cf_out = _TMP_DIR / f"cf_out_{sid}.txt"

    all_targets = masscan_hits + targets
    if all_targets:
        cf_in.write_text("\n".join(all_targets) + "\n")

    cf_total = len(masscan_hits) + len(targets)
    if cf_total > 0:
        _emit(sid, "log", f"cf-scanner TLS 检测 ({cf_total} 目标, 并发={threads})")
        hit_count = run_cf_scanner(cf_in, cf_out, threads, progress_callback=_cb, sid=sid)
    else:
        hit_count = 0

    if _cancel_is(sid):
        return

    if hit_count == 0:
        _emit(sid, "error", "未检测到 CF 节点")
        _emit(sid, "scan_complete", {"total": 0, "dc_list": []})
        return

    _emit(sid, "log", f"cf-scanner 命中 {hit_count} 个节点")

    hits = []
    with open(cf_out) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if ":" not in line:
                line = f"{line}:{ports_str.split(',')[0].strip()}"
            hits.append(line)

    results = verify_batch(hits, concurrency=min(32, threads),
                           progress_callback=_cb, sid=sid)
    if _cancel_is(sid):
        return

    _emit(sid, "log", f"API 验证通过 {len(results)} 个节点")

    enrich_geoip(results)

    if not results:
        _emit(sid, "error", "API 验证通过 0 个节点")
        _emit(sid, "scan_complete", {"total": 0, "dc_list": []})
        return

    if do_cert:
        added = cert_enum(results, progress_callback=_cb, sid=sid, threads=threads)
        if added:
            _emit(sid, "log", f"证书反查新增 {added} 个节点")

    if _cancel_is(sid):
        return

    _measure_latencies(results, sid, threads=min(threads, 200))
    if _cancel_is(sid):
        return

    filtered = finalize_results(results, delay_ms)
    dc_list = build_dc_list(filtered)
    _stream_and_save(filtered, sid)

    _emit(sid, "scan_complete", {"total": len(filtered), "dc_list": dc_list})
    _emit(sid, "log", f"扫描完成: {len(filtered)} 个节点 ({len(dc_list)} 个数据中心)")

    if do_speed and filtered:
        _emit(sid, "log", f"开始批量测速 ({len(filtered)} 个节点)...")
        done_spd = 0
        total_spd = len(filtered)
        with ThreadPoolExecutor(max_workers=min(10, threads)) as ex:
            fmap = {}
            for r in filtered:
                if _cancel_is(sid):
                    break
                fmap[ex.submit(run_speed_test, r["ip"], r["port"])] = r["ip"]
            for future in as_completed(fmap):
                if _cancel_is(sid):
                    break
                ip = fmap[future]
                try:
                    spd = future.result()
                except Exception:
                    spd = "N/A"
                _emit(sid, "speed_result", {"ip": ip, "speed": spd})
                done_spd += 1
                if done_spd % 10 == 0:
                    _emit(sid, "scan_progress", {
                        "current": done_spd, "total": total_spd, "stage": "测速",
                    })
        _emit(sid, "log", "测速完成")

    _emit(sid, "task_complete", None)

    for f in (cf_in, cf_out):
        try:
            f.unlink()
        except OSError:
            pass


@app.route("/")
def index():
    return send_from_directory("web", "index.html")


@app.route("/api/events")
def api_events():
    sid = request.args.get("session", "")
    if not sid:
        return jsonify({"error": "missing session"}), 400
    q = _get_or_create_queue(sid)

    def generate():
        while True:
            try:
                msg = q.get(timeout=15)
                yield f"data: {json.dumps(msg, ensure_ascii=False)}\n\n"
            except queue.Empty:
                yield f"data: {json.dumps({'type': 'ping', 'data': None})}\n\n"

    return Response(generate(), mimetype="text/event-stream",
                    headers={
                        "Cache-Control": "no-cache",
                        "X-Accel-Buffering": "no",
                        "Access-Control-Allow-Origin": "*",
                    })


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json() or {}
    sid = data.get("session", _gen_session_id())

    params = {
        "mode": data.get("mode", "asn_cidr"),
        "port_mode": data.get("port_mode", "default"),
        "custom_ports": data.get("custom_ports", ""),
        "threads": data.get("threads", 100),
        "delay": data.get("delay", 500),
        "speed": data.get("speed", False),
        "cert": data.get("cert", False),
        "smart": data.get("smart", False),
        "ip_mode": data.get("ip_mode", "all"),
        "asns": data.get("asns", ""),
        "cidrs": data.get("cidrs", ""),
        "ips": data.get("ips", ""),
        "port": data.get("port", 443),
        "ip_type": data.get("ip_type", 4),
        "fallback_port": data.get("fallback_port", 443),
    }

    t = threading.Thread(target=run_scan, args=(sid, params), daemon=True)
    t.start()
    return jsonify({"status": "started", "session": sid})


@app.route("/api/speed-test", methods=["POST"])
def api_speed_test():
    data = request.get_json() or {}
    ip = data.get("ip", "")
    port = int(data.get("port", 443))
    sid = data.get("session", "")
    if not ip:
        return jsonify({"error": "missing ip"}), 400

    def _do():
        r = run_speed_test(ip, port)
        _emit(sid, "speed_result", {"ip": ip, "speed": r})

    threading.Thread(target=_do, daemon=True).start()
    return jsonify({"status": "started"})


@app.route("/api/cancel", methods=["POST"])
def api_cancel():
    data = request.get_json() or {}
    sid = data.get("session", "")
    if sid:
        with _CANCEL_LOCK:
            f = _CANCEL_FLAGS.get(sid)
            if f:
                f.set()
        _emit(sid, "log", "任务取消中...")
    return jsonify({"status": "cancelled"})


@app.route("/api/export", methods=["POST"])
def api_export():
    data = request.get_json() or {}
    sid = data.get("session", "")
    with _RESULTS_LOCK:
        results = _SCAN_RESULTS.get(sid, [])
    if not results:
        return jsonify({"error": "no results"}), 404

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = BASE / f"export_{ts}.csv"
    with open(path, "w") as f:
        f.write("IP地址,端口,TLS,数据中心,地区,城市,网络延迟,下载速度,ASN,协议\n")
        for r in results:
            proto = "IPv6" if ":" in r["ip"] else "IPv4"
            f.write(f"{r['ip']},{r.get('port','-')},TRUE,{r.get('colo','')},"
                    f"{r.get('country','')},{r.get('region','')},"
                    f"{r.get('latency','')},,AS{r.get('asn','')},{proto}\n")
    return send_from_directory(str(BASE), path.name, as_attachment=True)


@app.route("/api/export-cidrs", methods=["POST"])
def api_export_cidrs():
    data = request.get_json() or {}
    sid = data.get("session", "")
    with _CIDR_LOCK:
        cidrs = _CIDR_CACHE.get(sid, [])
    if not cidrs:
        return jsonify({"error": "no cidrs"}), 404

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = BASE / f"output_v6_{ts}.csv"
    with open(path, "w") as f:
        f.write("CIDR,IP数量,协议\n")
        for cidr in cidrs:
            try:
                cnt = ipaddress.ip_network(cidr, strict=False).num_addresses
            except ValueError:
                cnt = 0
            proto = "IPv6" if ":" in cidr else "IPv4"
            f.write(f"{cidr},{cnt},{proto}\n")
    return send_from_directory(str(BASE), path.name, as_attachment=True)


@app.route("/api/server-info", methods=["GET"])
def api_server_info():
    cpu = os.cpu_count() or 1
    mem = 512
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if "MemAvailable" in line:
                    mem = int(line.split()[1]) // 1024
                    break
    except (FileNotFoundError, OSError):
        pass
    return jsonify({
        "cpu": cpu,
        "memory_mb": mem,
        "cf_scanner": CF_SCANNER.is_file(),
        "geoip": pipeline_geo_available(),
    })


@app.route("/api/results", methods=["GET"])
def api_results():
    sid = request.args.get("session", "")
    with _RESULTS_LOCK:
        results = _SCAN_RESULTS.get(sid, [])
    return jsonify(results)


def main():
    parser = argparse.ArgumentParser(description="IP-Tidy WEB Server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8899)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    if CF_SCANNER.is_file():
        print(f"[OK] cf-scanner: {CF_SCANNER}")
    else:
        print(f"[WARN] cf-scanner 未找到: cd cf-scanner-src && go build -o ../cf-scanner main.go")

    print(f"IP-Tidy WEB http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=args.debug,
            threaded=True, use_reloader=False)


if __name__ == "__main__":
    main()