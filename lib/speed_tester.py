import socket
import time
import concurrent.futures
from collections import deque
from dataclasses import dataclass
from typing import Optional

from lib.net_utils import ssl_connect, build_http_request, parse_cf_ray


@dataclass
class SpeedTestResult:
    ip: str
    port: int
    peak_speed_kbps: float
    bandwidth_mbps: float
    rtt_avg_ms: float
    colo: str
    http_latency_ms: float
    bytes_downloaded: int
    duration_sec: float
    rtt_std_ms: float = 0
    error: Optional[str] = None


SPEED_HOST = "speed.cloudflare.com"
SPEED_PATH = "/__down?bytes=50000000"
WINDOW_SECONDS = 1.0
CHUNK_SIZE = 65536


def _measure_peak(
    ip: str, port: int, timeout: int = 30, bandwidth_target: int = 50
) -> SpeedTestResult:
    start = time.time()
    total_bytes = 0
    colo = ""
    peak_bytes_per_sec = 0.0
    try:
        ssock = ssl_connect(ip, port, SPEED_HOST, timeout=10)
        ssock.settimeout(timeout)
        ssock.sendall(build_http_request(SPEED_HOST, SPEED_PATH))

        window: deque[tuple[float, int]] = deque()
        headers_done = False
        header_buf = b""

        while True:
            try:
                chunk = ssock.read(CHUNK_SIZE)
            except socket.timeout:
                break
            if not chunk:
                break

            if not headers_done:
                header_buf += chunk
                idx = header_buf.find(b"\r\n\r\n")
                if idx >= 0:
                    _, colo = parse_cf_ray(header_buf[:idx])
                    body_data = header_buf[idx + 4:]
                    headers_done = True
                    if body_data:
                        now = time.time()
                        window.append((now, len(body_data)))
                        total_bytes += len(body_data)
            else:
                now = time.time()
                window.append((now, len(chunk)))
                total_bytes += len(chunk)

            now = time.time()
            while window and window[0][0] < now - WINDOW_SECONDS:
                window.popleft()
            if len(window) > 1:
                win_bytes = sum(b for _, b in window)
                win_dur = min(window[-1][0] - window[0][0], WINDOW_SECONDS)
                instant = win_bytes / max(win_dur, 0.001)
                peak_bytes_per_sec = max(peak_bytes_per_sec, instant)

            if peak_bytes_per_sec * 8 / 1_000_000 >= bandwidth_target:
                break

        ssock.close()
        elapsed = time.time() - start
        peak_kbps = peak_bytes_per_sec / 1024
        bandwidth = peak_kbps * 8 / 1024
        return SpeedTestResult(
            ip=ip, port=port,
            peak_speed_kbps=round(peak_kbps, 1),
            bandwidth_mbps=round(bandwidth, 1),
            rtt_avg_ms=0, colo=colo,
            http_latency_ms=round(elapsed * 1000, 1),
            bytes_downloaded=total_bytes,
            duration_sec=round(elapsed, 1),
        )
    except Exception as e:
        elapsed = time.time() - start
        return SpeedTestResult(
            ip=ip, port=port,
            peak_speed_kbps=0, bandwidth_mbps=0,
            rtt_avg_ms=0, colo="",
            http_latency_ms=round(elapsed * 1000, 1),
            bytes_downloaded=0, duration_sec=round(elapsed, 1),
            error=str(e),
        )


def speed_test(
    candidates: list[str],
    bandwidth_target: int = 50,
    timeout: int = 30,
    rtt_results: Optional[dict[str, float]] = None,
    concurrency: int = 5,
) -> list[SpeedTestResult]:
    results: list[SpeedTestResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futs = []
        for cand in candidates:
            parts = cand.split(":")
            ip = parts[0]
            port = int(parts[1]) if len(parts) > 1 else 443
            futs.append(executor.submit(_measure_peak, ip, port, timeout, bandwidth_target))
        for f in concurrent.futures.as_completed(futs):
            try:
                r = f.result()
                if r.error is None:
                    if rtt_results and r.ip in rtt_results:
                        r.rtt_avg_ms = rtt_results[r.ip]
                results.append(r)
            except (OSError, RuntimeError, ValueError):
                pass
    results.sort(key=lambda x: x.bandwidth_mbps, reverse=True)
    return results