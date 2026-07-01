import socket
import time
import statistics
import concurrent.futures
from dataclasses import dataclass
from typing import Optional


@dataclass
class RttResult:
    ip: str
    port: int
    rtt_avg_ms: float
    rtt_min_ms: float
    rtt_std_ms: float
    reachable: bool


TCP_TIMEOUT = 3
TCP_SAMPLES = 3


def _measure_rtt(ip: str, port: int, timeout: int = TCP_TIMEOUT, samples: int = TCP_SAMPLES) -> RttResult:
    rtts: list[float] = []
    for _ in range(samples):
        try:
            start = time.time()
            with socket.create_connection((ip, port), timeout=timeout):
                elapsed = (time.time() - start) * 1000
            rtts.append(elapsed)
        except (socket.timeout, OSError):
            break
    if not rtts:
        return RttResult(ip=ip, port=port, rtt_avg_ms=0, rtt_min_ms=0, rtt_std_ms=0, reachable=False)
    avg = statistics.mean(rtts)
    rmin = min(rtts)
    std = statistics.stdev(rtts) if len(rtts) > 1 else 0
    return RttResult(ip=ip, port=port, rtt_avg_ms=round(avg, 1), rtt_min_ms=round(rmin, 1),
                     rtt_std_ms=round(std, 1), reachable=True)


def rtt_sort(
    candidates: list[str],
    top_k: int = 10,
    concurrency: int = 50,
    port: int = 443,
    timeout: int = TCP_TIMEOUT,
    samples: int = TCP_SAMPLES,
) -> list[RttResult]:
    parsed: list[tuple[str, int]] = []
    for cand in candidates:
        parts = cand.split(":")
        ip = parts[0]
        p = int(parts[1]) if len(parts) > 1 else port
        parsed.append((ip, p))

    results: list[RttResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futs = [executor.submit(_measure_rtt, ip, p, timeout, samples) for ip, p in parsed]
        for f in concurrent.futures.as_completed(futs):
            try:
                r = f.result()
                if r.reachable:
                    results.append(r)
            except (OSError, RuntimeError):
                pass

    results.sort(key=lambda x: x.rtt_avg_ms)
    return results[:top_k]