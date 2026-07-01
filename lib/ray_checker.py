import time
import concurrent.futures
from dataclasses import dataclass
from typing import Optional

from lib.net_utils import ssl_connect, build_http_request, parse_cf_ray, read_http_response


@dataclass
class RayCheckResult:
    ip: str
    port: int
    ray_present: bool
    colo: str
    http_latency_ms: float
    error: Optional[str] = None


CF_RAY_HOST = "cloudflare.com"
CF_RAY_PATH = "/cdn-cgi/trace"
DEFAULT_TIMEOUT = 10


def _check_one(ip: str, port: int, timeout: int = DEFAULT_TIMEOUT) -> RayCheckResult:
    start = time.time()
    try:
        ssock = ssl_connect(ip, port, CF_RAY_HOST, timeout)
        ssock.sendall(build_http_request(CF_RAY_HOST, CF_RAY_PATH))
        response = read_http_response(ssock)
        ssock.close()
        elapsed_ms = (time.time() - start) * 1000
        ray_present, colo = parse_cf_ray(response)
        return RayCheckResult(
            ip=ip, port=port, ray_present=ray_present, colo=colo,
            http_latency_ms=round(elapsed_ms, 1),
            error=None if ray_present else "no CF-RAY header",
        )
    except Exception as e:
        elapsed_ms = (time.time() - start) * 1000
        return RayCheckResult(
            ip=ip, port=port, ray_present=False, colo="",
            http_latency_ms=round(elapsed_ms, 1), error=str(e),
        )


def ray_check(
    candidates: list[str],
    concurrency: int = 32,
    timeout: int = DEFAULT_TIMEOUT,
) -> list[RayCheckResult]:
    results: list[RayCheckResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futs = []
        for cand in candidates:
            parts = cand.split(":")
            ip = parts[0]
            port = int(parts[1]) if len(parts) > 1 else 443
            futs.append(executor.submit(_check_one, ip, port, timeout))
        for f in concurrent.futures.as_completed(futs):
            try:
                results.append(f.result())
            except (OSError, RuntimeError):
                pass
    return results