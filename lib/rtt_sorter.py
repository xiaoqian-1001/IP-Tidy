import socket
import time
import ssl
import concurrent.futures
from dataclasses import dataclass


@dataclass
class RttResult:
    ip: str
    port: int
    rtt_ms: float
    cf_ray: bool
    colo: str
    reachable: bool


TCP_TIMEOUT = 3
TRACE_HOST = b"speed.cloudflare.com"
TRACE_PATH = b"/cdn-cgi/trace"
HTTP_REQ = b"GET " + TRACE_PATH + b" HTTP/1.1\r\nHost: " + TRACE_HOST + b"\r\nConnection: close\r\n\r\n"


def _parse_trace(body: str) -> tuple[bool, str]:
    colo = ""
    for line in body.splitlines():
        if line.startswith("colo="):
            colo = line[5:].strip()
            break
    return bool(colo), colo


def _check_one(ip: str, port: int, timeout: int = TCP_TIMEOUT) -> RttResult:
    try:
        start = time.time()
        sock = socket.create_connection((ip, port), timeout=timeout)
        rtt_ms = round((time.time() - start) * 1000, 1)

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ssock = ctx.wrap_socket(sock, server_hostname=TRACE_HOST.decode())
        ssock.settimeout(timeout)
        ssock.sendall(HTTP_REQ)

        resp = b""
        while True:
            chunk = ssock.read(4096)
            if not chunk:
                break
            resp += chunk
        ssock.close()

        header_end = resp.find(b"\r\n\r\n")
        if header_end == -1:
            return RttResult(ip=ip, port=port, rtt_ms=rtt_ms, cf_ray=False, colo="", reachable=True)

        headers = resp[:header_end].decode("utf-8", errors="replace")
        body = resp[header_end + 4:].decode("utf-8", errors="replace")

        has_ray = any("cf-ray" in line.lower() for line in headers.splitlines())
        _, colo = _parse_trace(body if has_ray else "")

        return RttResult(ip=ip, port=port, rtt_ms=rtt_ms, cf_ray=has_ray, colo=colo, reachable=True)

    except (socket.timeout, OSError):
        return RttResult(ip=ip, port=port, rtt_ms=0, cf_ray=False, colo="", reachable=False)


def rtt_sort(
    candidates: list[str],
    top_k: int = 10,
    concurrency: int = 50,
    port: int = 443,
    timeout: int = TCP_TIMEOUT,
) -> list[RttResult]:
    if not candidates or top_k <= 0:
        return []
    parsed: list[tuple[str, int]] = []
    for cand in candidates:
        parts = cand.split(":")
        ip = parts[0]
        p = int(parts[1]) if len(parts) > 1 else port
        parsed.append((ip, p))

    results: list[RttResult] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futs = [executor.submit(_check_one, ip, p, timeout) for ip, p in parsed]
        for f in concurrent.futures.as_completed(futs):
            try:
                r = f.result()
                if r.reachable:
                    results.append(r)
            except (OSError, RuntimeError):
                pass

    results.sort(key=lambda x: x.rtt_ms)
    return results[:top_k]
