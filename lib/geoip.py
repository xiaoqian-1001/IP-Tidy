#!/usr/bin/env python3
"""离线 IP 地理信息查询 -- MaxMind GeoLite2 数据库 (离线优先，在线回退)"""

import os
import sys
import json
import gzip
import time
import io
import shutil
import socket
import ipaddress
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional, Callable

_MAXMIND_ENABLED = False
_MAXMIND_CITY: Optional[Callable] = None
_MAXMIND_ASN: Optional[Callable] = None

_GEO_DIR = Path.home() / ".config" / "ip-tidy"
_GEO_DIR.mkdir(parents=True, exist_ok=True)

_CITY_DB = _GEO_DIR / "GeoLite2-City.mmdb"
_ASN_DB = _GEO_DIR / "GeoLite2-ASN.mmdb"
_KEY_FILE = _GEO_DIR / "maxmind_key"

_MAXMIND_DOWNLOAD = "https://download.maxmind.com/app/geoip_download"
_CITY_URL = f"{_MAXMIND_DOWNLOAD}?edition_id=GeoLite2-City&license_key={{}}&suffix=tar.gz"
_ASN_URL = f"{_MAXMIND_DOWNLOAD}?edition_id=GeoLite2-ASN&license_key={{}}&suffix=tar.gz"


def _init() -> None:
    """加载 maxminddb 模块和数据库文件"""
    global _MAXMIND_ENABLED, _MAXMIND_CITY, _MAXMIND_ASN
    if _MAXMIND_ENABLED:
        return
    try:
        import maxminddb
        if _CITY_DB.is_file():
            _MAXMIND_CITY = maxminddb.open_database(str(_CITY_DB))
        if _ASN_DB.is_file():
            _MAXMIND_ASN = maxminddb.open_database(str(_ASN_DB))
        _MAXMIND_ENABLED = bool(_MAXMIND_CITY or _MAXMIND_ASN)
    except ImportError:
        pass


def lookup(ip: str) -> dict:
    """离线查询 IP 信息，返回 {country, city, isp, asn} 或空 dict"""
    _init()
    if not _MAXMIND_ENABLED:
        return {}

    result: dict = {}
    try:
        ip_bytes = socket.inet_pton(socket.AF_INET, ip)
    except OSError:
        try:
            ip_bytes = socket.inet_pton(socket.AF_INET6, ip)
        except OSError:
            return {}

    if _MAXMIND_CITY:
        try:
            data = _MAXMIND_CITY.get(ip_bytes)
            if data:
                result["country"] = (data.get("country") or {}).get("iso_code", "")
                subs = data.get("subdivisions", [])
                result["region"] = subs[0].get("iso_code", "") if subs else ""
                result["city"] = (data.get("city") or {}).get("names", {}).get("en", "")
        except Exception:
            pass

    if _MAXMIND_ASN:
        try:
            data = _MAXMIND_ASN.get(ip_bytes)
            if data:
                result["asn"] = f"AS{data.get('autonomous_system_number', '')}"
                result["isp"] = data.get("autonomous_system_organization", "")
        except Exception:
            pass

    return result


def is_available() -> bool:
    """检查离线数据库是否可用"""
    _init()
    return _MAXMIND_ENABLED


def _find_mmdb_in_tar(tar_path: Path, suffix: str) -> Optional[Path]:
    """从 tar.gz 中提取 .mmdb 文件"""
    import tarfile
    with tarfile.open(tar_path, "r:gz") as tar:
        for member in tar.getmembers():
            if member.name.endswith(suffix):
                tar.extract(member, path=str(tar_path.parent))
                extracted = tar_path.parent / member.name
                # 移动到目标位置
                target = _CITY_DB if "City" in suffix else _ASN_DB
                shutil.move(str(extracted), str(target))
                # 清理目录
                subdir = tar_path.parent / member.name.split("/")[0]
                if subdir.is_dir():
                    shutil.rmtree(str(subdir), ignore_errors=True)
                return target
    return None


def _download_db(url: str, temp_file: Path) -> bool:
    """下载数据库文件"""
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=60) as resp:
            with open(temp_file, "wb") as f:
                shutil.copyfileobj(resp, f)
        return True
    except Exception as e:
        print(f"  下载失败: {e}")
        return False


def download_geoip(license_key: str) -> bool:
    """下载 GeoLite2 数据库，返回是否成功"""
    if not license_key:
        return False

    city_url = _CITY_URL.format(license_key)
    asn_url = _ASN_URL.format(license_key)

    success = False
    tmp_city = _GEO_DIR / "city.tar.gz"
    tmp_asn = _GEO_DIR / "asn.tar.gz"

    print("  下载 GeoLite2-City ...")
    if _download_db(city_url, tmp_city):
        if _find_mmdb_in_tar(tmp_city, "GeoLite2-City.mmdb"):
            print(f"  [OK] {_CITY_DB.name} ({_CITY_DB.stat().st_size // 1024 // 1024}MB)")
            success = True
        tmp_city.unlink(missing_ok=True)

    print("  下载 GeoLite2-ASN ...")
    if _download_db(asn_url, tmp_asn):
        if _find_mmdb_in_tar(tmp_asn, "GeoLite2-ASN.mmdb"):
            print(f"  [OK] {_ASN_DB.name} ({_ASN_DB.stat().st_size // 1024 // 1024}MB)")
            success = True
        tmp_asn.unlink(missing_ok=True)

    if success:
        _KEY_FILE.write_text(license_key)
        global _MAXMIND_ENABLED, _MAXMIND_CITY, _MAXMIND_ASN
        _MAXMIND_ENABLED = False
        _MAXMIND_CITY = None
        _MAXMIND_ASN = None

    return success


def get_saved_key() -> Optional[str]:
    """获取已保存的 MaxMind License Key"""
    if _KEY_FILE.is_file():
        return _KEY_FILE.read_text().strip()
    return None


def geo_update_interactive() -> bool:
    """交互式下载/更新 GeoIP 数据库"""
    key = get_saved_key()
    if not key:
        print()
        print("  MaxMind GeoLite2 免费数据库需要注册获取 License Key:")
        print("  1. 访问 https://www.maxmind.com/en/geolite2/signup")
        print("  2. 注册后进入 Account -> Manage License Keys -> Generate")
        print()
        try:
            key = input("  License Key (回车跳过): ").strip()
        except (EOFError, KeyboardInterrupt):
            return False
        if not key:
            return False

    print()
    return download_geoip(key)
