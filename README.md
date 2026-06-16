# ASNIPtest

从 ASN 拉取 IP 段 → 端口扫描 → Cloudflare 反代节点检测 → 输出可用 CF 节点。

## 一键安装

```bash
curl -fsSL https://raw.githubusercontent.com/e13815332/ASNIPtest/main/install.sh | bash
```

## 使用

```bash
cd ~/ASNIPtest
python3 run.py AS209242
```

多个 ASN：

```bash
python3 run.py AS209242,AS3214
```

## 流程

```
ASN(命令行) → RIPEStat → CIDR → prips 展开 IP
    → masscan 端口扫描 → cf-scanner 粗筛 → API 精筛 → CSV
```

## 依赖工具

| 工具 | 用途 | 来源 |
|------|------|------|
| [masscan](https://github.com/robertdavidgraham/masscan) | 高速端口扫描 | `apt install masscan` |
| [prips](https://manpages.debian.org/prips) | CIDR IP 段展开 | `apt install prips` |
| [RIPEStat API](https://stat.ripe.net/) | ASN → CIDR 查询 | 免费公开 API |
| cf-scanner | CF 反代检测 | 内置 Go 源码，自动编译 |
| 精筛 API | 二次验证节点可用性 | 内置 |

## 输出

运行完成后自动输出 CSV 文件，并提供临时下载链接：

```
📥 下载链接 (临时, 按回车关闭):
http://1.2.3.4:8899/output_AS209242_20260616_120000.csv
```

CSV 列：IP地址, 端口, TLS, 数据中心, 地区, 城市, 网络延迟, 下载速度, ASN

## 硬件自适应

根据 CPU 核数/内存自动调整参数：

| 配置 | masscan | cf并发 | API并发 |
|------|---------|--------|---------|
| 2核1G | 2,000 pps | 200 | 8 |
| 4核2G | 4,000 pps | 400 | 32 |
| 16核16G | 16,000 pps | 500 | 32 |
