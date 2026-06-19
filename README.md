# ASNIPtest

从 **ASN 编号** 出发，自动完成 IP 段拉取 → 端口扫描 → Cloudflare 反代节点检测，输出可用 CF 节点 CSV。

---

## 目录

- [快速开始](#快速开始)
- [安装](#安装)
  - [Linux / macOS](#linux--macos)
  - [Windows（WSL2）](#windowswsl2)
- [使用](#使用)
  - [命令行模式](#命令行模式)
  - [交互模式](#交互模式)
- [工作流程](#工作流程)
- [输出格式](#输出格式)
- [硬件自适应](#硬件自适应)
- [依赖](#依赖)
- [卸载](#卸载)

---

## 快速开始

**Linux / macOS**
```bash
curl -fsSL https://raw.githubusercontent.com/e13815332/ASNIPtest/main/install.sh | bash
```

**Windows**（需先装 WSL2）
```powershell
# PowerShell 管理员模式，装完重启
wsl --install

# 重启后进 Ubuntu 终端
curl -fsSL https://raw.githubusercontent.com/e13815332/ASNIPtest/main/install.sh | bash
```

---

## 安装

### Linux / macOS

一条命令安装所有依赖（masscan、prips）并注册全局命令：

```bash
curl -fsSL https://raw.githubusercontent.com/e13815332/ASNIPtest/main/install.sh | bash
```

安装完成后，在任意目录输入 `cmtjd` 即可启动。

> **手动安装**：如果不想用一键脚本，可以 clone 仓库后手动运行 `python3 run.py`。需自行安装 masscan 和 prips。

### Windows（WSL2）

Windows 10/11 自带 WSL2，装上就能用 Linux 环境：

**第一步：安装 WSL2**

PowerShell 管理员模式运行：

```powershell
wsl --install
```

系统会自动安装 Ubuntu + WSL2 内核。完成后**重启电脑**。

**第二步：安装 ASNIPtest**

重启后开始菜单会多一个「Ubuntu」应用，打开它，输入：

```bash
curl -fsSL https://raw.githubusercontent.com/e13815332/ASNIPtest/main/install.sh | bash
```

> WSL2 默认使用桥接模式，正式测试时需调整为 NAT 模式才能正常使用 masscan。

---

## 使用

### 命令行模式

直接指定 ASN 编号启动扫描：

```bash
cmtjd AS209242                 # 单个 ASN，默认端口
cmtjd AS209242,AS3214          # 多个 ASN（逗号分隔）
cmtjd AS209242 AS3214          # 多个 ASN（空格分隔）
cmtjd AS209242 -p 80             # 单端口
cmtjd AS209242 -p 1-1000          # 任意范围
cmtjd AS209242 -p 80,443,8000-9000  # 混合
```

> 手动运行时用 `python3 run.py` 代替 `cmtjd`。

### 交互模式

不带参数运行，进入交互提示：

```bash
cmtjd
```

```
  硬件: 4核 2048MB → masscan 4000pps ...

  本机公网 IP: 1.2.3.4
  地区: Tokyo, JP  运营商: xxx

  输入 ASN 编号 (多个用逗号分隔): _

  默认端口: 443,8443,2053,2083,2087,2096
  回车使用默认，或输入自定义端口 (如 80 或 1-1000 或 80,443,8000-9000): _
```

输入 ASN 后自动开始扫描。API 精筛完成后询问是否测速，用户选择后输出 CSV 下载链接。

> 测速为手动选择（TCP 延迟 + CF 下载带宽），默认跳过。

---

## 工作流程

```
用户输入 ASN
    │
    ▼
┌──────────────────────┐
│ 1. ASN → CIDR        │  RIPEStat API 查询该 ASN 广播的所有 IPv4 前缀
├──────────────────────┤
│ 2. CIDR → IP 列表    │  prips 展开 CIDR 为完整 IP 地址
├──────────────────────┤
│ 3. masscan 端口扫描   │  高速 SYN 扫描，检测开放端口
├──────────────────────┤
│ 4. cf-scanner 粗筛   │  TLS 握手检测，过滤 Cloudflare 反代节点
├──────────────────────┤
│ 5. API 精筛          │  二次验证节点可用性（TLS + 数据中心 + 地区）
├──────────────────────┤
│ 6. 手动测速（可选）    │  TCP 延迟 + CF 文件下载速度
├──────────────────────┤
│ 输出 CSV + 下载链接   │  临时 HTTP 服务提供文件下载
└──────────────────────┘
```

---

## 输出格式

运行完成后生成 CSV 文件并启动临时下载服务：

```
📥 下载链接 (临时, 按回车关闭):
http://1.2.3.4:8899/output_AS209242_20260617_120000.csv

结果: 42 条 → output_AS209242_20260617_120000.csv
```

**CSV 列说明：**

| 列 | 说明 | 示例 |
|---|---|---|
| IP地址 | Cloudflare 节点 IP | `162.159.192.1` |
| 端口 | TLS 端口 | `443` |
| TLS | TLS 版本 | `TRUE` |
| 数据中心 | CF 数据中心代号 | `HKG` |
| 地区 | 国家/地区代码 | `HK` |
| 城市 | 城市名 | `Hong Kong` |
| 网络延迟 | TCP 延迟 (ms) | `42` |
| 下载速度 | CF 下载带宽 (Mbps) | `5.12` |
| ASN | 源 ASN 编号 | `AS209242` |

> 下载链接自动检测本机 IP，同时显示局域网和公网地址（公网不同时）。按 **回车** 关闭下载服务。

---

## 硬件自适应

根据 CPU 核数和可用内存自动调整扫描参数，无需手动配置：

| 硬件配置 | masscan 速率 | cf-scanner 并发 | API 并发 |
|---|---|---|---|
| 2 核 / 1 GB | 2,000 pps | 200 | 32 |
| 4 核 / 2 GB | 4,000 pps | 400 | 32 |
| 8 核 / 8 GB | 8,000 pps | 500 | 32 |
| 16 核 / 16 GB | 16,000 pps | 500 | 32 |

> cf-scanner 并发最低 200，最高 500。masscan 速率 = CPU 核数 × 1000。

---

## 依赖

| 工具 | 用途 | 安装方式 |
|---|---|---|
| [masscan](https://github.com/robertdavidgraham/masscan) | 高速端口扫描 | `apt install masscan` 或源码编译 |
| prips | CIDR → IP 段展开 | `apt install prips` |
| cf-scanner | CF 反代节点检测 | 内置，自动编译 |
| [RIPEStat API](https://stat.ripe.net/) | ASN → CIDR | 免费公开，无需注册 |

> `install.sh` 自动处理所有依赖。

### 不支持的环境

masscan 依赖 **raw socket**（CAP_NET_RAW），以下环境有限制：

- ❌ NAT 容器（独角鲸/小鲸等，缺少 CAP_NET_RAW）
- ❌ OpenVZ / LXC 未开启特权模式
- ⚠️ WSL2 需切换为 NAT 网络模式（默认桥接不支持 raw socket）

> 换到 KVM VPS 或物理机即可正常使用。

---

## 卸载

```bash
curl -fsSL https://raw.githubusercontent.com/e13815332/ASNIPtest/main/uninstall.sh | bash
```

这会删除 `cmtjd` 命令和 `~/ASNIPtest` 目录。
