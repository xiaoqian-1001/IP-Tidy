# 10 个 CF IP 扫描测速仓库完整拆解分析

## 一、各仓库核心定位速览

| 仓库 | 语言 | 核心定位 | 独特价值 |
|---|---|---|---|
| **CFScanner** (MortezaBashsiz) | Go/Python/Bash | CF IP 扫描 + XRay 端到端验证 | Server-Timing 头部解析、蓄水池采样、抖动计算 |
| **better-cloudflare-ip** (badafans) | Go | 两阶段 RTT→带宽优选 | CF-RAY 白名单验证、滑动窗口峰值、4 阶段探测 pipeline |
| **Cloudflare-IP-SpeedTest** (badafans) | Go | IP 延迟+下载测速+位置识别 | TCP 连接复用 HTTP 探测、位置缓存 |
| **Cloudflare-IP-SpeedTest** (bh-qt) | Go | 同上 + Worker 代理 | `/cdn-cgi/trace` 位置探测、Worker 代理测速 |
| **iptest** (Kwisma) | Go | IP 质量多维检测 | Trace 响应全字段解析、出站 IP 类型分类 |
| **CFST-GUI** (axuitomo) | Go+Vue | 全平台 GUI + WebUI | Range 分片测速、完整性校验、COLO 字典系统、CIDR 集合运算 |
| **yx-tools** (byJoey) | Python | 小白一键测速+反代 | 多策略下载回退链、`sys.stdin.isatty()` 双接口分流 |
| **cfip-tools** (HandsomeMJZ) | C+Python | 按区域 Top-N 优选 | 最小堆区域筛选、`curl --resolve` DNS 绕过 |
| **SenPaiScanner** (MatinSenPai) | Go | DPI 感知扫描+邻居扩展 | 超时预算拆分、空闲保持检测、SNI 轮换 |
| **cdn-ip-scanner** (shahinst) | Python | Web 端多 CDN 扫描 | Round-robin 采样、5 次顺序验证、TCP 预过滤 |

## 二、按功能维度的借鉴点

### 2.1 IP 生成与采样

| 借鉴点 | 来源 | 说明 |
|---|---|---|
| **蓄水池采样** | CFScanner (Python) | 引入 `reservoir_sampling` 替代大段 CIDR 的全量枚举，O(n) 时间复杂度、O(k) 内存 |
| **Round-robin /24 轮询** | cdn-ip-scanner | 混合大小 CIDR 时，拆 /24 后轮询采样，避免大段淹没小段 |
| **加权随机 CIDR 选择** | SenPaiScanner | 按 CIDR 地址空间大小加权，大段命中概率高，适合随机抽样场景 |
| **邻居 IP 扩展** | SenPaiScanner | 发现健康 IP 后在其 `/32` 两侧 ±1..N 扩展探测，比固定 /16 扩展更精细 |

### 2.2 TCP/HTTP 探测与位置识别

| 借鉴点 | 来源 | 说明 |
|---|---|---|
| **CF-RAY 白名单验证** | better-cloudflare-ip | RTT 阶段校验 `CF-RAY` 响应头存在，确保到达 Cloudflare 网络 |
| **`/cdn-cgi/trace` 位置探测** | bh-qt / badafans / iptest | HTTP GET 获取 `colo=XXX` 字段，替代第三方 API 查位置 |
| **Server-Timing 头部解析** | CFScanner | 从 CF 响应头解析 `dur=0.123` 分离服务器处理时间，获取真实网络延迟 |
| **TCP 连接复用 HTTP 探测** | badafans / bh-qt | TCP 建连后通过 `Transport.Dial` 注入同一 conn 做 HTTP，避免二次握手 |
| **超时预算拆分** | SenPaiScanner | TCP 1/4 + TLS 1/2 + HTTP 1/4 分阶段分配超时 |

### 2.3 测速与进度

| 借鉴点 | 来源 | 说明 |
|---|---|---|
| **Range 分片并行测速** | CFST-GUI | HTTP Range 分片并发下载 + 随机偏移避免 CDN 缓存 |
| **滑动窗口峰值检测** | better-cloudflare-ip | 1s 窗口 + 尾窗口丢弃，比简单平均更反映真实带宽 |
| **预热期排除** | CFST-GUI | 前 1s 流量不计入有效测量，避开 TCP 慢启动阶段 |
| **完整性校验** | CFST-GUI | 下载后校验 Content-MD5/Digest 头，确保数据完整 |
| **心跳回退进度** | CFST-GUI | stage-level 冷却机制，连续失败触发冷却 |

### 2.4 筛选与排序

| 借鉴点 | 来源 | 说明 |
|---|---|---|
| **最小堆区域 Top-N** | cfip-tools | 每区域维护大小为 N 的最小堆，heapushpop 淘汰最差，O(n log N) |
| **多维度评分系统** | cdn-ip-scanner / SenPaiScanner | 按延迟/丢包率/抖动/吞吐量多级评分 |
| **双模式排序 Fallback** | bh-qt / badafans | 有测速按速度降序，无测速按延迟升序 |

### 2.5 并发控制

| 借鉴点 | 来源 | 说明 |
|---|---|---|
| **信号量 + 原子计数** | CFST-GUI / SenPaiScanner | buffered channel 信号量限流 + `atomic.Int32` 无锁统计 |
| **暂停/恢复通道** | CFScanner (Go) | 键盘事件驱动 pauseChan/resumeChan |
| **Rate limiter 限速** | SenPaiScanner | 添加可配置的全局速率限制 |
| **结果通道管道** | bh-qt | 探测结果走 `resultChan` → consumer worker 做后处理 |

### 2.6 设施与可靠性

| 借鉴点 | 来源 | 说明 |
|---|---|---|
| **多策略下载回退链** | yx-tools | request → wget → curl → urllib 四级回退 |
| **DNS 阻塞预检** | CFScanner | 扫描前检查 `speed.cloudflare.com` 是否可达 |
| **空闲保持 DPI 检测** | SenPaiScanner | TLS 建立后静置检测是否被 DPI 阻断 |
| **SNI 轮换** | SenPaiScanner | 多域名轮换作为 SNI，避免 DPI 黑名单 |
| **配置热加载 + 环境变量注入** | cfip-tools / yx-tools | config 文件 + 命令行覆盖 + 环境变量三层优先级 |

## 三、高优先级落地建议（按收益排序）

### P0 — 实测可见的收益

**1. CF-RAY 白名单验证 + `/cdn-cgi/trace` 位置探测**（better-cloudflare-ip / bh-qt）
- 在 RTT 探测阶段验证 `CF-RAY` 响应头，确保 IP 真实属于 Cloudflare 网络
- 从 `/cdn-cgi/trace` 直接获取 `colo=XXX` 数据中心代码
- 实现成本：每个探测请求增加一次 HTTP HEAD，复用 TCP 连接

**2. Range 分片并行测速**（CFST-GUI）
- 当前下载测速是单线程全量下载，改为 Range 分片 + 4-8 并发
- 预热期 1s + 滑动窗口峰值统计
- 预计速度测量精度 + 20-30%

**3. 滑动窗口峰值 + 预热期丢弃**（better-cloudflare-ip）
- 当前测速按全量下载算平均速度，改为 1s 窗口算瞬时峰值
- 前 1s 数据丢弃（TCP 慢启动期）

**4. TCP 连接复用 HTTP 探测**（badafans / bh-qt / iptest）
- 当前 TCP 连通测试和 HTTP 探测是两次独立建连
- 复用 TCP 连接减少约 1 次 RTT 的握手开销

### P1 — 架构优化

**5. 蓄水池采样处理大 CIDR**（CFScanner）
- `step_deep_mine` 当前扩展 /16 CIDR 后暴力全量 masscan
- 引入蓄水池采样对超大 CIDR 做代表性抽样，降低扫描量

**6. 最小堆区域 Top-N**（cfip-tools）
- 当前结果收集后全量排序再裁剪
- 每数据中心维护大小为 N 的最小堆，O(n log N)

**7. 超时预算拆分**（SenPaiScanner）
- 当前探测使用单一超时值
- 改为 TCP 1/4 + TLS 1/2 + HTTP 1/4 分阶段预算

### P2 — 体验与鲁棒性

**8. 多策略下载回退链**（yx-tools）
- `_ensure_cfst_binary` 当前使用 urlretrieve 单一下载
- 加入 urllib → requests → wget → curl 四级回退

**9. DNS 阻塞预检**（CFScanner）
- 扫描前检查 `speed.cloudflare.com` 解析结果
- DNS 被劫持返回私有地址时给出明确提示后退出

**10. 两阶段管道 + 结果通道**（bh-qt / cfip-tools）
- 延迟探测走 `resultChan` → consumer worker 做下载测速
- 解耦探测与消费，天然支持双阶段 pipeline

## 四、与当前项目架构的冲突评估

| 建议 | 与当前架构冲突 | 迁移成本 |
|---|---|---|
| CF-RAY 验证 + trace 探测 | 低 — 在现有 RTT 模块中加一个 HTTP 请求即可 | 低 |
| Range 分片测速 | 中 — 当前测速调用外部 cfst 二进制，Range 需要内部实现 | 中 |
| TCP 连接复用 | 低 — 修改 http client 的 Transport.Dial | 低 |
| 蓄水池采样 | 中 — 需要在 masscan 前增加采样逻辑 | 中 |
| 最小堆排序 | 低 — 替换现有 sort.Slice | 低 |
| 超时预算拆分 | 低 — 修改超时参数计算 | 低 |
| 多策略下载 | 低 — 包装现有下载函数 | 低 |
| DNS 预检 | 低 — 启动时增加一次 DNS 查询 | 极低 |
| 两阶段管道 | 中 — 需重构探测流程为 generator + consumer 模式 | 中 |

---

*分析日期: 2026-07-01*
*覆盖仓库: CFScanner, better-cloudflare-ip, Cloudflare-IP-SpeedTest(x2), iptest, CFST-GUI, yx-tools, cfip-tools, SenPaiScanner, cdn-ip-scanner*
