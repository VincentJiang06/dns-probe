# 1.x 实现与验收边界

日期：2026-09-07。本文件描述当前代码，避免把拟议功能当作已发布能力。1.2 的快捷语法、答案视图和命名调整见 CHANGELOG。

## 已交付

- 可安装 Python 包及 `dnsprobe` / `dnstk` 命令。无子命令等价于 run；JSON、NDJSON、人用文本共享一个引擎。源码旧脚本有明确的兼容层。
- 严格、有界的 JSON 请求；配置字段、endpoint、DNS 名、fixture、信任锚、参数优先级均校验。无隐式配置读取和交互。
- 墙钟、次数、全局/端点并发、令牌桶速率和证据体积预算；重试、TCP 回退、深入检查和持续会话共享调度。原生系统解析使用可终止独立 helper。
- system、UDP、TCP、DoT、DoH、DoQ；DNS question/ID/source 校验，IPv4/IPv6，TLS 主机名/CA 校验，数值 bootstrap，连接复用，源接口地址绑定。
- DNS 基础语义及明确期望、受控 NXDOMAIN/NODATA、TCP、实际 TC 回退、EDNS/EDE、DNSSEC fixture 行为、记录集、CNAME、委派、DNS64、ECS、NSID/id.server、本地 DNSSEC 签名链和否定证明；显式 APP.CONNECT。
- 分离 execution、assessment、coverage；观测、检查和 finding 互相引用；保留失败与取消；原子完整报告与证据文件、SHA-256；离线 explain / compare。
- quick/standard/deep 与 general/hong-kong/mainland/custom；显式 observe/bench 保留逐目标时间序列，共享全会话预算。
- 独立复核回归覆盖私有 fixture 和委派泄漏、合成地址排名、CNAME 取消引用、无关 RR owner、SERVFAIL 假通过、内部异常、跨会话预算和比较条件。

## 有意保留的边界

| 能力 | 当前边界与报告行为 |
|---|---|
| “全部测试” | 前置条件不足记 skipped/inconclusive，不补造通过。all 会将未完成的必要检查体现为退出码 3。 |
| 权威侧出口观察 | `IDENTITY.OBSERVE` 声明 available=false；需要额外运营权威观察服务，当前没有外部基础设施。 |
| DNSSEC 真值 | 受控 fixture 及其过期时间由用户提供；本地验证的 DS/DNSKEY 锚由用户管理。没有在线锚更新或长期固定的第三方真值域名。 |
| DNSSEC 验证 | 实际执行密码学签名和 DS 链验证，支持已覆盖的 NSEC/NSEC3 否定证明；NSEC3 opt-out、高迭代、未支持的算法/策略、复杂 wildcard 正向证明等返回 inconclusive。不是通用递归验证服务器。 |
| EDNS / 截断 | 使用 1232-byte EDNS payload，记录 EDE 和实际 TCP 回退；没有对每个 MTU、分片路径作穷举。未观察到 TC 不宣称已验证截断恢复。 |
| 委派 | 从指定/内置根逐层查找一条有界委派路径，校验 referral 和 glue 所属；不穷举所有 NS、根和路由，也不做 AXFR。 |
| 缓存 / 身份 | 首次、重复和连接复用观测分开；不证明缓存冷暖。NSID/ECS 为自报/回显，fake-IP 不证明上游身份；不判断浏览器 DNS 泄漏。 |
| 性能 | p95/p99 只在 20/100 成功样本后显示。推荐是当前目标、当前网络、足量可靠样本下的观测筛选；无全球最优或 95% 置信度断言。 |
| bench / compare | bench 为有界诊断采样，非容量压测。compare 严格检查实现、环境、策略和日程；性能回归字段保守为 null，不伪造显著性结论。 |
| Workload | 保留香港/大陆/国际域名场景；没有恢复历史 45/40/15 加权综合评分，避免缺组时得出失真排名。 |
| 自动追加 | 基础失败有界重试、TC 触发 TCP；深入项目按 profile/显式列表运行，没有依赖 LLM 的开放式追加。 |
| 接口 / 系统路径 | interface 绑定选定接口的源地址，不能保证内核实际从该接口发包。原生系统解析不支持强制接口；未知 RCODE/TTL/AD/upstream 留空。原生只支持 A/AAAA，其他类型明确 skipped；自动模式有适用 wire DNS 时由 wire 路径承担必要检查。显式 @system 查询其他类型为未完成，不误报 DNS 故障。 |
| 平台 | macOS/Linux 的 GitHub CI 已在 Python 3.11/3.14 分别通过 187 项测试、构建与 wheel 安装检查。Windows 两个 Python 版本均有 9 项失败（发现预算、网卡枚举与进程检测等），继续标为 experimental；详见 VALIDATION-1.2.md。Linux 使用 resolvectl 状态 fallback，不声称完成 D-Bus 原生集成。 |

这些边界是可观察性、外部基础设施或后续专业功能的边界；接口会显式暴露它们。有关运行命令以 README 和 `dnsprobe --help` / `dnsprobe run --help` 为准。

## 本地回归证据

各模块的初始 RED、GREEN、bug fix revert-to-RED 和独立复核记录在 `tests/evidence-*.md`。协议测试使用真实回环服务，证书和 DNSSEC 测试使用本地生成的密钥/签名；不需要外部 DNS 服务。

构建产物只包含包代码、schema 和明示的项目文档/测试；原工作目录中的历史网络结果、Surge 配置、下载规则与 `.artifacts` 不进入 wheel/sdist。
