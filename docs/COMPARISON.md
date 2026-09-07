# GitHub 同类项目调研与采用决策

检索日期：2026-09-07。下面是官方仓库/文档公开说明的能力，不是本机对这些工具做的性能测评。没有复制其实现代码。

| 项目 | 主要定位与做法 | DNS Probe 采用的做法 |
|---|---|---|
| [doggo](https://github.com/mr-karan/doggo) | 面向人的 DNS 查询工具；表格/颜色、JSON、显式协议、追踪；README 给出可复制示例和 `jq` 用法 | JSON 与人用表格共享结果；首屏直接展示命令、输出与安装；不让 agent 解析装饰性终端文本 |
| [q](https://github.com/natesales/q) | 小型多协议 DNS 客户端；独立 output/transport；pretty/column/json/yaml/raw；源码安装和发行制品 | 保留独立报告层和传输层；清晰格式参数、完整 JSON 证据；不把展示逻辑放进探测代码 |
| [dnsx](https://github.com/projectdiscovery/dnsx) | 批量 DNS 工具；stdin/stdout、JSONL、可省略原始响应、速率和重试控制、集成测试 | 单次 JSON 与流式 JSONL 分开；摘要保留决定和证据索引，完整数据按需输出；次数/速率限制明确 |
| [iperf3](https://github.com/esnet/iperf) | 明确客户端/服务端的带宽测量；JSON 和 line-delimited JSON 可用于程序集成；极限优化需显式开启 | 完整终态与增量事件分开；持续测量必须显式时长；不把快速诊断叫容量测试 |
| [Trippy](https://github.com/fujiapple852/trippy) | traceroute + ping 的持续诊断；清楚的安装、平台、权限、列和配置文档，展示实际使用画面 | 终端表格优先展示路径、协议、样本与时延；文档明确测试环境与平台边界；暂不加入依赖 TTY 的全屏界面 |
| [netshoot](https://github.com/nicolaka/netshoot) | 在 Docker/Kubernetes 网络命名空间中组合多种工具，按故障场景给出用法 | 报告写明观测所在环境；提供容器构建方式与网络命名空间说明，不把容器 DNS 当宿主机 DNS |

来源细节：[doggo README](https://raw.githubusercontent.com/mr-karan/doggo/main/README.md)、[q release 配置](https://github.com/natesales/q/blob/main/.goreleaser.yml)、[iperf3 调用文档](https://software.es.net/iperf/invoking.html)。

## 产品定位

DNS Probe 以 **一次有预算的调用，产出诊断、覆盖范围、证据和下一步参数** 为中心。现有工具各有擅长的查询、批量扫描、追踪或吞吐量测量；本项目优先做好普通终端使用，同时保持供脚本、CI 和 agent 消费的 JSON 协议稳定。

目前保留 Python/asyncio。为了模仿 Go 项目的单文件发行而立即重写语言，会增加协议和取消行为的回归面。现阶段发行 wheel/sdist、校验和与干净源码包；安装后直接调用 console script。独立原生二进制只有通过各平台验收后才列为下载选项。

## 本轮落地

1. 默认紧凑 JSON；`--json`、`--jsonl` 为短入口，`--pretty` 用于可读 JSON；`--human` / `--format text` 输出人用表格，并展示答案、TTL 与来源路径。
2. 无论 TTY、管道、CI 或 agent，默认行为相同；结构化错误保留退出码。`--agent` 继续可用。
3. 终端展示执行状态、健康评估、覆盖和未验证原因；路径级时延明确样本口径；未知值用 `-`，不补零。
4. DNS 返回文本等不可信内容在终端展示时转义控制字符；JSON 保留原始数据语义。
5. 英文首页与中文说明、JSON 请求/报告示例、agent 接入指南、贡献/安全说明、变更记录与 issue 表单。
6. CI 检查协议与 CLI、schema 和包内容；发行过程先生成带校验和的可审阅制品，再由维护者发布。

## 发布与命名

[ProjectDiscovery 的 dnsprobe](https://github.com/projectdiscovery/dnsprobe) 已有同名仓库且处于归档状态。本项目与其无关联。产品名采用 **DNS Probe**，仓库名 **dns-probe**，Python distribution 为 `dns-probe`，console command 为 `dnsprobe`。GitHub 仓库由 owner 命名空间区分，无需在产品标题增加 Agent。包名尚未在 PyPI 发布或预留。安装前需留意机器上是否已有其他同名命令。

许可证已由维护者选定为 [MIT](../LICENSE)。公开仓库为 [VincentJiang06/dns-probe](https://github.com/VincentJiang06/dns-probe)。README 不展示不存在的 PyPI、Homebrew 或 GitHub release 徽章，不把尚未运行的跨平台 CI 说成已通过。使用 GitHub draft release 先检查制品，是官方支持的发布流程：[GitHub release 管理文档](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository)。

## 基于什么实现

| 组件 | 在 DNS Probe 中的职责 | 选择理由与维护要求 |
|---|---|---|
| [dnspython](https://dnspython.readthedocs.io/en/stable/async.html) | DNS 报文/记录、异步传输、DNSSEC 验证基础能力 | 直接使用结构化 API，保持记录和异常信息。当前锁定 2.8.0；自有 QUIC 取消适配依赖该版本内部接口，升级必须跑真实协议和取消测试。 |
| [HTTPX](https://www.python-httpx.org/async/) | DoH HTTP 客户端 | 复用连接与 TLS 验证，禁用环境代理，DNS 上下文仍由引擎管理。 |
| [aioquic](https://aioquic.readthedocs.io/) | DoQ 的 QUIC 传输 | 复用协议实现；受统一预算控制。没有将 DoQ 宣称为 HTTP/3。 |
| [cryptography](https://cryptography.io/en/latest/) | 密码学与证书基础能力 | 配合 dnspython 验证签名，不自写密码算法。 |
| [psutil](https://psutil.readthedocs.io/) | 本地网卡和地址枚举 | 明确绑定源地址，仍由内核决定路由。 |
| [jsonschema](https://python-jsonschema.readthedocs.io/) | 报告/schema 合约验证 | 同一套打包 schema 供 CLI、测试和集成使用。 |

上述库由锁文件管理，不将它们改写或复制进本仓库。dnspython 的异步接口支持 asyncio，符合现有调度器；替换成包装 dig/doggo 子进程会额外引入安装路径、版本和输出格式依赖，并让统一取消、次数统计、证据结构更难控制，因此没有采用。

## 普通 CLI 的具体取舍

1. 使用域名、域名后的大写 RR 类型和 `@resolver` 快捷输入，保留明确的 `-d/-t/-r`。不完整模拟 dig 的所有选项。
2. `--human` 一眼看到实际 DNS 答案，再看诊断；默认仍是 JSON，符合现有自动化调用契约。
3. 产品是 DNS 诊断工具，agent 只是接入方式之一；README 首先说明安装和日常使用。
4. 继续提供 wheel/sdist、源码包、MIT、贡献文档、CI、issue 表单和 draft release。没有实际发行的包管理渠道不展示安装命令或徽章。
