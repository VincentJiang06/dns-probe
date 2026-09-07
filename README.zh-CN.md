# DNS Probe

**一个命令，查清 DNS 到底发生了什么。**

[English](README.md) · [CLI 使用指南](docs/CLI.md) · [JSON 接入](docs/AGENT_INTEGRATION.md) · [同类项目调研](docs/COMPARISON.md) · [MIT](LICENSE)

DNS Probe 是一个日常 DNS 诊断工具。输入域名，可选解析器，就能在限定时间内检查解析结果、协议行为和重复查询情况，给出发现、证据与尚未完成的检查。终端可以直接看答案和耗时，脚本、CI 和 agent 则读取同一份 JSON 报告。

```sh
dnsprobe example.com --human
dnsprobe example.com A AAAA @1.1.1.1 --human
dnsprobe example.com @https://dns.google/dns-query --pretty
```

产品名 **DNS Probe**，命令 **`dnsprobe`**，Python 包 **`dns-probe`**。本项目与已归档的 [ProjectDiscovery dnsprobe](https://github.com/projectdiscovery/dnsprobe) 无关联。

## 安装

需要 Python **3.11+**。可直接从 GitHub 安装：

```sh
uv tool install git+https://github.com/VincentJiang06/dns-probe.git@v1.2.1
```

或克隆项目：

```sh
git clone https://github.com/VincentJiang06/dns-probe.git
cd dns-probe
```

在本项目目录执行：

```sh
uv tool install .
dnsprobe --version
dnsprobe example.com --human
```

也可以在虚拟环境中执行 `python -m pip install .`。开发时使用 `uv sync --locked`，然后 `uv run --no-sync dnsprobe example.com --human`。安装完成后直接调用 `dnsprobe`，不必每次启动包管理器。

目前尚未发布 PyPI、Homebrew 包或独立原生二进制；请从 GitHub 源码或 [Releases](https://github.com/VincentJiang06/dns-probe/releases) 中经过校验的 wheel 安装。旧的本地 `dnsprobe-agent` 包升级方法见 [迁移说明](LEGACY_MIGRATION.md)。

## 日常使用

```sh
# 使用系统适用的解析路径诊断
dnsprobe example.com --human

# 指定记录类型与解析器
dnsprobe example.com MX @1.1.1.1 --human
dnsprobe example.com @tls://one.one.one.one:853 --human
dnsprobe example.com @https://dns.google/dns-query --human

# 缩短整体预算，或只执行基础解析检查
dnsprobe example.com --profile quick --budget 2s --human
dnsprobe example.com A @1.1.1.1 --tests DNS.BASIC --human

# 多域名、多解析器
dnsprobe example.com example.org @1.1.1.1 @8.8.8.8 --human

# 私有域名只使用指定内部解析器
dnsprobe service.corp @10.0.0.53 --network-scope system --human

# 离线查看计划，不发 DNS 请求
dnsprobe plan example.com @1.1.1.1 --pretty
```

`--human` 等价于 `--format text`：展示解析答案、记录类型、TTL、解析路径，以及执行状态、问题、覆盖率与耗时。长答案和大报告会缩略，完整证据保留在 JSON 中。[终端示例](examples/terminal.txt) 来自本地合成 DNS fixture，不是公网测速成绩。

快捷类型使用域名后面的**大写**记录名，例如 `example.com A AAAA`。也可明确写 `-d/--domain`、`-t/--type`、`-r/--resolver`。小写单标签视为域名；与子命令同名的域名用 `dnsprobe run NAME`。详细规则见 [CLI 指南](docs/CLI.md)。

## JSON 与自动化

**默认输出 JSON**，终端、管道和 CI 都一样。stdout 中没有日志或进度动画，也不需要交互确认。

```sh
dnsprobe example.com                           # 紧凑 JSON 摘要
dnsprobe example.com --pretty                  # 缩进 JSON
dnsprobe example.com --jsonl                   # 增量事件与唯一终态报告
dnsprobe example.com --detail full             # 完整检查、答案和观测
dnsprobe example.com --artifact-dir .artifacts # 另存完整报告与证据
dnsprobe --request-json - < examples/request.json
dnsprobe schema --kind report
```

`--json` 显式选择 JSON；`--jsonl` 等价于 `--format ndjson`。`--pretty` 只用于 JSON。保留旧的 `--agent` 别名，但正常调用不需要它。紧凑摘要上限 8 KiB，缩进后体积会增加；完整输出与单个工件上限 64 MiB。摘要省略的记录与证据可通过完整报告获取。

程序先读 `execution.exit_code`、`assessment.status`、`coverage.sufficient_for_assessment`，再读 `findings`。进程完成不等于 DNS 健康。`next_actions[].argv` 是参数数组，应直接传给子进程，不要拼接 shell。

| 退出码 | 含义 |
|---|---|
| 0 | 必要检查证据充分，未触发失败策略 |
| 1 | 必要检查失败或触发失败策略 |
| 2 | 输入不合法 |
| 3 | 证据不足、超时或资源上限 |
| 4 | 工具内部或报告写入错误 |
| 130 | 中断，尽可能保留已有证据 |

`--fail-on never` 不会把覆盖不足、工具错误或中断变成 0。[请求示例](examples/request.json)、[完整报告](examples/report.json)、[摘要](examples/summary.json) 与 [接入指南](docs/AGENT_INTEGRATION.md) 提供可直接使用的格式。

## 检查能力与边界

- 系统原生地址解析，UDP、TCP、验证证书的 DoT、DoH、DoQ。
- RCODE、地址与 AD 期望，负响应、EDNS/EDE，截断后的 TCP 回退。
- CNAME、记录检查、有界委派追踪、DNS64、NSID 与显式 ECS。
- 使用带过期时间 fixture 检查解析器 DNSSEC 行为；使用调用者提供的信任锚验证签名、DS 链及受支持的否定证明。
- `--connect` 显式启用解析后 TCP/TLS 连通性检查，不发送 HTTP 请求。
- 重复查询和持续观察，共享时间、次数、速率、并发及证据预算。

| 模式 | 默认时间上限 | DNS 尝试上限 |
|---|---:|---:|
| quick | 5 秒 | 80 |
| standard | 15 秒 | 240 |
| deep | 60 秒 | 900 |

预算是上限，健康网络可能提前结束。`--tests all` 会逐项报告前置条件不足，不能自动创建受控测试区或信任锚。`IDENTITY.OBSERVE` 需要尚未提供的外部基础设施；DNSSEC 和 Windows 实验性支持的准确边界见 [实现状态](docs/STATUS.md)。

不指定目标时可使用内置公开控制域名。输入自己的域名后，默认走系统适用路径；自动公共比较需要 `--public-comparison`，显式解析器表示选择这些端点。已发现的私有后缀仍需逐目标许可才能进入自动公共路径。`system`/`private` scope 禁用自动公共候选与公开控制查询。详见 [查询范围](docs/CLI.md#query-scope)。

不修改系统 DNS，不清缓存，不使用环境 HTTP 代理。加密端点验证证书与主机名，无自动不安全降级。私有 CA、bootstrap 地址等通过 JSON 请求指定。

## 持续观察与比较

```sh
dnsprobe observe example.com @1.1.1.1 --duration 1m --interval 5s --human
dnsprobe bench example.com @1.1.1.1 @8.8.8.8 --duration 15s --rate 20 --human
dnsprobe explain --report report.json --finding f-001
dnsprobe compare before.json after.json
dnsprobe capabilities --pretty
```

observe/bench 都要求明确目标、解析器与时长；observe 还需间隔，bench 还需速率。所有样本共用预算，可能因资源或样本上限提前结束。bench 是诊断采样，不推断服务器容量。p95/p99 分别至少需要 20/100 个成功样本；缺少逐目标可靠证据时不推荐解析器。网络、策略或实现变化时，compare 不直接判断性能退化。

## 基于成熟组件

[dnspython](https://www.dnspython.org/) 提供 DNS 报文、记录、异步查询与 DNSSEC 基础能力；HTTPX、aioquic、cryptography 支撑加密传输和签名验证。DNS Probe 在此基础上处理系统解析路径、统一预算、证据判断与报告，不要求机器安装 `dig`。

CLI 语法参考 [doggo](https://github.com/mr-karan/doggo)、[q](https://github.com/natesales/q)，JSONL 和明确测量边界参考 dnsx、iperf3。采用理由与不采用的部分见 [调研与复用决策](docs/COMPARISON.md)，未复制这些项目的实现代码。

## 开发与发布

```sh
uv sync --locked
uv run --no-sync pytest -q
uv run --no-sync python -m build --no-isolation
uv run --no-sync python scripts/check_distribution.py
uv run --no-sync python scripts/prepare_release.py --require-license --output release
```

测试使用离线 DNS 报文与本地 UDP/TCP/TLS/HTTPS/QUIC 服务。GitHub CI 已在 macOS/Linux 的 Python 3.11/3.14 上分别通过全部 187 项测试、构建和 wheel 安装检查。Windows 仍为实验性：首次 CI 有 9 项失败，涉及发现阶段预算与平台相关测试。实际记录和边界见 [验证](docs/VALIDATION-1.2.1.md)。

源码导出采用明确文件范围与 SHA-256 清单，排除本地网络报告和无关文件。参阅 [发布说明](docs/RELEASING.md)、[贡献](CONTRIBUTING.md)、[安全](SECURITY.md)、[变更记录](CHANGELOG.md)。

本项目采用 [MIT 许可证](LICENSE)。
