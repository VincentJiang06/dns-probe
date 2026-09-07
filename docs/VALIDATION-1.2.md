# 1.2.0 验收记录

日期：2026-09-07；本次实际运行平台：macOS。产品名 DNS Probe，distribution `dns-probe`，许可证 MIT。

## 验收范围

- CLI 位置参数、大写 RR 类型、`@resolver`、参数混排、`-d/-t/-r` 与 `--human`。
- 显式 `-t mx` 的大小写归一化；JSON 请求的严格类型校验和小写位置域名语义保留。
- 人用答案表的路径、记录、TTL、重复折叠、长值省略、控制字符和无响应边界。
- 系统原生查询的能力边界，以及 wire DNS 的独立行为。
- 原有 UDP/TCP/TLS/HTTPS/QUIC、DNSSEC、预算、取消、期望、私有路由、JSON/JSONL 与报告测试。
- wheel/sdist、MIT 元数据、schema、合成示例、导出清单和本地 Git 范围。

本轮在既有 CLI 与展示参数化组中扩展用例；原生能力边界增加一个参数化回归组。已有断言未弱化，无重复或过时测试需要删除。行为修复均记录初始 RED、GREEN 和回退验证；独立复核记录在 `tests/evidence-cli-ergonomics.md`、`tests/evidence-answer-view.md` 及引擎测试证据中。

## 实际结果

| 项目 | 结果 |
|---|---|
| Python 3.14.6 全套测试 | **187 passed in 8.58s** |
| Python 3.11.15 全套测试 | **187 passed in 6.94s** |
| sdist 解包代码的完整测试 | **187 passed in 8.46s**；使用包内源码、测试与脚本 |
| Python 3.11 独立 wheel 环境 | 仓库外 `python -I -m dnsprobe` 的版本、快捷语法、小写类型与 plan 通过 |
| 用户安装 | 旧 `dnsprobe-agent` 已迁移为 `dns-probe 1.2.0`；仓库外 `dnsprobe` 可用 |
| wheel / MIT | 包名、版本、`License-Expression: MIT`、LICENSE 字节一致；3 个 schema 均有效 |
| 文档命令 | 62 条命令离线语法与请求校验；另外检查参数混排、保留词、IPv6、URL 与错误分支 |
| 合成示例 | 当前引擎生成 3 个检查、5 个观测，通过报告 schema；终端与 JSON 同源 |
| 实际网络 quick 冒烟 | 系统原生、UDP、DoH 各 1 次 A 查询，均 pass / exit 0；进程墙钟分别约 450、162、278 ms |

网络冒烟只说明本机、该域名、该时刻的路径可用，不代表速度排名或所有网络行为通过。首次同时启动三个已安装进程、每个预算 1.5 秒时，系统发现阶段耗尽预算，三者均正确返回 unknown / exit 3，未生成 DNS 观测；随后使用默认 quick 的 5 秒预算逐次验证通过。短预算包含发现开销，不能保证冷启动一定完成。

本机离线安装首次使用 uv 默认 Python 时缺少对应平台缓存；明确使用已验收的 Python 3.14 后完成安装。实际发行可联网安装依赖，或预备与目标 Python 匹配的缓存。没有把中间失败记录为成功。

最后文档补充之后重新构建制品；发布检查同时确认 Python 源码、测试和脚本字节与通过测试的 sdist 解包目录一致。最终哈希以 `dist/SHA256SUMS` 与 `release/source-manifest.json` 为准。

## 平台与发布限制

Linux/Windows 的 GitHub Actions 配置已准备，本会话尚未取得远端执行结果。Windows 仍为实验性任务。Docker 客户端存在，但本机 daemon socket 不存在，未执行镜像构建或容器实测。

公开示例由本地合成 DNS 服务生成，环境发现替换为明确标注的 fixture，避免导出真实机器信息。公网冒烟结果如果运行，只写入忽略的本地诊断目录，不作为示例或解析器排名。

本地 Git 和发布文件准备不代表已经创建远端仓库、推送源码或发布 PyPI 包。
