# 1.1.0 验收记录

日期：2026-09-07；实际平台：macOS。

| 项目 | 实际结果 |
|---|---|
| Python 3.14.6 全套测试 | **156 passed in 7.23s** |
| Python 3.11.15 全套测试 | **156 passed in 7.40s** |
| 默认 JSON、别名、pretty、错误、JSONL、stdin | CLI 套件包含真实子进程、回环 DNS、SIGINT、未关闭输入管道、配置预算与 Unicode 控制字符 |
| 人用界面 | 7 个参数化场景，限制宽度/行数，区分全部观测和重复样本，不修改原报告 |
| 源码导出 | 3 个参数化场景，精确白名单、可重复 ZIP、哈希、源目录不变、拒绝符号链接 |
| sdist 解包后的完整测试 | **156 passed in 7.35s** |
| 用户安装命令 | 1.1.0 在仓库外可用；默认/pretty JSON、schema、错误和离线 compare 验证通过 |
| wheel/sdist | 构建成功；3 个 schema 均随 wheel 打包并通过校验；无本机网络配置和诊断工件 |
| 文档示例 | 本机合成 DNS 服务生成 `examples/report.json`、`summary.json`、`terminal.txt`；完整报告通过 schema |
| 公开源码包链接 | 相对 Markdown 链接检查通过 |
| Docker | daemon 未运行；Dockerfile 已准备，未声称通过容器实测 |

新增两个独立参数化测试组，另在现有 CLI 组内扩展输出/输入边界用例。格式及 stdin 修复有 RED/GREEN/revert-to-RED 证据；测试证据位于 `tests/evidence-cli-polish.md` 和 `tests/evidence-presentation-release.md`。

Linux/Windows 工作流尚未在 GitHub 执行。Windows 为实验性 job。GitHub 地址和许可证未确定前不上传仓库或对外发布。
