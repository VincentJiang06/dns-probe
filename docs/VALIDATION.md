# 1.0 初始交付验收（历史记录）

2026-09-07，macOS，Python 3.14.6。

| 验收 | 实际结果 |
|---|---|
| `.venv/bin/python -m pytest -q` | **130 passed in 5.20s** |
| 独立复核的最终针对性验收 | **34 passed in 0.44s** |
| `.venv/bin/python -m build --no-isolation` | wheel 与 sdist 成功生成 |
| wheel 独立环境安装 | 成功，不依赖仓库源码路径 |
| 独立环境命令 | capabilities、schema、plan、compare、explain、dnstk --help 均通过 |
| 2 秒预算真实 quick 试跑 | execution completed，exit 0，assessment pass，20/20 checks completed |
| 此次引擎耗时与输出 | **255.462 ms**，30 条观测，25 次可见 DNS 尝试、5 次辅助调用，摘要 **2399 bytes** |
| 真实报告校验 | report JSON Schema 通过；工件 SHA-256 与磁盘内容一致 |
| 打包隐私检查 | wheel 含 3 个 schema；wheel/sdist 不含历史诊断、Surge 配置、结果工件 |

真实试跑命令：`dnsprobe run --agent --profile quick --budget 2s --artifact-dir .artifacts/live-smoke`。这次耗时只描述本机当时网络，未声称其他网络同样快，也不把系统/代理可能提供的合成结果当作已验证的公共上游身份。

测试中的网络服务器均在本机回环。另行授权的上述公开控制名试跑是唯一真实公网验收，不是容量压测。Linux/Windows CI 矩阵已经配置，本次没有这些平台的实机结果。

每个模块和独立复核的 RED/GREEN 证据保存在 `tests/evidence-*.md`。
