#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dnstk · DNS 工具族统一入口
==========================

三个测量工具 + 一个系统探针, 全部从这里调用:

  人用模式(完整彩色输出, 参数与底层工具完全一致):
    python3 dnstk.py bench [-s IP]... [--domestic|--abroad] [-r N] ...
    python3 dnstk.py hk    [-s IP]... [--intl|--cn] [-r N] [--quick] ...
    python3 dnstk.py lab   [--profile quick|standard|marathon] [-s IP]...
    python3 dnstk.py sys                        # 查看本机 DNS 与代理接管状态

  Agent 模式(静默测量, stdout 只输出一行 JSON, 退出码表达成败):
    python3 dnstk.py agent bench [-s IP]... [--no-ping]
    python3 dnstk.py agent hk    [-s IP]...
    python3 dnstk.py agent lab   --profile quick -s IP ...   # lab 请显式选档
    python3 dnstk.py agent sys
    追加 --brief 可去掉 data 明细, 只留结论(ok/warnings/recommend), 更省 token。

Agent JSON envelope 结构:
    {
      "ok": true,              # 退出码 0 且成功产出数据
      "mode": "bench|hk|lab|sys",
      "elapsed_s": 3.2,
      "warnings": ["fake_ip_proxy", "nxdomain_hijack:1.2.3.4", ...],
      "recommend": {"primary": {...}, "backup": {...}},   # 按 score 排序, backup 优先异组
      "data": {...}            # 底层工具的完整 JSON payload(--brief 时省略)
    }
  warnings 约定: fake_ip_proxy=代理TUN接管; nxdomain_hijack:IP=NXDOMAIN劫持;
  burst_throttle:IP=并发限流; unreachable:IP=不可达。

退出码: 0 成功 · 1 测量失败或异常 · 2 用法错误。
依赖: Python 3.10+, 与四个模块同目录。
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import sys
import tempfile
import time

import dns_bench
import dns_bench_hk
import dns_core
import dns_lab

MODES = {"bench": dns_bench, "hk": dns_bench_hk, "lab": dns_lab}
MODE_HELP = {
    "bench": "快速跑分: 查询延迟 + ICMP + 劫持检测 (数秒)",
    "hk":    "香港场景: 港/国际/大陆三组加权 + CDN 调度对比 (数十秒)",
    "lab":   "深度诊断: 五阶段, quick/standard/marathon 三档 (1/6/30 分钟)",
}


# ══════════════════════════════════════════════════════════════════ 人用模式


def run_human(mode: str, args: list[str]) -> int:
    """直接转发给底层工具, 完整彩色输出与交互行为不变。"""
    return MODES[mode].main(args)


def run_sys(agent: bool = False) -> int:
    cur = dns_core.system_dns()
    fake = dns_core.has_fake_ip(cur)
    if agent:
        print(json.dumps({"ok": True, "mode": "sys", "system_dns": cur,
                          "fake_ip_proxy": fake},
                         ensure_ascii=False, separators=(",", ":")))
        return 0
    print("  本机当前 DNS: " + ("  ".join(cur) if cur else "(未检出)"))
    if fake:
        print("  ⚠ " + dns_core.FAKE_IP_WARNING)
    else:
        print("  ✓ 系统 DNS 不在 fake-IP 段, 测量结果不受代理 TUN 干扰")
    return 0


# ══════════════════════════════════════════════════════════════════ Agent 模式


def _emit_json(obj: dict) -> None:
    """单行紧凑 JSON —— agent 读一行就够, 最省 token。"""
    print(json.dumps(obj, ensure_ascii=False, separators=(",", ":")))


def run_agent(mode: str, args: list[str], brief: bool = False) -> int:
    if "-h" in args or "--help" in args:
        # 帮助请求直接走人用模式, 避免 help 被 stdout 缓冲吞掉
        return run_human(mode, args)

    if "--json" in args:
        _emit_json({"ok": False, "mode": mode,
                    "error": "agent 模式不支持 --json: 结果本身就是 JSON 输出"})
        return 2

    dns_core.reset_agent_events()
    fd, tmp = tempfile.mkstemp(prefix="dnstk-", suffix=".json")
    os.close(fd)
    argv = args + ["--color", "never", "--json", tmp]

    buf = io.StringIO()
    started = time.time()
    try:
        with contextlib.redirect_stdout(buf):
            rc = MODES[mode].main(argv)
    except KeyboardInterrupt:
        rc = 130
    except SystemExit as exc:            # 底层 argparse 用法错误等
        rc = exc.code if isinstance(exc.code, int) else 1
    except Exception as exc:             # 兜底: agent 永远拿到 JSON 而非 traceback
        _emit_json({"ok": False, "mode": mode,
                    "error": f"{type(exc).__name__}: {exc}"})
        return 1
    finally:
        pass

    payload = {}
    try:
        with open(tmp, encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, json.JSONDecodeError):
        pass
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass

    if rc != 0 or not payload:
        tail = " ⏎ ".join(buf.getvalue().splitlines()[-3:]) if rc != 0 else ""
        _emit_json({"ok": False, "mode": mode, "returncode": rc,
                    "error": "measurement failed", "detail": tail[:400] or None})
        return 1 if rc == 0 else (2 if rc == 2 else 1)

    envelope = dns_core.agent_envelope(mode, payload, time.time() - started)
    if brief:
        envelope.pop("data", None)
    _emit_json(envelope)
    return 0


# ══════════════════════════════════════════════════════════════════ CLI


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dnstk", description="DNS 工具族统一入口 (bench / hk / lab / sys / agent)",
        epilog="示例: dnstk bench --domestic · dnstk agent lab --profile quick -s 223.5.5.5")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, help_ in MODE_HELP.items():
        sub.add_parser(name, add_help=False, help=help_ + " · 其余参数原样透传")
    sysp = sub.add_parser("sys", help="查看本机 DNS 与 fake-IP 代理接管状态")
    ag = sub.add_parser("agent", help="静默测量 + 单行 JSON 输出(供 agent 调用)")
    ag.add_argument("mode", choices=list(MODES) + ["sys"],
                    help="bench | hk | lab | sys")
    ag.add_argument("--brief", action="store_true",
                    help="省略 data 明细, 只输出 ok/warnings/recommend 结论")
    return p


def _historical_main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args, extra = parser.parse_known_args(argv)

    if args.cmd == "agent":
        if args.mode == "sys":
            return run_sys(agent=True)
        return run_agent(args.mode, extra, brief=args.brief)
    if args.cmd == "sys":
        return run_sys()
    return run_human(args.cmd, extra)


def main(argv=None) -> int:
    """Route the historic script name through the explicit DNSProbe v1 adapter."""
    from pathlib import Path
    import sys
    source = str(Path(__file__).resolve().parent / "src")
    if source not in sys.path:
        sys.path.insert(0, source)
    from dnsprobe.legacy import main as compatibility_main
    return compatibility_main(argv, mode=None)


if __name__ == "__main__":
    sys.exit(main())
