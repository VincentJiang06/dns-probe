#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DNS Bench · 本机到多个 DNS 服务器的延迟基准测试与推荐工具

功能:
  1. DNS 查询延迟 —— 自己构造 DNS 报文直连 53 端口, 逐个测 RTT(不依赖 dig/nslookup)
  2. ICMP ping    —— 系统 ping, 反映到服务器本身的链路质量
  3. 劫持检测     —— 查询随机不存在的域名, 正常应返回 NXDOMAIN, 若返回 IP 则判定劫持
最后按综合得分排序, 输出彩色排行榜 + 分场景推荐。

测量口径:
  每个服务器先用 4 个域名各做一次"预热查询"填充其缓存(结果不计入统计), 再进行正式采样,
  因此得到的延迟更接近日常浏览网页时的真实体感; 连续 3 次超时即判定不可达并提前退出。

用法:
  python3 dns_bench.py                      # 测试内置全部服务器(推荐)
  python3 dns_bench.py --domestic           # 只测国内服务器
  python3 dns_bench.py --abroad             # 只测国际服务器
  python3 dns_bench.py -s 223.5.5.5 -s 1.1.1.1
  python3 dns_bench.py --rounds 8 --top 5   # 提高采样次数, 只显示前 5
  python3 dns_bench.py --no-ping            # 跳过 ICMP, 更快
  python3 dns_bench.py --json out.json      # 导出 JSON
  python3 dns_bench.py --color always       # 强制彩色(管道/重定向时也生效)

说明: 仅用 Python 3 标准库 + 同目录 dns_core.py; 交互式 TTY 下会渲染实时面板, 非 TTY 自动降级为纯文本。
"""

from __future__ import annotations

import argparse
import concurrent.futures as futures
import json
import platform
import shutil
import statistics
import sys
import threading
import time

from dns_core import (FAKE_IP_WARNING, C_ACCENT, C_BAD, C_MUTE, C_NAME, C_OK, C_WARN,
                      Term, clip, color_of, detect_hijack, dw, gradient, is_router_cache,
                      pad, ping_host, query, rule, has_fake_ip, load_servers_file,
                      RELIABILITY_DEFAULT)
from dns_core import fmt as fmt_ms
from dns_core import system_dns as current_system_dns


def dns_query(server: str, domain: str, timeout: float, qtype: int = 1) -> float | None:
    """适配层: 只关心 RTT; rcode 0(NOERROR)/3(NXDOMAIN) 都算服务器正常应答。"""
    rtt, p = query(server, domain, qtype=qtype, timeout=timeout)
    if rtt is None or not p or p["rcode"] not in (0, 3):
        return None
    return rtt

# ──────────────────────────────────────────────────────────────── 服务器清单

# (IP, 名称, 分组)
SERVERS: list[tuple[str, str, str]] = [
    # 中国大陆
    ("223.5.5.5",       "阿里 AliDNS",     "国内"),
    ("223.6.6.6",       "阿里 AliDNS 备",  "国内"),
    ("119.29.29.29",    "腾讯 DNSPod",     "国内"),
    ("182.254.116.116", "腾讯 DNSPod 备",  "国内"),
    ("114.114.114.114", "114DNS",          "国内"),
    ("114.114.115.115", "114DNS 备",       "国内"),
    ("180.76.76.76",    "百度 DNS",        "国内"),
    ("1.2.4.8",         "CNNIC SDNS",      "国内"),
    ("210.2.4.8",       "CNNIC SDNS 备",   "国内"),
    ("117.50.11.11",    "OneDNS 纯净",     "国内"),
    ("117.50.10.10",    "OneDNS 拦截",     "国内"),
    ("123.123.123.123", "联通 DNS",        "国内"),
    ("211.136.192.6",   "移动 DNS",        "国内"),
    ("202.96.209.5",    "电信 DNS(沪)",    "国内"),
    # 国际
    ("8.8.8.8",         "Google DNS",      "国际"),
    ("8.8.4.4",         "Google DNS 备",   "国际"),
    ("1.1.1.1",         "Cloudflare",      "国际"),
    ("1.0.0.1",         "Cloudflare 备",   "国际"),
    ("9.9.9.9",         "Quad9",           "国际"),
    ("149.112.112.112", "Quad9 备",        "国际"),
    ("208.67.222.222",  "OpenDNS",         "国际"),
    ("208.67.220.220",  "OpenDNS 备",      "国际"),
    ("94.140.14.14",    "AdGuard DNS",     "国际"),
    ("94.140.15.15",    "AdGuard DNS 备",  "国际"),
]

# 延迟测试用域名(都是高频域名, 反映真实体感)
PROBE_DOMAINS = ["www.qq.com", "www.baidu.com", "www.taobao.com", "www.apple.com"]

# 场景预设(VeloDNS 思路): 按用途筛选服务器子集
PRESETS: dict[str, dict] = {
    "privacy": {
        "desc": "无日志承诺的隐私优先服务",
        "ips": {"1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
                "94.140.14.14", "94.140.15.15"},
    },
    "family": {
        "desc": "带恶意域名/广告拦截的过滤型",
        "ips": {"94.140.14.14", "94.140.15.15", "117.50.10.10"},
    },
    "uncensored": {
        "desc": "不过滤结果的纯净型(排除拦截型)",
        "ips": {"223.5.5.5", "223.6.6.6", "119.29.29.29", "182.254.116.116",
                "114.114.114.114", "114.114.115.115", "180.76.76.76", "1.2.4.8",
                "210.2.4.8", "123.123.123.123", "8.8.8.8", "8.8.4.4",
                "1.1.1.1", "1.0.0.1", "9.9.9.9", "64.6.64.6"},
    },
}
PRESETS["gaming"] = PRESETS["uncensored"]     # 低延迟无过滤, 与 uncensored 同集

# ──────────────────────────────────────────────────────────────── 终端样式






LOGO = [
    "██████╗ ███╗   ██╗███████╗    ██████╗ ███████╗███╗   ██╗ ██████╗██╗  ██╗",
    "██╔══██╗████╗  ██║██╔════╝    ██╔══██╗██╔════╝████╗  ██║██╔════╝██║  ██║",
    "██║  ██║██╔██╗ ██║███████╗    ██████╔╝█████╗  ██╔██╗ ██║██║     ███████║",
    "██║  ██║██║╚██╗██║╚════██║    ██╔══██╗██╔══╝  ██║╚██╗██║██║     ██╔══██║",
    "██████╔╝██║ ╚████║███████║    ██████╔╝███████╗██║ ╚████║╚██████╗██║  ██║",
    "╚═════╝ ╚═╝  ╚═══╝╚══════╝    ╚═════╝ ╚══════╝╚═╝  ╚═══╝ ╚═════╝╚═╝  ╚═╝",
]
GRADIENT_STOPS = [(86, 205, 245), (96, 165, 250), (167, 139, 250), (244, 114, 182)]


def draw_banner(t: Term) -> None:
    if t.color:
        for line in LOGO:
            print("  " + gradient(line, t, GRADIENT_STOPS))
    else:
        for line in LOGO:
            print("  " + line)
    sub = "DNS 延迟基准测试 · 查询延迟 / 链路延迟 / 劫持检测 → 智能推荐"
    print("  " + t.paint(sub, t.fg(int(C_MUTE))))
    print()






# ──────────────────────────────────────────────────────────────── 测试逻辑


class ProbeResult:
    """单个服务器的测试结果。"""

    def __init__(self, ip: str, name: str, group: str):
        self.ip = ip
        self.name = name
        self.group = group
        self.samples: list[float] = []
        self.samples_v6: list[float] = []      # AAAA(IPv6) 查询, 与 A 分开统计
        self.total_v6 = 0
        self.success_v6 = 0
        self.success = 0
        self.total = 0
        self.icmp: float | None = None
        self.icmp_loss: float | None = None
        self.hijack = False
        self.hijack_note: str | None = None
        self.router_cache = False              # 疑似本机路由器缓存应答(<2ms)
        self.status = "pending"   # pending | running | done
        self.error = ""

    # 派生指标
    @property
    def median(self) -> float | None:
        return statistics.median(self.samples) if self.samples else None

    @property
    def average(self) -> float | None:
        return statistics.fmean(self.samples) if self.samples else None

    @property
    def jitter(self) -> float | None:
        return statistics.pstdev(self.samples) if len(self.samples) > 1 else 0.0

    @property
    def p95(self) -> float | None:
        """95 分位延迟, 比中位数更能反映长尾抖动。"""
        if not self.samples:
            return None
        ordered = sorted(self.samples)
        idx = max(0, min(len(ordered) - 1, int(round(0.95 * (len(ordered) - 1)))))
        return ordered[idx]

    @property
    def loss(self) -> float:
        # total=0(异常路径/未真正采样)不算 100% 丢失, 与 dns_core.Stream 语义一致
        return 0.0 if not self.total else (self.total - self.success) / self.total * 100

    @property
    def score(self) -> float:
        """综合得分(0~100): 延迟 60% + 稳定性 25% + 抖动 15%, 再扣劫持惩罚。"""
        med = self.median
        if med is None:
            return 0.0
        latency_score = 60.0 * max(0.0, 1.0 - min(med, 200) / 200) ** 1.8
        stability_score = 25.0 * (self.success / self.total if self.total else 0)
        jitter_score = 15.0 * max(0.0, 1.0 - min(self.jitter or 0, 100) / 100)
        total = latency_score + stability_score + jitter_score
        if self.hijack:
            total -= 15
        return max(0.0, min(100.0, total))

    @property
    def v6_median(self) -> float | None:
        return statistics.median(self.samples_v6) if self.samples_v6 else None

    @property
    def v6_support(self) -> float:
        """AAAA 应答率(0-100)。IPv6 查询失败常见, 不计入总应答率。"""
        return self.success_v6 / self.total_v6 * 100 if self.total_v6 else 0.0

    def to_dict(self) -> dict:
        return {
            "ip": self.ip, "name": self.name, "group": self.group,
            "dns_median_ms": round(self.median, 2) if self.median is not None else None,
            "dns_p95_ms": round(self.p95, 2) if self.p95 is not None else None,
            "dns_avg_ms": round(self.average, 2) if self.average is not None else None,
            "dns_min_ms": round(min(self.samples), 2) if self.samples else None,
            "jitter_ms": round(self.jitter, 2) if self.jitter is not None else None,
            "loss_percent": round(self.loss, 1),
            "aaaa_median_ms": round(self.v6_median, 2) if self.v6_median is not None else None,
            "aaaa_support_percent": round(self.v6_support, 1),
            "icmp_avg_ms": self.icmp,
            "icmp_loss_percent": self.icmp_loss,
            "hijack": self.hijack,
            "hijack_note": self.hijack_note,
            "router_cache": self.router_cache,
            "score": round(self.score, 1),
        }


def probe_server(res: ProbeResult, rounds: int, timeout: float,
                 domains: list[str], do_ping: bool, do_hijack: bool,
                 do_v6: bool = True) -> ProbeResult:
    """
    测试单个服务器。
    - 先做一轮"预热查询"让服务器缓存生效, 结果不计入统计(更贴近日常使用体感)
    - 连续 3 次超时即判定不可达并提前退出, 避免无响应服务器拖慢整体进度
    - 每个域名 A 与 AAAA 各查一次: 解析器对两类记录行为可能不同(IPv6 场景)
    """
    res.status = "running"
    try:
        for domain in domains:
            dns_query(res.ip, domain, timeout)

        consecutive_fail = 0
        for domain in domains:
            for _ in range(rounds):
                rtt = dns_query(res.ip, domain, timeout)
                res.total += 1
                if rtt is None:
                    consecutive_fail += 1
                    if consecutive_fail >= 3:
                        res.status = "done"
                        return res
                else:
                    consecutive_fail = 0
                    res.success += 1
                    res.samples.append(rtt)
                if do_v6:
                    rtt6 = dns_query(res.ip, domain, timeout, qtype=28)
                    res.total_v6 += 1
                    if rtt6 is not None:
                        res.success_v6 += 1
                        res.samples_v6.append(rtt6)
                time.sleep(0.01)  # 轻微节流, 避免突发丢包

        # GRC 经典陷阱: <2ms 的"神速"多半是本机路由器在应答, 不是真实网络
        if res.median is not None and is_router_cache(res.median):
            res.router_cache = True

        if res.samples and do_hijack:
            res.hijack, res.hijack_note = detect_hijack(res.ip, timeout)
        if do_ping:
            p = ping_host(res.ip)
            if p:
                res.icmp, res.icmp_loss = p["avg"], p["loss"]
    except Exception as exc:  # 兜底, 不让单个服务器异常中断整体
        res.error = str(exc)
    res.status = "done"
    return res


# ──────────────────────────────────────────────────────────────── 实时面板

SPINNER = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


class LivePanel:
    """TTY 下的实时刷新面板: 每个服务器一行, 显示进度与当前延迟。"""

    def __init__(self, results: list[ProbeResult], t: Term):
        self.results = results
        self.t = t
        self.frames = 0
        self.lines_printed = 0
        self.lock = threading.Lock()
        # 窗口高度不足时降级为单行进度, 避免面板滚屏
        try:
            rows = shutil.get_terminal_size((100, 24)).lines
        except Exception:
            rows = 24
        self.compact = rows < len(results) + 6

    def _row(self, res: ProbeResult) -> str:
        t = self.t
        name_w, ip_w = 16, 17
        ip_part = t.paint(pad(res.ip, ip_w), t.fg(int(C_MUTE)))
        name_part = t.paint(pad(clip(res.name, name_w), name_w), t.fg(int(C_NAME)))

        if res.status == "pending":
            state = t.paint("· 等待 ", t.fg(int(C_MUTE)))
            metric = ""
        elif res.status == "running":
            spin = SPINNER[self.frames % len(SPINNER)]
            state = t.paint(f"{spin} 测试中", t.fg(int(C_ACCENT)))
            metric = t.paint(f"{len(res.samples)}/{res.total} 次", t.fg(int(C_MUTE))) if res.total else ""
        else:
            med = res.median
            if med is None:
                state = t.paint("✕ 无响应", t.fg(int(C_BAD)))
                metric = t.paint("超时 / 不可达", t.fg(int(C_MUTE)))
            else:
                state = t.paint("✓ " + pad(f"{med:6.1f} ms", 11), t.fg(int(color_of(med))), t.BOLD)
                extra = f"丢失 {res.loss:.0f}%"
                if res.icmp is not None:
                    extra += f" · ping {res.icmp:.1f} ms"
                if res.hijack:
                    extra += " · " + t.paint("疑似劫持", t.fg(int(C_BAD)))
                metric = t.paint(extra, t.fg(int(C_MUTE)))
        return "  " + name_part + ip_part + state + "  " + metric

    def render(self, done: int, total: int) -> None:
        with self.lock:
            self.frames += 1
            t = self.t
            pct = done / total if total else 0
            bar_w = max(10, min(40, t.width - 34))
            filled = int(bar_w * pct)
            bar = t.paint("█" * filled, t.fg(int(C_ACCENT))) + t.paint("░" * (bar_w - filled), t.fg(240))

            if self.compact:
                # 单行进度: 窗口太矮, 不铺开面板
                done_cnt = sum(1 for r in self.results if r.status == "done")
                spin = SPINNER[self.frames % len(SPINNER)]
                sys.stdout.write("\r\033[2K  " + t.paint(spin, t.fg(int(C_ACCENT)))
                                 + " " + t.paint(f"测试进度 {done_cnt}/{total}", t.BOLD) + "  " + bar)
                sys.stdout.flush()
                return

            if self.lines_printed:
                sys.stdout.write(f"\033[{self.lines_printed}A\033[J")
            print("  " + t.paint(f"测试进度  {done}/{total}", t.BOLD) + "  " + bar)
            print()
            for res in self.results:
                print(self._row(res))
            self.lines_printed = len(self.results) + 3
            sys.stdout.flush()

    def finish(self) -> None:
        if self.compact:
            sys.stdout.write("\r\033[2K")
        sys.stdout.flush()


# ──────────────────────────────────────────────────────────────── 结果渲染


def bar_chart(value: float, vmax: float, width: int, t: Term) -> str:
    """用小方块绘制相对长度的条形图。"""
    ratio = 0.0 if vmax <= 0 else min(1.0, value / vmax)
    filled = int(round(ratio * width))
    color = str(color_of(value))
    return t.paint("▰" * filled, t.fg(int(color))) + t.paint("▱" * (width - filled), t.fg(240))


def render_table(results: list[ProbeResult], t: Term, top: int | None = None) -> None:
    shown = [r for r in results if r.median is not None] + [r for r in results if r.median is None]
    if top:
        shown = shown[:top]

    col_rank, col_name, col_ip = 6, 16, 17
    col_med, col_p95, col_loss, col_ping, col_score = 12, 11, 9, 12, 7
    col_v6 = 11
    bar_w = 12
    max_med = max((r.median or 0) for r in shown) or 1.0

    def header() -> str:
        cells = [
            pad("名次", col_rank, "center"),
            pad("服务器", col_name),
            pad("IP", col_ip),
            pad("查询延迟", col_med, "right"),
            pad("", bar_w),
            pad("P95", col_p95, "right"),
            pad("v6", col_v6, "right"),
            pad("丢失", col_loss, "right"),
            pad("Ping", col_ping, "right"),
            pad("得分", col_score, "right"),
        ]
        return "  " + t.paint("".join(cells), t.BOLD)

    rule(t)
    print(header())
    rule(t)

    for idx, r in enumerate(shown, 1):
        med = r.median
        if med is None:
            line = (
                "  " + t.paint(pad(str(idx), col_rank, "center"), t.fg(int(C_MUTE)))
                + t.paint(pad(clip(r.name, col_name), col_name), t.fg(int(C_MUTE)))
                + t.paint(pad(r.ip, col_ip), t.fg(int(C_MUTE)))
                + t.paint(pad("无响应", col_med, "right"), t.fg(int(C_BAD)))
                + " " * (bar_w + 2)
                + t.paint(pad("—", col_p95, "right"), t.fg(int(C_MUTE)))
                + t.paint(pad("—", col_v6, "right"), t.fg(int(C_MUTE)))
                + t.paint(pad("100%", col_loss, "right"), t.fg(int(C_BAD)))
                + t.paint(pad("—", col_ping, "right"), t.fg(int(C_MUTE)))
                + t.paint(pad("0", col_score, "right"), t.fg(int(C_MUTE)))
            )
            print(line)
            continue

        rank_style = t.BOLD if idx <= 3 else ""
        med_txt = f"{med:.1f} ms"
        # v6 列: AAAA 中位数(支持率不足时标灰), 无样本显示 —
        if r.v6_median is not None:
            v6_txt = f"{r.v6_median:.0f}ms/{r.v6_support:.0f}%"
            v6_col = C_OK if r.v6_support >= 95 else C_WARN if r.v6_support >= 50 else C_BAD
        else:
            v6_txt, v6_col = "—", C_MUTE
        line = (
            "  " + t.paint(pad(str(idx), col_rank, "center"), t.fg(int(C_ACCENT)), rank_style)
            + t.paint(pad(clip(r.name, col_name), col_name), t.fg(int(C_NAME)), rank_style)
            + t.paint(pad(r.ip, col_ip), t.fg(int(C_MUTE)))
            + t.paint(pad(med_txt, col_med, "right"), t.fg(int(color_of(med))), t.BOLD)
            + "  " + bar_chart(med, max_med, bar_w, t)
            + t.paint(pad(f"{r.p95:.1f} ms", col_p95, "right"), t.fg(int(C_MUTE)))
            + t.paint(pad(v6_txt, col_v6, "right"), t.fg(int(v6_col)))
            + t.paint(pad(f"{r.loss:.0f}%", col_loss, "right"),
                      t.fg(int(C_OK if r.loss == 0 else C_WARN if r.loss < 30 else C_BAD)))
            + t.paint(pad(fmt_ms(r.icmp) + (" ms" if r.icmp is not None else ""), col_ping, "right"),
                      t.fg(int(color_of(r.icmp) if r.icmp is not None else int(C_MUTE))))
            + t.paint(pad(f"{r.score:.0f}", col_score, "right"),
                      t.fg(int(C_OK if r.score >= 70 else C_WARN if r.score >= 45 else C_BAD)), t.BOLD)
        )
        if r.hijack:
            line += "  " + t.paint("⚠ 劫持", t.fg(int(C_BAD)))
        if r.router_cache:
            line += "  " + t.paint("⚠ 路由器缓存", t.fg(int(C_WARN)))
        print(line)

    rule(t)


def card_box(lines: list[tuple[str, str, str]], t: Term, width: int | None = None) -> None:
    """绘制推荐卡片: lines 为 (标签, 内容, 颜色) 三元组; 宽度按内容自适应。"""
    if width is None:
        longest = max((dw(f" {label}  {content}") for label, content, _ in lines),
                      default=44)
        width = min(max(longest + 6, 48), max(t.width - 4, 48))
    inner = width
    print("  " + t.paint("┌" + "─" * (inner - 2) + "┐", t.fg(240)))
    for label, content, color in lines:
        left = t.paint(f" {label} ", t.fg(int(color)), t.BOLD)
        body = clip(f"{left} {content}", inner - 4)
        print("  " + t.paint("│", t.fg(240)) + " " + pad(body, inner - 4) + " "
              + t.paint("│", t.fg(240)))
    print("  " + t.paint("└" + "─" * (inner - 2) + "┘", t.fg(240)))


def reliable_pool(results: list[ProbeResult], min_reliability: float) -> list[ProbeResult]:
    """应答率达标且未劫持的候选; 全军覆没时退化为'未劫持'再退化为全量。"""
    alive = [r for r in results if r.median is not None]
    reliable = [r for r in alive if 100 - r.loss >= min_reliability]
    pool = reliable or alive
    clean = [r for r in pool if not r.hijack] or pool
    return clean


def build_recommendations(results: list[ProbeResult],
                          min_reliability: float = RELIABILITY_DEFAULT
                          ) -> list[tuple[str, str, str]]:
    """生成去重后的推荐卡片: (标签, 内容, 颜色)。"""
    clean = reliable_pool(results, min_reliability)
    cards: list[tuple[str, str, str]] = []
    picked: set[str] = set()

    def add(tag: str, res: ProbeResult | None, content: str, color: str) -> None:
        if res is None or res.ip in picked:
            return
        picked.add(res.ip)
        cards.append((tag, content, color))

    def best(pool: list[ProbeResult], key) -> ProbeResult | None:
        return min(pool, key=key) if pool else None

    def first_word(res: ProbeResult) -> str:
        return res.name.split()[0]

    overall = best(clean, lambda r: (-r.score, r.median or 999))
    if overall is not None:
        add("最佳", overall, f"{overall.name}  {overall.ip}   延迟 {overall.median:.1f} ms"
                             f"  得分 {overall.score:.0f}", C_OK)

    # ② 备用: 与首选不同厂商(按名称首词区分)里的最优, 用于容灾; 优先于其他标签挑选
    backup = best([r for r in clean if overall is not None
                   and first_word(r) != first_word(overall)],
                  lambda r: (-r.score, r.median or 999))
    if backup is not None:
        add("备用", backup, f"{backup.name}  {backup.ip}   延迟 {backup.median:.1f} ms"
                            f"  得分 {backup.score:.0f}", C_ACCENT)

    # ③ 最快: 取全量最优; 若已被前面的标签占用则跳过, 避免把"最快"错贴给次优服务器
    fastest = best(clean, lambda r: r.median or 999)
    if fastest is not None:
        add("最快", fastest, f"{fastest.name}  {fastest.ip}   延迟 {fastest.median:.1f} ms"
                             f"  最低 {min(fastest.samples):.1f} ms", C_OK)

    # ④ 最稳: 全量里丢包最低、P95 长尾最小的; 同样只在未被占用时列出
    steady = best(clean, lambda r: (r.loss, r.p95 or 999))
    if steady is not None:
        add("最稳", steady, f"{steady.name}  {steady.ip}   丢失 {steady.loss:.0f}%"
                            f"  P95 {steady.p95:.1f} ms", C_ACCENT)

    if overall is not None and overall.group != "国内":
        d = best([r for r in clean if r.group == "国内"], lambda r: r.median or 999)
        if d is not None:
            add("国内", d, f"{d.name}  {d.ip}   延迟 {d.median:.1f} ms", C_NAME)

    a = best([r for r in clean if r.group == "国际"], lambda r: r.median or 999)
    if a is not None:
        add("出海", a, f"{a.name}  {a.ip}   延迟 {a.median:.1f} ms"
                       f"  (适合境外站点 / 代理环境)", C_NAME)

    hijacked = [r for r in clean if r.hijack]
    if hijacked:
        names = "、".join(f"{r.name}({r.ip})" for r in hijacked[:3])
        cards.append(("规避", f"{names} 存在 NXDOMAIN 劫持, 不建议日常使用", C_BAD))
    return cards


def render_summary(results: list[ProbeResult], t: Term, elapsed: float) -> None:
    alive = [r for r in results if r.median is not None]
    print()
    print("  " + t.paint(f"共测试 {len(results)} 个服务器, 有响应 {len(alive)} 个, "
                         f"耗时 {elapsed:.1f}s", t.fg(int(C_MUTE))))
    if alive:
        med_all = statistics.median([r.median for r in alive])
        best = min(alive, key=lambda r: r.median)
        print("  " + t.paint(f"全网中位延迟 {med_all:.1f} ms · "
                             f"最快 {best.name} {best.median:.1f} ms", t.fg(int(C_MUTE))))


def render_apply_guide(results: list[ProbeResult], t: Term,
                       min_reliability: float = RELIABILITY_DEFAULT) -> None:
    clean = reliable_pool(results, min_reliability)
    if not clean:
        return
    ranked = sorted(clean, key=lambda r: (-r.score, r.median))
    primary = ranked[0]
    secondary = None
    for cand in ranked[1:]:
        if cand.name.split()[0] != primary.name.split()[0]:
            secondary = cand
            break

    print()
    print("  " + t.paint("建议配置", t.fg(int(C_ACCENT)), t.BOLD))
    print("  " + t.paint(f"  首选  {primary.name} {primary.ip}", t.fg(int(C_NAME))))
    if secondary:
        print("  " + t.paint(f"  备用  {secondary.name} {secondary.ip}", t.fg(int(C_NAME))))
    ips = [primary.ip] + ([secondary.ip] if secondary else [])
    print()
    print("  " + t.paint("修改方式", t.fg(int(C_MUTE))))
    system = platform.system().lower()
    if system == "darwin":
        print("    系统设置 → 网络 → Wi-Fi → 详细信息 → DNS → 添加上面"
              + ("两个 IP" if secondary else "的 IP"))
        print("    命令行: " + t.paint("networksetup -setdnsservers Wi-Fi " + " ".join(ips), t.fg(int(C_OK))))
        print("    验证:   " + t.paint("networksetup -getdnsservers Wi-Fi", t.fg(int(C_MUTE))))
        print("    还原:   " + t.paint("networksetup -setdnsservers Wi-Fi empty", t.fg(int(C_MUTE))))
    elif system == "linux":
        print("    /etc/resolv.conf 增加: "
              + t.paint("nameserver " + primary.ip, t.fg(int(C_OK))))
        print("    (使用 NetworkManager 时建议用 nmcli 修改, 以免重启后被覆盖)")
    else:
        print("    控制面板 → 网络和共享中心 → 适配器 → IPv4 属性 → 填入首选 / 备用 DNS")
    print()


# ──────────────────────────────────────────────────────────────── 主流程


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="dns_bench.py",
        description="DNS 延迟基准测试与推荐工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n"
               "  python3 dns_bench.py                    测试全部内置服务器\n"
               "  python3 dns_bench.py --domestic -r 8     国内服务器, 每个域名查 8 次\n"
               "  python3 dns_bench.py -s 223.5.5.5 -s 119.29.29.29 -s 1.1.1.1\n"
               "  python3 dns_bench.py --json result.json  导出结构化结果\n",
    )
    p.add_argument("-s", "--server", action="append", metavar="IP",
                   help="指定要测试的 DNS 服务器 IP, 可重复; 指定后忽略内置列表")
    p.add_argument("--servers-file", metavar="PATH",
                   help="从文件加载服务器清单, 每行: IP [名称] [分组], # 注释")
    p.add_argument("--preset", choices=sorted(PRESETS), metavar="NAME",
                   help="场景预设: " + " / ".join(f"{k}({v['desc']})" for k, v in PRESETS.items()))
    p.add_argument("--domestic", action="store_true", help="只测试国内服务器")
    p.add_argument("--abroad", action="store_true", help="只测试国际服务器")
    p.add_argument("--no-v6", action="store_true",
                   help="跳过 AAAA(IPv6) 查询; 默认 A/AAAA 分开统计")
    p.add_argument("--min-reliability", type=float, default=RELIABILITY_DEFAULT, metavar="PCT",
                   help=f"推荐门槛: 应答率低于此百分比不进推荐(默认 {RELIABILITY_DEFAULT:.0f}, GRC 口径)")
    p.add_argument("-r", "--rounds", type=int, default=4,
                   help="每个域名的查询次数(默认 4), 次数越多越稳但更慢")
    p.add_argument("-d", "--domain", action="append", metavar="DOMAIN",
                   help="延迟测试用域名, 可重复; 默认 %s" % ", ".join(PROBE_DOMAINS))
    p.add_argument("-t", "--timeout", type=float, default=1.5, help="单次查询超时秒数(默认 1.5)")
    p.add_argument("-c", "--concurrency", type=int, default=8, help="并发测试数(默认 8)")
    p.add_argument("--no-ping", action="store_true", help="跳过 ICMP ping 测试")
    p.add_argument("--no-hijack", action="store_true", help="跳过劫持检测")
    p.add_argument("--top", type=int, metavar="N", help="排行榜只显示前 N 名")
    p.add_argument("--json", metavar="PATH", help="将结果导出为 JSON 文件")
    p.add_argument("--color", choices=["auto", "always", "never"], default="auto",
                   help="彩色输出策略(默认 auto)")
    p.add_argument("-q", "--quiet", action="store_true", help="静默模式, 不显示实时面板")
    return p.parse_args(argv)


def select_servers(args: argparse.Namespace) -> list[tuple[str, str, str]]:
    if args.server:
        known = {ip: (name, group) for ip, name, group in SERVERS}
        return [(ip, known.get(ip, ("自定义", "自定义"))[0],
                 known.get(ip, ("自定义", "自定义"))[1]) for ip in args.server]
    if getattr(args, "servers_file", None):
        return load_servers_file(args.servers_file)
    if getattr(args, "preset", None):
        ips = PRESETS[args.preset]["ips"]
        known = {ip: (name, group) for ip, name, group in SERVERS}
        # 预设 IP 不在内置清单时也要能测(名称回退为自定义)
        out = []
        for ip in ips:
            name, group = known.get(ip, (f"预设 {ip}", args.preset))
            out.append((ip, name, group))
        return out
    if args.domestic:
        return [s for s in SERVERS if s[2] == "国内"]
    if args.abroad:
        return [s for s in SERVERS if s[2] == "国际"]
    return list(SERVERS)


def _historical_main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    t = Term(args.color)
    servers = select_servers(args)
    domains = args.domain or PROBE_DOMAINS

    draw_banner(t)

    cur = current_system_dns()
    if cur:
        print("  " + t.paint("本机当前 DNS: ", t.fg(int(C_MUTE)))
              + t.paint("  ".join(cur), t.fg(int(C_NAME))))
        if has_fake_ip(cur):
            print("  " + t.paint("› 警告: " + FAKE_IP_WARNING, t.fg(int(C_WARN))))
    print("  " + t.paint(f"测试范围: {len(servers)} 个服务器 · {len(domains)} 个域名 · "
                         f"每个 {args.rounds} 次查询"
                         + ("" if args.no_ping else " · 含 ICMP"), t.fg(int(C_MUTE))))
    print()

    results = [ProbeResult(ip, name, group) for ip, name, group in servers]
    by_ip = {r.ip: r for r in results}

    use_panel = t.color and not args.quiet and sys.stdout.isatty()
    panel = LivePanel(results, t) if use_panel else None
    if panel:
        panel.render(0, len(results))
    else:
        print("  正在测试, 请稍候…")

    start = time.time()
    completed = 0
    try:
        with futures.ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as pool:
            future_map = {
                pool.submit(probe_server, r, args.rounds, args.timeout,
                            domains, not args.no_ping, not args.no_hijack,
                            not args.no_v6): r.ip
                for r in results
            }
            for fut in futures.as_completed(future_map):
                ip = future_map[fut]
                try:
                    fut.result()
                except Exception as exc:
                    by_ip[ip].error = str(exc)
                    by_ip[ip].status = "done"
                completed += 1
                if panel:
                    panel.render(completed, len(results))
    except KeyboardInterrupt:
        print("\n  " + t.paint("已中断", t.fg(int(C_BAD))))
        return 130

    elapsed = time.time() - start
    if panel:
        panel.render(len(results), len(results))
        panel.finish()

    # 排序: 有响应的按得分降序(同分按延迟升序), 无响应的排在最后
    results.sort(key=lambda r: (r.median is None, -r.score, r.median or 999))

    print()
    render_table(results, t, args.top)
    render_summary(results, t, elapsed)

    cards = build_recommendations(results, args.min_reliability)
    if cards:
        print()
        print("  " + t.paint("推荐列表", t.fg(int(C_ACCENT)), t.BOLD))
        card_box(cards, t)

    render_apply_guide(results, t, args.min_reliability)

    if args.json:
        payload = {
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "probe_domains": domains,
            "rounds_per_domain": args.rounds,
            "system_dns": cur,
            "results": [r.to_dict() for r in results],
        }
        try:
            with open(args.json, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False, indent=2)
            print("  " + t.paint(f"结果已导出: {args.json}", t.fg(int(C_OK))))
        except OSError as exc:
            print("  " + t.paint(f"导出失败: {exc}", t.fg(int(C_BAD))))

    return 0


def main(argv=None) -> int:
    """Route the historic script name through the explicit DNSProbe v1 adapter."""
    from pathlib import Path
    import sys
    source = str(Path(__file__).resolve().parent / "src")
    if source not in sys.path:
        sys.path.insert(0, source)
    from dnsprobe.legacy import main as compatibility_main
    return compatibility_main(argv, mode='bench')


if __name__ == "__main__":
    sys.exit(main())
