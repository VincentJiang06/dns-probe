#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DNS Bench · 香港版 (dns_bench_hk.py)

专为香港网络环境设计的 DNS 基准测试。与通用版的区别:

1. 服务器清单按香港实际可选: 香港有 anycast 节点的国际 DNS + 大陆 DNS(影响淘宝/微信等
   大陆服务的 CDN 调度) + 亚太邻近(台湾/韩国) 作参照
2. 自动把本机 DHCP 分配的运营商 DNS(PCCW / HKBN / CSL / 3HK / 中国移动香港 等)
   加入测试, 无需手工查地址
3. 分三组域名分别测延迟: 香港本地 / 国际 / 大陆, 并按 45% : 40% : 15% 加权算综合分
   —— 在香港, "访问大陆服务快"和"访问国际服务快"往往需要不同的 DNS
4. CDN 调度对比: 展示不同 DNS 解析淘宝/腾讯时返回的节点 IP, 揭示地域调度差异

用法:
  python3 dns_bench_hk.py                  # 全部服务器(推荐)
  python3 dns_bench_hk.py --quick          # 快速模式, 跳过 ping、采样减半
  python3 dns_bench_hk.py --intl           # 只看国际 DNS
  python3 dns_bench_hk.py --cn             # 只看大陆 DNS(调大陆服务的候选)
  python3 dns_bench_hk.py -s 1.1.1.1 -s 223.5.5.5
  python3 dns_bench_hk.py -r 6 --json hk.json
  python3 dns_bench_hk.py --color never    # 纯文本, 便于重定向到文件

依赖: Python 3.10+ 标准库 + 同目录 dns_core.py。macOS / Linux / Windows 通用。
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
from dns_core import system_dns


def resolve(server: str, domain: str, timeout: float, qtype: int = 1) -> tuple[float | None, list[str]]:
    """适配层: 返回 (RTT, A 记录); rcode 0(NOERROR)/3(NXDOMAIN) 都算正常应答。"""
    rtt, p = query(server, domain, qtype=qtype, timeout=timeout)
    if rtt is None or not p or p["rcode"] not in (0, 3):
        return None, []
    return rtt, p["ips"]

# ──────────────────────────────────────────────────────────────── 服务器清单

# (IP, 名称, 分组)  分组用于场景推荐与加权
SERVERS_HK: list[tuple[str, str, str]] = [
    # 国际公共 DNS —— 在香港大多有 anycast 节点, 通常是个位数毫秒
    ("1.1.1.1",         "Cloudflare",        "国际"),
    ("1.0.0.1",         "Cloudflare 备",     "国际"),
    ("8.8.8.8",         "Google DNS",        "国际"),
    ("8.8.4.4",         "Google DNS 备",     "国际"),
    ("9.9.9.9",         "Quad9",             "国际"),
    ("149.112.112.112", "Quad9 备",          "国际"),
    ("208.67.222.222",  "OpenDNS",           "国际"),
    ("208.67.220.220",  "OpenDNS 备",        "国际"),
    ("94.140.14.14",    "AdGuard DNS",       "国际"),
    ("94.140.15.15",    "AdGuard DNS 备",    "国际"),
    ("64.6.64.6",       "Verisign DNS",      "国际"),
    ("64.6.65.6",       "Verisign 备",       "国际"),
    ("156.154.70.1",    "Neustar Ultra",     "国际"),
    ("8.26.56.26",      "Comodo Secure",     "国际"),
    # 大陆公共 DNS —— 在香港访问走跨境, 但解析大陆站点常返回更近的大陆节点
    ("223.5.5.5",       "阿里 AliDNS",       "大陆"),
    ("223.6.6.6",       "阿里 AliDNS 备",    "大陆"),
    ("119.29.29.29",    "腾讯 DNSPod",       "大陆"),
    ("182.254.116.116", "腾讯 DNSPod 备",    "大陆"),
    ("114.114.114.114", "114DNS",            "大陆"),
    ("180.76.76.76",    "百度 DNS",          "大陆"),
    # 亚太邻近 —— 参照组, 台湾/韩国节点在香港的落地延迟
    ("168.95.1.1",      "HiNet 中华电信",    "亚太"),
    ("168.95.192.1",    "HiNet 备",          "亚太"),
    ("101.101.101.101", "Quad101 台湾",      "亚太"),
    ("168.126.63.1",    "KT 韩国电信",       "亚太"),
]

# 分场景域名: 香港本地 / 国际 / 大陆
DOMAIN_GROUPS: dict[str, list[str]] = {
    "香港": ["www.hk01.com", "www.mtr.com.hk", "www.hsbc.com.hk", "www.hku.hk"],
    "国际": ["www.google.com", "www.cloudflare.com", "www.youtube.com", "www.wikipedia.org"],
    "大陆": ["www.qq.com", "www.taobao.com", "www.baidu.com", "www.bilibili.com"],
}
GROUP_ORDER = ["香港", "国际", "大陆"]
# 综合得分权重: 在香港本地与国际为主, 大陆服务为辅
GROUP_WEIGHT = {"香港": 0.45, "国际": 0.40, "大陆": 0.15}
# CDN 调度探针: 记录这些域名被解析到了哪些 IP
CDN_PROBE = ["www.taobao.com", "www.qq.com"]

DNS_PORT = 53


# ──────────────────────────────────────────────────────────────── 横幅

LOGO = [
    "██╗  ██╗██╗  ██╗    ██████╗ ███╗   ██╗███████╗",
    "██║  ██║██║ ██╔╝    ██╔══██╗████╗  ██║██╔════╝",
    "███████║█████╔╝     ██║  ██║██╔██╗ ██║███████╗",
    "██║  ██║██╔═██╗     ██║  ██║██║╚██╗██║╚════██║",
    "██║  ██║██║  ██╗    ██████╔╝██║ ╚████║███████║",
    "╚═╝  ╚═╝╚═╝  ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚══════╝",
]
STOPS = [(86, 205, 245), (96, 165, 250), (167, 139, 250), (244, 114, 182)]


def banner(t: Term) -> None:
    print()
    for line in LOGO:
        print("  " + (gradient(line, t, STOPS) if t.color else line))
    print("  " + t.paint("香港版 · 本地 / 国际 / 大陆 三场景延迟 · CDN 调度对比 · 智能推荐",
                         t.fg(int(C_MUTE))))
    print()


# ──────────────────────────────────────────────────────────────── 测试模型


class Result:
    def __init__(self, ip: str, name: str, group: str):
        self.ip, self.name, self.group = ip, name, group
        self.samples: list[float] = []
        self.samples_v6: list[float] = []     # AAAA(IPv6), 与 A 分开统计
        self.total_v6 = self.success_v6 = 0
        self.by_group: dict[str, list[float]] = {g: [] for g in GROUP_ORDER}
        self.cdn: dict[str, tuple[str, ...]] = {}
        self.success = self.total = 0
        self.icmp: float | None = None
        self.icmp_loss: float | None = None
        self.hijack = False
        self.hijack_note: str | None = None
        self.router_cache = False
        self.status = "pending"

    @property
    def v6_median(self) -> float | None:
        return statistics.median(self.samples_v6) if self.samples_v6 else None

    @property
    def v6_support(self) -> float:
        return self.success_v6 / self.total_v6 * 100 if self.total_v6 else 0.0

    @property
    def median(self) -> float | None:
        return statistics.median(self.samples) if self.samples else None

    def gmedian(self, g: str) -> float | None:
        return statistics.median(self.by_group[g]) if self.by_group[g] else None

    @property
    def p95(self) -> float | None:
        if not self.samples:
            return None
        ordered = sorted(self.samples)
        return ordered[min(len(ordered) - 1, int(round(0.95 * (len(ordered) - 1))))]

    @property
    def loss(self) -> float:
        # total=0(异常路径/未真正采样)不算 100% 丢失, 与 dns_core.Stream 语义一致
        return 0.0 if not self.total else (self.total - self.success) / self.total * 100

    @property
    def score(self) -> float:
        """综合得分: 三组延迟按权重加权(各 0-60 分) + 稳定性 25 + 抖动 15。"""
        if self.median is None:
            return 0.0
        lat = 0.0
        weights = 0.0
        for g in GROUP_ORDER:
            med = self.gmedian(g)
            if med is None:
                continue
            w = GROUP_WEIGHT[g]
            lat += 60.0 * max(0.0, 1.0 - min(med, 200) / 200) ** 1.8 * w
            weights += w
        if weights > 0:
            lat = lat / weights * sum(GROUP_WEIGHT.values())
        jitter = statistics.pstdev(self.samples) if len(self.samples) > 1 else 0.0
        jit = 15.0 * max(0.0, 1.0 - min(jitter, 100) / 100)
        total = lat + 25.0 * (self.success / self.total if self.total else 0) + jit
        return max(0.0, min(100.0, total - (15 if self.hijack else 0)))

    def to_dict(self) -> dict:
        hk_m, intl_m, cn_m = (self.gmedian(g) for g in GROUP_ORDER)
        return {
            "ip": self.ip, "name": self.name, "group": self.group,
            "median_ms": round(self.median, 2) if self.median is not None else None,
            "p95_ms": round(self.p95, 2) if self.p95 is not None else None,
            "hk_ms": round(hk_m, 2) if hk_m is not None else None,
            "intl_ms": round(intl_m, 2) if intl_m is not None else None,
            "cn_ms": round(cn_m, 2) if cn_m is not None else None,
            "aaaa_median_ms": round(self.v6_median, 2) if self.v6_median is not None else None,
            "aaaa_support_percent": round(self.v6_support, 1),
            "loss_percent": round(self.loss, 1),
            "icmp_ms": self.icmp,
            "hijack": self.hijack,
            "hijack_note": self.hijack_note,
            "router_cache": self.router_cache,
            "score": round(self.score, 1),
            "cdn": {k: list(v) for k, v in self.cdn.items()},
        }


def probe(res: Result, rounds: int, timeout: float, do_ping: bool, do_hijack: bool,
          do_v6: bool = True) -> Result:
    res.status = "running"
    try:
        for domains in DOMAIN_GROUPS.values():      # 预热, 填充服务器缓存
            for d in domains:
                resolve(res.ip, d, timeout)

        fails = 0
        for g, domains in DOMAIN_GROUPS.items():
            for d in domains:
                for _ in range(rounds):
                    rtt, ips = resolve(res.ip, d, timeout)
                    res.total += 1
                    if rtt is None:
                        fails += 1
                        if fails >= 3:              # 连续超时, 判定不可达
                            res.status = "done"
                            return res
                    else:
                        fails = 0
                        res.success += 1
                        res.samples.append(rtt)
                        res.by_group[g].append(rtt)
                        if d in CDN_PROBE and ips:
                            res.cdn[d] = tuple(sorted(ips[:3]))   # 排序, 避免顺序不同被当成两组
                    if do_v6:                       # AAAA 与 A 分开统计(IPv6 场景)
                        rtt6, _ips6 = resolve(res.ip, d, timeout, qtype=28)
                        res.total_v6 += 1
                        if rtt6 is not None:
                            res.success_v6 += 1
                            res.samples_v6.append(rtt6)
                    time.sleep(0.01)

        # GRC 陷阱: <2ms 的"ISP DNS"多半是本机路由器缓存应答
        if res.median is not None and is_router_cache(res.median):
            res.router_cache = True
        if res.samples and do_hijack:
            res.hijack, res.hijack_note = detect_hijack(res.ip, timeout)
        if do_ping:
            p = ping_host(res.ip)
            if p:
                res.icmp, res.icmp_loss = p["avg"], p["loss"]
    except Exception as exc:
        res.error = str(exc)
    res.status = "done"
    return res


# ──────────────────────────────────────────────────────────────── 实时面板

SPINNER = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


class Panel:
    def __init__(self, results: list[Result], t: Term):
        self.results, self.t = results, t
        self.frames = self.printed = 0
        self.lock = threading.Lock()
        try:
            rows = shutil.get_terminal_size((100, 24)).lines
        except Exception:
            rows = 24
        self.compact = rows < len(results) + 6

    def _row(self, r: Result) -> str:
        t = self.t
        head = (t.paint(pad(clip(r.name, 18), 18), t.fg(int(C_NAME)))
                + t.paint(pad(r.ip, 17), t.fg(int(C_MUTE))))
        if r.status == "pending":
            return "  " + head + t.paint("· 等待", t.fg(int(C_MUTE)))
        if r.status == "running":
            return ("  " + head + t.paint(SPINNER[self.frames % 10] + " 测试中", t.fg(int(C_ACCENT)))
                    + t.paint(f"  {len(r.samples)}/{r.total}", t.fg(int(C_MUTE))) if r.total
                    else "  " + head + t.paint(SPINNER[self.frames % 10] + " 测试中", t.fg(int(C_ACCENT))))
        med = r.median
        if med is None:
            return "  " + head + t.paint("✕ 无响应", t.fg(int(C_BAD)))
        state = t.paint(f"✓ {med:6.1f} ms", t.fg(int(color_of(med))), t.BOLD)
        extra = f" 香港 {r.gmedian('香港') or 0:.0f} · 国际 {r.gmedian('国际') or 0:.0f} · 大陆 {r.gmedian('大陆') or 0:.0f}"
        return "  " + head + state + t.paint(extra, t.fg(int(C_MUTE)))

    def render(self, done: int, total: int) -> None:
        with self.lock:
            self.frames += 1
            t = self.t
            bw = max(10, min(36, t.width - 32))
            filled = int(bw * (done / total if total else 0))
            bar = t.paint("█" * filled, t.fg(int(C_ACCENT))) + t.paint("░" * (bw - filled), t.fg(240))
            if self.compact:
                sys.stdout.write("\r\033[2K  " + t.paint(SPINNER[self.frames % 10], t.fg(int(C_ACCENT)))
                                 + " " + t.paint(f"测试进度 {done}/{total}", t.BOLD) + "  " + bar)
                sys.stdout.flush()
                return
            if self.printed:
                sys.stdout.write(f"\033[{self.printed}A\033[J")
            print("  " + t.paint(f"测试进度  {done}/{total}", t.BOLD) + "  " + bar)
            print()
            for r in self.results:
                print(self._row(r))
            self.printed = len(self.results) + 3
            sys.stdout.flush()

    def finish(self) -> None:
        if self.compact:
            sys.stdout.write("\r\033[2K")
        sys.stdout.flush()


# ──────────────────────────────────────────────────────────────── 渲染


def render_table(results: list[Result], t: Term, top: int | None = None) -> None:
    shown = results[:top] if top else results
    cols = [(6, "center"), (17, "left"), (17, "left"), (9, "right"), (9, "right"),
            (9, "right"), (9, "right"), (8, "right"), (7, "right"), (9, "right"), (6, "right")]
    heads = ["名次", "服务器", "IP", "香港", "国际", "大陆", "P95", "v6", "丢失", "Ping", "得分"]

    def row(cells: list[str], colors: list[str]) -> str:
        return "  " + "".join(pad(t.paint(c, t.fg(int(col))) if col else c, w, a)
                              for c, (w, a), col in zip(cells, cols, colors))

    rule(t)
    print("  " + "".join(pad(t.paint(h, t.BOLD), w, a) for (w, a), h in zip(cols, heads)))
    rule(t)
    for i, r in enumerate(shown, 1):
        if r.median is None:
            print(row([str(i), clip(r.name, 15), r.ip, "无响应", "—", "—", "—", "—", "100%", "—", "0"],
                      [C_MUTE, C_MUTE, C_MUTE, C_BAD, C_MUTE, C_MUTE, C_MUTE, C_MUTE,
                       C_BAD, C_MUTE, C_BAD]))
            continue
        if r.v6_median is not None:
            v6_txt = f"{r.v6_median:.0f}/{r.v6_support:.0f}%"
            v6_col = C_OK if r.v6_support >= 95 else C_WARN if r.v6_support >= 50 else C_BAD
        else:
            v6_txt, v6_col = "—", C_MUTE
        cells = [str(i), clip(r.name, 15), r.ip,
                 f"{r.gmedian('香港'):.1f}" if r.gmedian("香港") else "—",
                 f"{r.gmedian('国际'):.1f}" if r.gmedian("国际") else "—",
                 f"{r.gmedian('大陆'):.1f}" if r.gmedian("大陆") else "—",
                 f"{r.p95:.1f}",
                 v6_txt,
                 f"{r.loss:.0f}%",
                 f"{r.icmp:.1f}" if r.icmp is not None else "—",
                 f"{r.score:.0f}"]
        colors = [C_ACCENT, C_NAME, C_MUTE,
                  color_of(r.gmedian("香港")), color_of(r.gmedian("国际")), color_of(r.gmedian("大陆")),
                  C_MUTE, v6_col,
                  C_OK if r.loss == 0 else C_WARN if r.loss < 30 else C_BAD,
                  color_of(r.icmp), C_OK if r.score >= 70 else C_WARN if r.score >= 45 else C_BAD]
        line = row(cells, colors)
        if r.hijack:
            line += "  " + t.paint("⚠ 劫持", t.fg(int(C_BAD)))
        print(line)
    rule(t)
    print("  " + t.paint("单位 ms · 香港/国际/大陆 为各组域名查询延迟中位数 · 得分权重 45%:40%:15%", t.fg(int(C_MUTE))))


def render_cdn(results: list[Result], t: Term) -> None:
    """展示不同 DNS 解析大陆站点时返回的节点差异。"""
    for domain in CDN_PROBE:
        buckets: dict[tuple[str, ...], list[str]] = {}
        for r in results:
            if domain in r.cdn:
                buckets.setdefault(r.cdn[domain], []).append(r.name)
        if not buckets:
            continue
        print()
        print("  " + t.paint(f"{domain} 解析节点分布", t.fg(int(C_ACCENT)), t.BOLD))
        items = sorted(buckets.items(), key=lambda kv: -len(kv[1]))
        for ips, names in items[:5]:
            shown = "、".join(names[:5]) + (f" 等 {len(names)} 个" if len(names) > 5 else "")
            print("    " + t.paint(" · ".join(ips[:2]), t.fg(int(C_NAME)))
                  + "  " + t.paint(shown, t.fg(int(C_MUTE))))
        if len(items) > 1:
            print("    " + t.paint(f"共 {len(items)} 种结果 → 该站点按来源做地域调度, "
                                   f"选 DNS 会直接影响你连到哪个节点", t.fg(int(C_WARN))))


def reliable_pool(results: list[Result], min_reliability: float) -> list[Result]:
    """应答率达标且未劫持的候选; 退化路径与 bench 一致。"""
    alive = [r for r in results if r.median is not None]
    reliable = [r for r in alive if 100 - r.loss >= min_reliability]
    pool = reliable or alive
    clean = [r for r in pool if not r.hijack] or pool
    return clean


def render_scene(results: list[Result], t: Term,
                 min_reliability: float = RELIABILITY_DEFAULT) -> None:
    """分场景最快小结(允许与推荐卡片重复, 保证信息完整)。"""
    clean = reliable_pool(results, min_reliability)
    if not clean:
        return
    probe = CDN_PROBE[0]
    cn_node = next((r.cdn[probe] for r in clean
                    if r.group == "大陆" and probe in r.cdn), None)
    print()
    print("  " + t.paint("分场景最快", t.fg(int(C_ACCENT)), t.BOLD))
    for g in GROUP_ORDER:
        b = min(clean, key=lambda r, g=g: r.gmedian(g) or 999)
        med = b.gmedian(g)
        if med is None:
            continue
        extra = ""
        if g == "大陆" and cn_node:
            extra = "  (解析到大陆节点)" if b.cdn.get(probe) == cn_node else "  (解析到海外节点)"
        print("    " + t.paint(pad(g + "站点", 10), t.fg(int(C_MUTE)))
              + t.paint(pad(clip(b.name, 15), 16), t.fg(int(C_NAME)))
              + t.paint(pad(b.ip, 17), t.fg(int(C_MUTE)))
              + t.paint(pad(f"{med:.1f} ms", 9), t.fg(int(color_of(med))), t.BOLD)
              + t.paint(extra, t.fg(int(C_WARN))))


def card_box(lines: list[tuple[str, str, str]], t: Term) -> None:
    longest = max((dw(f" {a}  {b}") for a, b, _ in lines), default=44)
    inner = min(max(longest + 6, 48), max(t.width - 4, 48))
    print("  " + t.paint("┌" + "─" * (inner - 2) + "┐", t.fg(240)))
    for label, content, color in lines:
        body = clip(f"{t.paint(f' {label} ', t.fg(int(color)), t.BOLD)} {content}", inner - 4)
        print("  " + t.paint("│", t.fg(240)) + " " + pad(body, inner - 4) + " "
              + t.paint("│", t.fg(240)))
    print("  " + t.paint("└" + "─" * (inner - 2) + "┘", t.fg(240)))


def build_recommendations(results: list[Result],
                          min_reliability: float = RELIABILITY_DEFAULT
                          ) -> list[tuple[str, str, str]]:
    clean = reliable_pool(results, min_reliability)
    cards: list[tuple[str, str, str]] = []
    picked: set[str] = set()

    def add(tag, res, content, color):
        if res is None or res.ip in picked:
            return
        picked.add(res.ip)
        cards.append((tag, content, color))

    def best(pool, key):
        return min(pool, key=key) if pool else None

    def brand(r):
        return r.name.split()[0]

    overall = best(clean, lambda r: (-r.score, r.median or 999))
    if overall:
        add("最佳", overall,
            f"{overall.name}  {overall.ip}   "
            f"香港 {overall.gmedian('香港') or 0:.1f} / 国际 {overall.gmedian('国际') or 0:.1f} ms"
            f"  得分 {overall.score:.0f}", C_OK)

    backup = best([r for r in clean if overall and brand(r) != brand(overall)],
                  lambda r: (-r.score, r.median or 999))
    if backup:
        add("备用", backup,
            f"{backup.name}  {backup.ip}   得分 {backup.score:.0f}  (不同运营方, 容灾)", C_ACCENT)

    for g, tag in (("香港", "本地"), ("国际", "国际")):
        b = best(clean, lambda r, g=g: r.gmedian(g) or 999)
        if b is not None:
            add(tag, b, f"{b.name}  {b.ip}   {g}站点 {b.gmedian(g):.1f} ms", C_NAME)

    # 大陆场景: 优先推荐能把大陆站点解析到大陆节点的 DNS, 而不是单纯看延迟
    # —— 在香港用一个"延迟低但返回海外节点"的 DNS 访问淘宝, 实际体验反而更差
    probe = CDN_PROBE[0]
    cn_node = next((r.cdn[probe] for r in clean
                    if r.group == "大陆" and probe in r.cdn), None)
    pool = [r for r in clean if cn_node and r.cdn.get(probe) == cn_node] or clean
    b = best(pool, lambda r: r.gmedian("大陆") or 999)
    if b is not None:
        note = "解析到大陆节点" if cn_node else ""
        add("大陆", b, f"{b.name}  {b.ip}   大陆站点 {b.gmedian('大陆'):.1f} ms"
                       + (f"  ({note})" if note else ""), C_NAME)

    hij = [r for r in clean if r.hijack]
    if hij:
        cards.append(("规避", "、".join(f"{r.name}({r.ip})" for r in hij[:3])
                      + " 存在 NXDOMAIN 劫持", C_BAD))
    return cards


def render_guide(results: list[Result], t: Term,
                 min_reliability: float = RELIABILITY_DEFAULT) -> None:
    clean = reliable_pool(results, min_reliability)
    if not clean:
        return
    ranked = sorted(clean, key=lambda r: (-r.score, r.median or 999))
    primary = ranked[0]
    secondary = next((r for r in ranked[1:] if r.name.split()[0] != primary.name.split()[0]), None)
    print()
    print("  " + t.paint("建议配置", t.fg(int(C_ACCENT)), t.BOLD))
    print("  " + t.paint(f"  首选  {primary.name} {primary.ip}", t.fg(int(C_NAME))))
    if secondary:
        print("  " + t.paint(f"  备用  {secondary.name} {secondary.ip}", t.fg(int(C_NAME))))
    ips = [primary.ip] + ([secondary.ip] if secondary else [])
    print()
    print("  " + t.paint("修改方式", t.fg(int(C_MUTE))))
    if platform.system().lower() == "darwin":
        print("    系统设置 → 网络 → Wi-Fi → 详细信息 → DNS → 添加上面"
              + ("两个 IP" if secondary else "的 IP"))
        print("    命令行: " + t.paint("networksetup -setdnsservers Wi-Fi " + " ".join(ips), t.fg(int(C_OK))))
        print("    生效:   " + t.paint("dscacheutil -flushcache && killall -HUP mDNSResponder", t.fg(int(C_MUTE))))
        print("    还原:   " + t.paint("networksetup -setdnsservers Wi-Fi empty", t.fg(int(C_MUTE))))
    elif platform.system().lower() == "linux":
        print("    /etc/resolv.conf 增加: " + t.paint("nameserver " + primary.ip, t.fg(int(C_OK))))
    else:
        print("    控制面板 → 网络和共享中心 → 适配器 → IPv4 属性 → 填入首选 / 备用 DNS")
    print()


# ──────────────────────────────────────────────────────────────── 主流程


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="dns_bench_hk.py",
        description="DNS 延迟基准测试 · 香港版",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n"
               "  python3 dns_bench_hk.py                 全部服务器(含运营商 DNS)\n"
               "  python3 dns_bench_hk.py --quick         快速模式\n"
               "  python3 dns_bench_hk.py --intl          只看国际 DNS\n"
               "  python3 dns_bench_hk.py --cn            只看大陆 DNS\n"
               "  python3 dns_bench_hk.py -s 1.1.1.1 -s 223.5.5.5\n")
    p.add_argument("-s", "--server", action="append", metavar="IP", help="指定服务器 IP(可重复)")
    p.add_argument("--servers-file", metavar="PATH",
                   help="从文件加载服务器清单, 每行: IP [名称] [分组], # 注释")
    p.add_argument("--intl", action="store_true", help="只测国际 DNS")
    p.add_argument("--cn", action="store_true", help="只测大陆 DNS")
    p.add_argument("--no-local", action="store_true", help="不自动加入本机运营商 DNS")
    p.add_argument("--no-v6", action="store_true", help="跳过 AAAA(IPv6) 查询")
    p.add_argument("--min-reliability", type=float, default=RELIABILITY_DEFAULT, metavar="PCT",
                   help=f"推荐门槛: 应答率低于此百分比不进推荐(默认 {RELIABILITY_DEFAULT:.0f})")
    p.add_argument("-r", "--rounds", type=int, default=4, help="每组每个域名的查询次数(默认 4)")
    p.add_argument("-t", "--timeout", type=float, default=1.5, help="单次查询超时秒数(默认 1.5)")
    p.add_argument("-c", "--concurrency", type=int, default=8, help="并发数(默认 8)")
    p.add_argument("--quick", action="store_true", help="快速模式: 跳过 ping 与劫持检测, 采样减半")
    p.add_argument("--no-ping", action="store_true", help="跳过 ICMP")
    p.add_argument("--top", type=int, metavar="N", help="只显示前 N 名")
    p.add_argument("--json", metavar="PATH", help="导出 JSON")
    p.add_argument("--color", choices=["auto", "always", "never"], default="auto")
    p.add_argument("-q", "--quiet", action="store_true", help="不显示实时面板")
    return p.parse_args(argv)


def build_servers(args) -> tuple[list[tuple[str, str, str]], list[str]]:
    """返回 (服务器清单, 自动加入的运营商 DNS 列表)。"""
    if args.server:
        known = {ip: (n, g) for ip, n, g in SERVERS_HK}
        return [(ip, known.get(ip, ("自定义", "自定义"))[0],
                 known.get(ip, ("自定义", "自定义"))[1]) for ip in args.server], []
    if getattr(args, "servers_file", None):
        return load_servers_file(args.servers_file), []
    if args.intl:
        return [s for s in SERVERS_HK if s[2] == "国际"], []
    if args.cn:
        return [s for s in SERVERS_HK if s[2] == "大陆"], []

    servers = list(SERVERS_HK)
    local_added: list[str] = []
    if not args.no_local:
        known_ips = {s[0] for s in servers}
        for ip in system_dns():
            if ip not in known_ips and not ip.startswith("127.") \
                    and not ip.startswith("198.18."):   # 排除代理软件的虚拟 DNS
                servers.append((ip, "运营商 DNS", "本地"))
                local_added.append(ip)
    return servers, local_added


def _historical_main(argv=None) -> int:
    args = parse_args(argv)
    t = Term(args.color)
    rounds = max(1, args.rounds // 2) if args.quick else args.rounds
    do_ping = not (args.quick or args.no_ping)
    do_hijack = not args.quick

    banner(t)

    servers, local_added = build_servers(args)
    cur = system_dns()
    if cur:
        print("  " + t.paint("本机当前 DNS: ", t.fg(int(C_MUTE))) + t.paint("  ".join(cur), t.fg(int(C_NAME))))
        if has_fake_ip(cur):
            print("  " + t.paint("› 警告: " + FAKE_IP_WARNING, t.fg(int(C_WARN))))
    if local_added:
        print("  " + t.paint("已自动加入运营商 DNS: ", t.fg(int(C_MUTE)))
              + t.paint("  ".join(local_added), t.fg(int(C_ACCENT))))
    print("  " + t.paint(f"测试范围: {len(servers)} 个服务器 · 3 组域名(香港/国际/大陆) · "
                         f"每组每个 {rounds} 次" + ("" if do_ping else " · 跳过 ICMP"), t.fg(int(C_MUTE))))
    print("  " + t.paint("提示: 结果只反映当前所在网络, 抵达香港后请重新测一次再定配置", t.fg(int(C_WARN))))
    print()

    results = [Result(ip, name, group) for ip, name, group in servers]
    by_ip = {r.ip: r for r in results}
    use_panel = t.color and not args.quiet and sys.stdout.isatty()
    panel = Panel(results, t) if use_panel else None
    if panel:
        panel.render(0, len(results))
    else:
        print("  正在测试, 请稍候…")

    start = time.time()
    completed = 0
    try:
        with futures.ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as pool:
            fmap = {pool.submit(probe, r, rounds, args.timeout, do_ping, do_hijack,
                                not args.no_v6): r.ip
                    for r in results}
            for fut in futures.as_completed(fmap):
                ip = fmap[fut]
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

    results.sort(key=lambda r: (r.median is None, -r.score, r.median or 999))

    print()
    render_table(results, t, args.top)
    alive = [r for r in results if r.median is not None]
    print()
    print("  " + t.paint(f"共测试 {len(results)} 个服务器, 有响应 {len(alive)} 个, 耗时 {elapsed:.1f}s",
                         t.fg(int(C_MUTE))))

    render_cdn(results, t)
    render_scene(results, t, args.min_reliability)

    cards = build_recommendations(results, args.min_reliability)
    if cards:
        print()
        print("  " + t.paint("分场景推荐", t.fg(int(C_ACCENT)), t.BOLD))
        card_box(cards, t)

    render_guide(results, t, args.min_reliability)

    if args.json:
        payload = {"generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                   "profile": "hong-kong",
                   "groups": DOMAIN_GROUPS,
                   "rounds_per_domain": rounds,
                   "system_dns": cur,
                   "results": [r.to_dict() for r in results]}
        try:
            with open(args.json, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False, indent=2)
            print("  " + t.paint(f"结果已导出: {args.json}", t.fg(int(C_OK))) + "\n")
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
    return compatibility_main(argv, mode='hk')


if __name__ == "__main__":
    sys.exit(main())
