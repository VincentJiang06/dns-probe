#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DNS LAB · 深度诊断实验室
=======================

不是一个"跑分"脚本。DNS 延迟测量里混杂着大量变量, 一次 ping 式的快照几乎说明不了
任何问题。本工具把变量逐个拆开, 分五个阶段测:

  阶段一 连通性筛查   先剔除不可达服务器, 避免后续长阶段把时间预算浪费在死链路上
  阶段二 延迟画像     冷查询(随机子域, 强制未缓存) 与 缓存命中 分开统计
  阶段三 长尾与抖动   P50/P90/P99 + MAD 离群点检测 —— 中位数会掩盖卡顿
  阶段四 突发压力     并发发起查询, 与串行基线对比, 暴露 QPS 限流与排队劣化
  阶段五 长时间监测   定时采样持续数分钟到数小时, 输出时序曲线与抖动事件

另外贯穿全程的正确性审计: NXDOMAIN 劫持、DNSSEC 验证、ECS 透传、私有地址返回。

用法
----
  python3 dns_lab.py                        # standard, 约 6 分钟
  python3 dns_lab.py --profile quick        # 约 1 分钟
  python3 dns_lab.py --profile marathon     # 约 30 分钟(推荐在你觉得网络不稳时用)
  python3 dns_lab.py --duration 3600        # 自定义监测时长(秒)
  python3 dns_lab.py --duration 1800 --interval 10
  python3 dns_lab.py --profile quick -s 1.1.1.1 -s 223.5.5.5
  python3 dns_lab.py --json lab.json        # 导出完整数据(时序会降采样)

随时 Ctrl+C 中断, 已完成的阶段会照常出报告。

依赖: Python 3.10+ 标准库 + 同目录 dns_core.py。
"""

from __future__ import annotations

import argparse
import concurrent.futures as futures
import json
import random
import statistics
import sys
import time

from dns_core import (FAKE_IP_WARNING, C_ACCENT, C_BAD, C_MUTE, C_NAME, C_OK,
                      C_WARN, Term, clip, color_of, dw, fmt, has_fake_ip,
                      is_private, pad, query, rand_sub, rule, sparkline)
from dns_core import system_dns as _core_system_dns


def system_dns(limit: int = 3) -> list[str]:
    """薄适配: lab 默认只取 3 个, 语义与历史版本保持一致。"""
    return _core_system_dns(limit)

# ══════════════════════════════════════════════════════════════════ 配置

SERVERS: list[tuple[str, str, str]] = [
    ("1.1.1.1",         "Cloudflare",     "国际"),
    ("1.0.0.1",         "Cloudflare 备",  "国际"),
    ("8.8.8.8",         "Google DNS",     "国际"),
    ("9.9.9.9",         "Quad9",          "国际"),
    ("208.67.222.222",  "OpenDNS",        "国际"),
    ("94.140.14.14",    "AdGuard",        "国际"),
    ("64.6.64.6",       "Verisign",       "国际"),
    ("156.154.70.1",    "Neustar",        "国际"),
    ("223.5.5.5",       "阿里 AliDNS",    "大陆"),
    ("223.6.6.6",       "阿里 AliDNS 备", "大陆"),
    ("119.29.29.29",    "腾讯 DNSPod",    "大陆"),
    ("114.114.114.114", "114DNS",         "大陆"),
    ("180.76.76.76",    "百度 DNS",       "大陆"),
    ("168.95.1.1",      "HiNet 台湾",     "亚太"),
    ("101.101.101.101", "Quad101 台湾",   "亚太"),
    ("168.126.63.1",    "KT 韩国",        "亚太"),
]

# 缓存命中的基准域名(真实高频域名, 反映日常浏览体感)
WARM_DOMAINS = ["www.qq.com", "www.baidu.com", "www.taobao.com", "www.apple.com"]
# 冷查询用的父域: 每次生成随机子域, 必然未缓存, 会走完整递归
COLD_PARENTS = ["cloudflare.com", "wikipedia.org", "qq.com", "apple.com"]
# 正确性测试用的标准域名
DNSSEC_OK = "sigok.verteiltesysteme.net"        # 应返回 NOERROR
DNSSEC_FAIL = "sigfail.verteiltesysteme.net"    # 启用验证时应返回 SERVFAIL
ECS_PROBE_DOMAIN = "o-o.myaddr.l.google.com"    # TXT, 返回服务器看到的来源

PROFILES = {
    "quick":    {"cold": 6,  "warm": 12, "burst": 0,  "duration": 0,    "interval": 10, "audit": True},
    "standard": {"cold": 12, "warm": 30, "burst": 25, "duration": 300,  "interval": 15, "audit": True},
    "marathon": {"cold": 15, "warm": 40, "burst": 40, "duration": 1800, "interval": 15, "audit": True},
}


_STAGE_NO = [0]
_CN = ["一", "二", "三", "四", "五", "六"]


def stage(title: str, note: str, t: Term, color=C_ACCENT) -> None:
    _STAGE_NO[0] += 1
    label = f"阶段{_CN[min(_STAGE_NO[0] - 1, len(_CN) - 1)]} · {title}"
    print()
    w = t.width
    print(f"  {t.paint(label, t.fg(int(color)), t.BOLD)}  {t.paint(note, t.fg(int(C_MUTE)))}")
    print("  " + t.paint("─" * (w - 4), t.fg(240)))



# ══════════════════════════════════════════════════════════════════ 统计


class Stream:
    """一组延迟样本的统计量, 重点关注长尾与离群。"""

    def __init__(self):
        self.v: list[float] = []
        self.fail = 0
        self.total = 0

    def add(self, x: float | None) -> None:
        self.total += 1
        if x is None:
            self.fail += 1
        else:
            self.v.append(x)

    @property
    def n(self) -> int:
        return len(self.v)

    @property
    def loss(self) -> float:
        # 未发送过查询(n=0)时返回 0 而非 100: quick 档跳过突发阶段,
        # 若按 100% 计会把所有服务器误判为"限流硬伤", 击穿推荐过滤
        return self.fail / self.total * 100 if self.total else 0.0

    def pct(self, q: float) -> float | None:
        if not self.v:
            return None
        s = sorted(self.v)
        if len(s) == 1:
            return s[0]
        k = (len(s) - 1) * q
        f = int(k)
        c = min(f + 1, len(s) - 1)
        return s[f] + (s[c] - s[f]) * (k - f)

    @property
    def p50(self): return self.pct(0.50)

    @property
    def p90(self): return self.pct(0.90)

    @property
    def p99(self): return self.pct(0.99)

    @property
    def maximum(self): return max(self.v) if self.v else None

    @property
    def mean(self): return statistics.fmean(self.v) if self.v else None

    @property
    def stdev(self): return statistics.pstdev(self.v) if len(self.v) > 1 else 0.0

    @property
    def mad(self) -> float:
        """中位绝对偏差, 比标准差更抗离群, 用于识别抖动事件。"""
        if len(self.v) < 3:
            return 0.0
        m = self.p50 or 0
        return statistics.median([abs(x - m) for x in self.v])

    def outliers(self, k: float = 3.0, floor: float = 1.5) -> list[float]:
        """离群点。除了 MAD 判据, 再加一条绝对下限:
        只有当延迟同时超过中位数的 floor 倍且高出 5ms 才算抖动,
        否则抖动极小的样本集会把它本正常波动全判成离群。"""
        m, d = self.p50, self.mad
        if m is None:
            return []
        thr = max(m + k * 1.4826 * d, m * floor, m + 5)
        return [x for x in self.v if x > thr]

    def to_dict(self) -> dict:
        return {"n": self.n, "loss_percent": round(self.loss, 2),
                "p50": round(self.p50, 2) if self.p50 is not None else None,
                "p90": round(self.p90, 2) if self.p90 is not None else None,
                "p99": round(self.p99, 2) if self.p99 is not None else None,
                "max": round(self.maximum, 2) if self.maximum is not None else None,
                "stdev": round(self.stdev, 2), "mad": round(self.mad, 2),
                "outlier_count": len(self.outliers())}


# ══════════════════════════════════════════════════════════════════ 结果模型


class Lab:
    def __init__(self, ip: str, name: str, group: str):
        self.ip, self.name, self.group = ip, name, group
        self.alive = False
        self.downed_at = ""
        self.warm = Stream()
        self.cold = Stream()
        self.burst = Stream()
        self.series: list[float | None] = []
        self.series_ts: list[float] = []
        self.hijack = False
        self.hijack_note: str | None = None
        self.private_ip = False
        self.dnssec_validate: bool | None = None
        self.dnssec_ad: bool | None = None
        self.ecs: bool | None = None
        self.pop_site: str | None = None     # anycast 落点(NSID/id.server, 常为机场码)
        self.dot_support = False             # DNS-over-TLS (853) 可用
        self.dot_rtt: float | None = None
        self.v6_rtt: float | None = None     # AAAA(IPv6) 查询延迟
        self.ladder: list[dict] = []         # 阶梯压测明细 [{concurrency, p50, loss, ratio}]
        self.notes: list[str] = []

    # —— 派生指标 ——
    @property
    def burst_ratio(self) -> float | None:
        """突发并发相对串行基线的劣化倍数。

        基线必须用同为冷查询的 cold.p50: 并发压测用的是随机子域(未缓存),
        若拿它去比缓存命中的 warm.p50, 等于把"递归耗时"算成了限流。
        """
        a, b = self.cold.p50, self.burst.p50
        if a and b and a > 0:
            return b / a
        return None

    @property
    def drift(self) -> float | None:
        """长时间监测的后半程相对前半程的漂移比例, 反映是否随时间劣化。"""
        s = [x for x in self.series if x is not None]
        if len(s) < 8:
            return None
        half = len(s) // 2
        first, second = statistics.median(s[:half]), statistics.median(s[half:])
        return (second - first) / first if first else None

    @property
    def availability(self) -> float | None:
        total = len(self.series)
        if not total:
            return None
        return sum(1 for x in self.series if x is not None) / total * 100

    @property
    def score(self) -> float:
        if not self.alive:
            return 0.0
        p50, p99, cold = self.warm.p50, self.warm.p99, self.cold.p50
        # 延迟 25 分
        lat = 25.0 * (1 - min(p50 or 200, 200) / 200) ** 1.6 if p50 else 0
        # 长尾 25 分
        tail = 25.0 * (1 - min(p99 or 400, 400) / 400) ** 1.6 if p99 else 0
        # 冷查询 15 分(首次访问体验)
        c = 15.0 * (1 - min(cold or 400, 400) / 400) ** 1.4 if cold else 0
        # 稳定性 20 分: 抖动 + 离群率 + 长时漂移 + 可用率
        jit = 8.0 * max(0.0, 1 - min(self.warm.stdev, 50) / 50)
        out_rate = len(self.warm.outliers()) / max(1, self.warm.n)
        out_s = 5.0 * max(0.0, 1 - out_rate * 10)
        drift_pen = 4.0 if (self.drift or 0) > 0.25 else 0.0
        avail = 3.0 * ((self.availability or 100) / 100)
        # 并发表现 10 分
        br = self.burst_ratio
        burst = 10.0 if br is None else max(0.0, 10.0 - max(0.0, br - 1.3) * 6)
        # 正确性 5 分
        audit = 5.0
        if self.hijack:
            audit -= 3
        if self.private_ip:
            audit -= 2
        if self.dnssec_validate:
            audit = min(5.0, audit + 0.5)
        total = lat + tail + c + jit + out_s + avail + burst + audit - drift_pen
        return max(0.0, min(100.0, total))

    def to_dict(self) -> dict:
        return {
            "ip": self.ip, "name": self.name, "group": self.group, "alive": self.alive,
            "warm": self.warm.to_dict(), "cold": self.cold.to_dict(),
            "burst": self.burst.to_dict(),
            "burst_ratio": round(self.burst_ratio, 2) if self.burst_ratio else None,
            "series_sampled": _downsample(self.series, 200),
            "availability_percent": round(self.availability, 2) if self.availability else None,
            "drift": round(self.drift, 3) if self.drift else None,
            "hijack": self.hijack, "private_ip": self.private_ip,
            "dnssec_validating": self.dnssec_validate, "dnssec_ad": self.dnssec_ad,
            "ecs": self.ecs, "notes": self.notes,
            "score": round(self.score, 1),
        }


def _downsample(seq: list, limit: int) -> list:
    if len(seq) <= limit:
        return [round(x, 2) if isinstance(x, float) else x for x in seq]
    step = len(seq) / limit
    return [round(seq[int(i * step)], 2) if isinstance(seq[int(i * step)], float) else None
            for i in range(limit)]


# ══════════════════════════════════════════════════════════════════ 阶段


def stage_reach(labs: list[Lab], timeout: float, t: Term, emit) -> None:
    stage("连通性筛查", "谁在线, 谁不在线", t)

    def work(lab: Lab):
        for d in ("www.qq.com", "www.cloudflare.com", "www.wikipedia.org"):
            rtt, p = query(lab.ip, d, timeout=timeout)
            lab.warm.add(rtt)          # 顺带作为后续预热的第一次
            if rtt is not None:
                lab.alive = True
                return
        lab.alive = False

    with futures.ThreadPoolExecutor(max_workers=12) as ex:
        list(ex.map(work, labs))

    down = [l for l in labs if not l.alive]
    for lab in labs:
        mark = t.paint("✓ 在线", t.fg(int(C_OK))) if lab.alive else t.paint("✕ 不可达", t.fg(int(C_BAD)))
        first = f"{lab.warm.p50:.1f} ms" if lab.warm.p50 else ""
        print("  " + t.paint(pad(clip(lab.name, 15), 16), t.fg(int(C_NAME)))
              + t.paint(pad(lab.ip, 17), t.fg(int(C_MUTE))) + mark + "  "
              + t.paint(first, t.fg(int(color_of(lab.warm.p50)))))
    if down:
        emit("info", f"{len(down)} 个服务器不可达, 后续阶段跳过: "
                     + "、".join(f"{l.name}" for l in down[:4])
                     + (" 等" if len(down) > 4 else ""))


def stage_latency(labs: list[Lab], cold_n: int, warm_n: int, timeout: float, t: Term, emit) -> None:
    stage("延迟画像", "冷查询(未缓存) 与 缓存命中 分开统计", t)

    def work(lab: Lab):
        lab.warm = Stream()            # 重置筛查阶段的样本
        # 冷查询: 随机子域, 必然未缓存, 走完整递归
        for _ in range(cold_n):
            rtt, _p = query(lab.ip, rand_sub(random.choice(COLD_PARENTS)), timeout=timeout)
            lab.cold.add(rtt)
            time.sleep(0.01)
        # 缓存命中: 先预热, 再连测
        for d in WARM_DOMAINS:
            query(lab.ip, d, timeout=timeout)
        for i in range(warm_n):
            d = WARM_DOMAINS[i % len(WARM_DOMAINS)]
            rtt, _p = query(lab.ip, d, timeout=timeout)
            lab.warm.add(rtt)
            time.sleep(0.01)

    alive = [l for l in labs if l.alive]
    with futures.ThreadPoolExecutor(max_workers=8) as ex:
        list(ex.map(work, alive))

    for lab in alive:
        print("  " + t.paint(pad(clip(lab.name, 15), 16), t.fg(int(C_NAME)))
              + t.paint(pad(lab.ip, 17), t.fg(int(C_MUTE)))
              + t.paint("缓存 ", t.fg(int(C_MUTE)))
              + t.paint(pad(fmt(lab.warm.p50, 1, " ms"), 10), t.fg(int(color_of(lab.warm.p50))), t.BOLD)
              + t.paint("冷查询 ", t.fg(int(C_MUTE)))
              + t.paint(pad(fmt(lab.cold.p50, 1, " ms"), 10), t.fg(int(color_of(lab.cold.p50))))
              + t.paint("丢失 ", t.fg(int(C_MUTE)))
              + t.paint(f"{lab.warm.loss + lab.cold.loss:.0f}%", t.fg(int(C_MUTE))))
    emit("info", "缓存命中 = 日常重复访问; 冷查询 = 首次访问某域名, 两者差 3-10 倍属正常")


def stage_burst(labs: list[Lab], n: int, timeout: float, t: Term, emit) -> None:
    if n <= 0:
        return
    stage("突发压力", "并发冷查询 vs 串行冷查询, 只有同类型才可比", t)

    def work(lab: Lab):
        domains = [rand_sub(random.choice(COLD_PARENTS)) for _ in range(n)]
        with futures.ThreadPoolExecutor(max_workers=n) as ex:
            futs = [ex.submit(query, lab.ip, d, 1, timeout) for d in domains]
            for f in futures.as_completed(futs):
                rtt, _p = f.result()
                lab.burst.add(rtt)

    with futures.ThreadPoolExecutor(max_workers=4) as ex:
        list(ex.map(work, [l for l in labs if l.alive]))

    emit("info", "基线同为冷查询; 劣化幅度含本机 UDP 栈与 Wi-Fi 排队, 是上限而非纯服务端限流")

    for lab in labs:
        if not lab.alive:
            continue
        ratio = lab.burst_ratio
        txt = f"×{ratio:.2f}" if ratio else "—"
        col = C_OK
        if ratio and ratio > 3.0:
            col = C_BAD
        elif ratio and ratio > 2.0:
            col = C_WARN
        print("  " + t.paint(pad(clip(lab.name, 15), 16), t.fg(int(C_NAME)))
              + t.paint(pad(lab.ip, 17), t.fg(int(C_MUTE)))
              + t.paint("并发冷查 ", t.fg(int(C_MUTE)))
              + t.paint(pad(fmt(lab.burst.p50, 1, " ms"), 11), t.fg(int(color_of(lab.burst.p50))))
              + t.paint("劣化 ", t.fg(int(C_MUTE)))
              + t.paint(pad(txt, 8), t.fg(int(col)))
              + t.paint(f"丢失 {lab.burst.loss:.0f}%", t.fg(int(C_MUTE))) +
              ("  " + t.paint("疑似限流", t.fg(int(C_BAD))) if ratio and ratio > 3.0 else ""))
        if ratio and ratio > 3.0:
            emit("warn", f"{lab.name} 并发下延迟劣化 {ratio:.1f} 倍, 可能有 QPS 限流"
                         f" (含本机网络栈与无线链路排队, 属劣化上限)")
        if lab.burst.loss > 10:
            emit("warn", f"{lab.name} 并发下丢包 {lab.burst.loss:.0f}%, 存在明显限流"
                         f" —— 丢包比延迟更能说明问题, 重传会直接拖慢整页加载")


def stage_audit(labs: list[Lab], timeout: float, t: Term, emit) -> None:
    stage("正确性审计", "劫持 / DNSSEC / ECS / 私有地址", t)

    def work(lab: Lab):
        # NXDOMAIN 劫持: 不存在的域名若返回答案即为劫持
        rtt, p = query(lab.ip, rand_sub("lab-nx.invalid"), timeout=timeout)
        if p and p.get("rcode") == 0 and p.get("ancount", 0) > 0:
            lab.hijack = True
        # 私有地址返回(典型劫持/内网劫持特征)
        for d in WARM_DOMAINS[:2]:
            _r, pp = query(lab.ip, d, timeout=timeout)
            if pp and any(is_private(x) for x in pp.get("ips", [])):
                lab.private_ip = True
        # DNSSEC: sigok 应成功, sigfail 启用验证时应 SERVFAIL
        _r, ok = query(lab.ip, DNSSEC_OK, timeout=timeout, do=True)
        _r, bad = query(lab.ip, DNSSEC_FAIL, timeout=timeout, do=True)
        if ok is not None:
            lab.dnssec_ad = bool(ok.get("ad"))
        if bad is not None:
            lab.dnssec_validate = bad.get("rcode") == 2
        # ECS: 带伪造子网查询, 看服务器是否按子网调度
        _r, ecs = query(lab.ip, ECS_PROBE_DOMAIN, qtype=16, timeout=timeout,
                        ecs=("1.2.3.4", 24))
        if ecs and ecs.get("txt"):
            lab.ecs = "1.2.3" in "".join(ecs["txt"]) or bool(ecs.get("opt", {}) and
                                                             ecs["opt"].get("ecs"))
        elif ecs and ecs.get("opt", {}) and ecs["opt"].get("ecs"):
            lab.ecs = True

    with futures.ThreadPoolExecutor(max_workers=8) as ex:
        list(ex.map(work, [l for l in labs if l.alive]))

    for lab in labs:
        if not lab.alive:
            continue
        def mark(ok, yes="✓", no="—"):
            if ok is None:
                return t.paint("?", t.fg(int(C_MUTE)))
            return t.paint(yes, t.fg(int(C_OK))) if ok else t.paint(no, t.fg(int(C_MUTE)))

        hij = t.paint("⚠ 劫持", t.fg(int(C_BAD))) if lab.hijack else ""
        print("  " + t.paint(pad(clip(lab.name, 15), 16), t.fg(int(C_NAME)))
              + t.paint(pad(lab.ip, 17), t.fg(int(C_MUTE)))
              + t.paint("DNSSEC验证 ", t.fg(int(C_MUTE))) + pad(mark(lab.dnssec_validate), 3)
              + t.paint(" ECS ", t.fg(int(C_MUTE))) + pad(mark(lab.ecs), 3)
              + t.paint(" 私有地址 ", t.fg(int(C_MUTE)))
              + pad(t.paint("⚠", t.fg(int(C_BAD))) if lab.private_ip
                    else t.paint("—", t.fg(int(C_MUTE))), 3)
              + hij)
        if lab.hijack:
            emit("danger", f"{lab.name} 存在 NXDOMAIN 劫持: 不存在的域名被解析出 IP")


SPIN = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]


def stage_marathon(labs: list[Lab], duration: int, interval: int, timeout: float,
                   t: Term, emit) -> None:
    if duration <= 0:
        return
    stage("长时间监测",
          f"每 {interval}s 采样一次, 持续 {duration // 60} 分 {duration % 60} 秒 · Ctrl+C 可提前结束", t)

    alive = [l for l in labs if l.alive]
    rounds = max(1, duration // interval)
    live = t.color and sys.stdout.isatty() and t.rows >= len(alive) + 5
    printed = 0
    frame = [0]

    def draw(r: int) -> None:
        nonlocal printed
        if not live:
            return
        if printed:
            sys.stdout.write(f"\033[{printed}A\033[J")
        frame[0] += 1
        bw = max(10, min(30, t.width - 40))
        filled = int(bw * r / rounds)
        bar = t.paint("█" * filled, t.fg(int(C_ACCENT))) + t.paint("░" * (bw - filled), t.fg(240))
        used = r * interval
        print("  " + t.paint(f"{used // 60:02d}:{used % 60:02d} / {duration // 60:02d}:{duration % 60:02d}",
                             t.BOLD) + "  " + bar + "  "
              + t.paint(SPIN[frame[0] % 10], t.fg(int(C_ACCENT))))
        print()
        for lab in alive:
            vals = [x for x in lab.series if x is not None]
            cur = lab.series[-1] if lab.series else None
            line = ("  " + t.paint(pad(clip(lab.name, 15), 16), t.fg(int(C_NAME)))
                    + t.paint(pad(fmt(cur, 1, " ms"), 10), t.fg(int(color_of(cur))))
                    + t.paint(sparkline(vals, 30), t.fg(int(color_of(statistics.median(vals) if vals else None)))))
            print(line)
        printed = len(alive) + 3
        sys.stdout.flush()

    print()
    try:
        for r in range(1, rounds + 1):
            t0 = time.time()

            def one(lab: Lab):
                # 每轮查全部域名取中位数, 模拟"打开一个含多个域名的网页",
                # 口径与阶段二的缓存 P50 一致, 两条曲线才可比
                samples = [query(lab.ip, d, timeout=timeout)[0] for d in WARM_DOMAINS]
                vals = [x for x in samples if x is not None]
                lab.series.append(statistics.median(vals) if vals else None)
                lab.series_ts.append(time.time())

            with futures.ThreadPoolExecutor(max_workers=min(16, len(alive))) as ex:
                list(ex.map(one, alive))
            draw(r)
            left = interval - (time.time() - t0)
            if left > 0 and r < rounds:
                time.sleep(left)
    except KeyboardInterrupt:
        emit("info", "监测被手动中断, 已保留此前的采样数据")
    finally:
        if not live:
            print("  " + t.paint("监测结束", t.fg(int(C_MUTE))))

    # 抖动事件与漂移
    for lab in alive:
        vals = [x for x in lab.series if x is not None]
        if len(vals) < 8:
            continue
        med = statistics.median(vals)
        mad = statistics.median([abs(x - med) for x in vals]) or 0
        spikes = [x for x in vals if mad > 0 and x > med + 4 * 1.4826 * mad]
        if spikes:
            lab.notes.append(f"监测期间出现 {len(spikes)} 次抖动尖峰, 最高 {max(spikes):.0f} ms"
                             f" (中位 {med:.0f} ms)")
        if (lab.drift or 0) > 0.25:
            lab.notes.append(f"后半程比前半程慢 {lab.drift * 100:.0f}%, 存在持续劣化")
        if lab.availability is not None and lab.availability < 99:
            lab.notes.append(f"监测期间可用率 {lab.availability:.1f}%")


# ══════════════════════════════════════════════════════════════════ 报告


def render_report(labs: list[Lab], t: Term, findings: list[tuple[str, str]]) -> None:
    alive = [l for l in labs if l.alive]
    ranked = sorted(alive, key=lambda l: -l.score)
    dead = [l for l in labs if not l.alive]

    # 长尾自动发现: 中位数掩盖的偶发卡顿, 这里显式点出来
    tail = [(l.warm.p99 / l.warm.p50, l) for l in alive
            if l.warm.p50 and l.warm.p99 and l.warm.p50 > 0
            and l.warm.p99 / l.warm.p50 > 3]
    for ratio, l in sorted(tail, key=lambda x: -x[0])[:3]:
        findings.append(("warn", f"{l.name} 长尾偏长: P99 {l.warm.p99:.0f} ms 是 P50 的 {ratio:.1f} 倍, "
                                 f"中位数完全看不出这种偶发卡顿"))
    if len(tail) > 3:
        findings.append(("info", f"另有 {len(tail) - 3} 个服务器 P99/P50 也超过 3 倍, 属该批次的普遍现象"))

    # 排行榜: 只显示本次真正测过的维度
    print()
    print("  " + t.paint("综合排行榜", t.fg(int(C_ACCENT)), t.BOLD))
    has_series = any(len([x for x in l.series if x is not None]) >= 2 for l in labs)
    has_burst = any(l.burst.n for l in labs)
    cols = [(4, "center"), (15, "left"), (16, "left"), (8, "right"), (8, "right"),
            (9, "right"), (8, "right")]
    heads = ["#", "服务器", "IP", "缓存P50", "P99", "冷查询", "抖动"]
    if has_burst:
        cols.append((7, "right"))
        heads.append("劣化")
    if has_series:
        cols += [(6, "right"), (12, "left")]
        heads += ["可用", "时序"]
    cols.append((5, "right"))
    heads.append("得分")

    def row(cells, colors) -> str:
        return "  " + " ".join(pad(t.paint(c, t.fg(int(col))) if col else c, w, a)
                               for (w, a), c, col in zip(cols, cells, colors))

    rule(t)
    print(row(heads, [C_MUTE] * len(heads)))
    rule(t)
    for i, l in enumerate(ranked, 1):
        cells = [str(i), clip(l.name, 14), l.ip,
                 fmt(l.warm.p50, 1), fmt(l.warm.p99, 1), fmt(l.cold.p50, 1), fmt(l.warm.stdev, 1)]
        colors = [C_ACCENT, C_NAME, C_MUTE, color_of(l.warm.p50), color_of(l.warm.p99),
                  color_of(l.cold.p50),
                  C_OK if l.warm.stdev < 5 else C_WARN if l.warm.stdev < 20 else C_BAD]
        if has_burst:
            cells.append(f"×{l.burst_ratio:.1f}" if l.burst_ratio else "—")
            colors.append(C_OK if (l.burst_ratio or 1) < 2.0
                          else C_WARN if (l.burst_ratio or 1) < 3.0 else C_BAD)
        if has_series:
            cells += [f"{l.availability:.0f}%" if l.availability is not None else "—",
                      sparkline([x for x in l.series if x is not None], 12)]
            colors += [C_OK if (l.availability or 100) >= 99.5
                       else C_WARN if (l.availability or 100) >= 98 else C_BAD, C_ACCENT]
        cells.append(f"{l.score:.0f}")
        colors.append(C_OK if l.score >= 70 else C_WARN if l.score >= 50 else C_BAD)
        line = row(cells, colors)
        if l.hijack:
            line += " " + t.paint("⚠劫持", t.fg(int(C_BAD)))
        print(line)
    for l in dead:
        cells = [str(len(ranked) + dead.index(l) + 1), clip(l.name, 14), l.ip,
                 "无响应", "—", "—", "—"]
        colors = [C_MUTE, C_MUTE, C_MUTE, C_BAD, C_MUTE, C_MUTE, C_MUTE]
        if has_burst:
            cells.append("—")
            colors.append(C_MUTE)
        if has_series:
            cells += ["0%", ""]
            colors += [C_BAD, C_MUTE]
        cells.append("0")
        colors.append(C_BAD)
        print(row(cells, colors))
    rule(t)

    # 长尾明细
    print()
    print("  " + t.paint("长尾与抖动明细", t.fg(int(C_ACCENT)), t.BOLD))
    for l in ranked[:8]:
        out = l.warm.outliers()
        print("  " + t.paint(pad(clip(l.name, 15), 16), t.fg(int(C_NAME)))
              + t.paint("P50 ", t.fg(int(C_MUTE))) + t.paint(pad(fmt(l.warm.p50, 1, "ms"), 9), t.fg(int(C_OK)))
              + t.paint(" P90 ", t.fg(int(C_MUTE))) + t.paint(pad(fmt(l.warm.p90, 1, "ms"), 9), t.fg(int(C_WARN)))
              + t.paint(" P99 ", t.fg(int(C_MUTE))) + t.paint(pad(fmt(l.warm.p99, 1, "ms"), 9), t.fg(int(C_BAD)))
              + t.paint(" 最大 ", t.fg(int(C_MUTE))) + t.paint(pad(fmt(l.warm.maximum, 1, "ms"), 9), t.fg(int(C_MUTE)))
              + t.paint(f" 离群 {len(out)}/{l.warm.n}", t.fg(int(C_MUTE))))

    # 时序曲线
    with_series = [l for l in ranked if len([x for x in l.series if x is not None]) >= 4]
    if with_series:
        print()
        print("  " + t.paint("长时间监测曲线", t.fg(int(C_ACCENT)), t.BOLD))
        for l in with_series[:10]:
            vals = [x for x in l.series if x is not None]
            print("  " + t.paint(pad(clip(l.name, 15), 16), t.fg(int(C_NAME)))
                  + t.paint(sparkline(vals, 40), t.fg(int(color_of(statistics.median(vals)))))
                  + "  " + t.paint(f"中位 {statistics.median(vals):.0f} ms", t.fg(int(C_MUTE))))

    # 备注
    noted = [l for l in ranked if l.notes]
    if noted:
        print()
        print("  " + t.paint("监测期间的异常", t.fg(int(C_ACCENT)), t.BOLD))
        for l in noted:
            for n in l.notes:
                print("    " + t.paint(pad(clip(l.name, 15), 16), t.fg(int(C_NAME)))
                      + t.paint(n, t.fg(int(C_WARN))))

    # 发现
    if findings:
        print()
        print("  " + t.paint("关键发现", t.fg(int(C_ACCENT)), t.BOLD))
        for level, msg in findings:
            col = C_BAD if level == "danger" else C_WARN if level == "warn" else C_MUTE
            dot = "!" if level == "danger" else "*" if level == "warn" else "-"
            print("    " + t.paint(dot, t.fg(int(col))) + "  " + t.paint(msg, t.fg(int(col))))

    # 推荐
    if ranked:
        print()
        print("  " + t.paint("推荐", t.fg(int(C_ACCENT)), t.BOLD))
        # 有明确限流(并发高丢包) 或 劫持的服务器不参与推荐
        healthy = [l for l in ranked if l.burst.loss <= 10 and not l.hijack] or ranked
        best = healthy[0]
        cards: list[tuple[str, str, str]] = []
        picked: set[str] = set()

        def add(tag: str, lab: Lab, content: str, col: str) -> None:
            if lab is None or lab.ip in picked:
                return
            picked.add(lab.ip)
            cards.append((tag, content, col))

        add("首选", best, f"{best.name}  {best.ip}   缓存 {best.warm.p50:.1f} / P99 "
                          f"{best.warm.p99 or 0:.1f} / 冷 {best.cold.p50 or 0:.1f} ms"
                          f"   得分 {best.score:.0f}", C_OK)
        backup = next((l for l in healthy[1:]
                       if l.name.split()[0] != best.name.split()[0] and l.ip not in picked), None)
        add("备用", backup, f"{backup.name}  {backup.ip}   得分 {backup.score:.0f}"
                            f"  (与首选不同运营方)" if backup else "", C_ACCENT)
        steady = min(healthy, key=lambda l: (l.warm.stdev, l.warm.p99 or 999))
        add("最稳", steady, f"{steady.name}  {steady.ip}   抖动 {steady.warm.stdev:.1f} ms"
                            f"  P99 {steady.warm.p99 or 0:.1f} ms", C_ACCENT)
        fast_cold = min((l for l in healthy if l.cold.p50), key=lambda l: l.cold.p50, default=None)
        add("首访", fast_cold, f"{fast_cold.name}  {fast_cold.ip}   冷查询 "
                               f"{fast_cold.cold.p50:.1f} ms  (打开新网站最快)"
                               if fast_cold else "", C_NAME)
        longest = max(dw(f" {a}  {b}") for a, b, _ in cards)
        inner = min(max(longest + 6, 50), max(t.width - 4, 50))
        print("  " + t.paint("┌" + "─" * (inner - 2) + "┐", t.fg(240)))
        for tag, content, col in cards:
            body = clip(f"{t.paint(f' {tag} ', t.fg(int(col)), t.BOLD)} {content}", inner - 4)
            print("  " + t.paint("│", t.fg(240)) + " " + pad(body, inner - 4) + " "
                  + t.paint("│", t.fg(240)))
        print("  " + t.paint("└" + "─" * (inner - 2) + "┘", t.fg(240)))


# ══════════════════════════════════════════════════════════════════ 主流程


def _historical_main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="dns_lab.py", description="DNS LAB · 深度诊断实验室",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例:\n"
               "  python3 dns_lab.py --profile quick        1 分钟快速体检\n"
               "  python3 dns_lab.py                        约 6 分钟标准诊断\n"
               "  python3 dns_lab.py --profile marathon     约 30 分钟马拉松\n"
               "  python3 dns_lab.py --duration 3600 --interval 20\n")
    p.add_argument("--profile", choices=list(PROFILES), default="standard")
    p.add_argument("--duration", type=int, help="覆盖监测时长(秒)")
    p.add_argument("--interval", type=int, help="覆盖采样间隔(秒)")
    p.add_argument("-s", "--server", action="append", metavar="IP", help="指定服务器(可重复)")
    p.add_argument("-t", "--timeout", type=float, default=2.0, help="单次查询超时(默认 2s)")
    p.add_argument("--no-audit", action="store_true", help="跳过正确性审计")
    p.add_argument("--no-local", action="store_true", help="不自动加入运营商 DNS")
    p.add_argument("--json", metavar="PATH", help="导出完整数据")
    p.add_argument("--color", choices=["auto", "always", "never"], default="auto")
    args = p.parse_args(argv)

    t = Term(args.color)
    cfg = dict(PROFILES[args.profile])
    if args.duration is not None:
        cfg["duration"] = args.duration
    if args.interval is not None:
        cfg["interval"] = max(2, args.interval)
    if args.no_audit:
        cfg["audit"] = False

    # 服务器清单
    if args.server:
        known = {ip: (n, g) for ip, n, g in SERVERS}
        servers = [(ip, known.get(ip, ("自定义", "自定义"))[0],
                    known.get(ip, ("自定义", "自定义"))[1]) for ip in args.server]
    else:
        servers = list(SERVERS)
        if not args.no_local:
            have = {s[0] for s in servers}
            for ip in system_dns():
                if ip not in have and not ip.startswith(("127.", "198.18.")):
                    servers.append((ip, "运营商 DNS", "本地"))
    labs = [Lab(ip, name, group) for ip, name, group in servers]

    findings: list[tuple[str, str]] = []

    def emit(level: str, msg: str) -> None:
        if level != "info":          # 解释性提示不算"发现"
            findings.append((level, msg))
        col = C_BAD if level == "danger" else C_WARN if level == "warn" else C_MUTE
        print("    " + t.paint("› " + msg, t.fg(int(col))))

    print()
    print("  " + t.paint("DNS LAB", t.fg(int(C_ACCENT)), t.BOLD)
          + t.paint("  ·  深度诊断实验室", t.fg(int(C_MUTE))))
    print("  " + t.paint(f"{len(labs)} 个服务器 · 5 个阶段 · 预计 "
                         f"{(cfg['duration'] + len(labs) * 3) // 60} 分钟", t.fg(int(C_MUTE))))
    cur = system_dns()
    if cur:
        print("  " + t.paint("本机当前 DNS: ", t.fg(int(C_MUTE))) + t.paint("  ".join(cur), t.fg(int(C_NAME))))
        if has_fake_ip(cur):
            emit("warn", FAKE_IP_WARNING)

    started = time.time()
    try:
        stage_reach(labs, args.timeout, t, emit)
        stage_latency(labs, cfg["cold"], cfg["warm"], args.timeout, t, emit)
        stage_burst(labs, cfg["burst"], args.timeout, t, emit)
        if cfg["audit"]:
            stage_audit(labs, args.timeout, t, emit)
        stage_marathon(labs, cfg["duration"], cfg["interval"], args.timeout, t, emit)
    except KeyboardInterrupt:
        print("\n  " + t.paint("已中断, 输出已完成部分的结果", t.fg(int(C_WARN))))

    render_report(labs, t, findings)
    print()
    print("  " + t.paint(f"总耗时 {time.time() - started:.0f}s", t.fg(int(C_MUTE))))

    if args.json:
        payload = {"generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                   "profile": args.profile,
                   "duration": cfg["duration"], "interval": cfg["interval"],
                   "system_dns": cur,
                   "findings": findings,
                   "servers": [l.to_dict() for l in labs]}
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
    return compatibility_main(argv, mode='lab')


if __name__ == "__main__":
    sys.exit(main())
