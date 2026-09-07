#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dns_core · DNS 测速工具族的共享核心
===================================

被 dns_bench.py / dns_bench_hk.py / dns_lab.py 引用, 不单独运行。
三件事曾经各写一份、已经出现语义分歧(如 ping_host 的 macOS 超时参数),
现在收拢为唯一实现 —— 改 bug 只改这里, 三个工具同步生效。

分层
----
  终端呈现   Term / 调色板 / dw·pad·clip / gradient / sparkline / fmt·color_of / rule
  DNS 协议   build_opt·build_query(EDNS/DO/ECS) / parse(完整解析) / query / rand_sub / is_private
  探测辅助   detect_hijack / ping_host / system_dns / fake-IP 代理接管检测
  常量       DNS_PORT / NX_SUFFIX

依赖: 仅 Python 标准库; 需 Python >= 3.10 (union 类型标注)。
"""

from __future__ import annotations

import os
import platform
import random
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import time
import unicodedata

DNS_PORT = 53
NX_SUFFIX = "dnsbench-nx.invalid"   # 劫持检测用的必然不存在域名后缀

# ══════════════════════════════════════════════════════════════════ 终端呈现


class Term:
    """终端能力探测与彩色输出。mode: auto(默认) / always / never。

    非 TTY 或设置 NO_COLOR 时自动降级为纯文本; Windows 下额外排除 dumb 终端。
    """

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    def __init__(self, mode: str = "auto"):
        self.mode = mode
        self.color = False
        self.width = 110
        self.rows = 24
        try:
            size = shutil.get_terminal_size((110, 24))
            self.width = max(76, min(118, size.columns))
            self.rows = size.lines
        except Exception:
            pass
        if mode == "always":
            self.color = True
        elif mode == "never":
            self.color = False
        else:
            self.color = bool(sys.stdout.isatty()) and not os.environ.get("NO_COLOR")
            if platform.system().lower() == "windows":
                self.color = self.color and os.environ.get("TERM", "") != "dumb"

    @staticmethod
    def fg(code: int) -> str:
        return f"\033[38;5;{code}m"

    def paint(self, text: str, *codes: str) -> str:
        return ("".join(codes) + text + self.RESET) if (self.color and codes) else text

    def truecolor(self, r: int, g: int, b: int) -> str:
        if not self.color:
            return ""
        return f"\033[38;2;{r};{g};{b}m"


# 调色板(256 色索引)
C_OK = "46"       # 绿
C_WARN = "226"    # 黄
C_BAD = "203"     # 红
C_MUTE = "244"    # 灰
C_NAME = "159"    # 浅青
C_ACCENT = "141"  # 紫
C_DIM = "240"     # 分隔线


def dw(text: str) -> int:
    """按终端显示宽度计算长度(中日韩全角字符占 2 列)。"""
    return sum(2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1 for ch in text)


def pad(text: str, width: int, align: str = "left") -> str:
    n = max(0, width - dw(text))
    if align == "right":
        return " " * n + text
    if align == "center":
        left = n // 2
        return " " * left + text + " " * (n - left)
    return text + " " * n


def clip(text: str, width: int) -> str:
    """超宽截断, 保证显示宽度不超过 width。"""
    if dw(text) <= width:
        return text
    out, total = "", 0
    for ch in text:
        w = dw(ch)
        if total + w > width - 1:
            break
        out += ch
        total += w
    return out + "…"


def gradient(text: str, t: Term, stops: list[tuple[int, int, int]]) -> str:
    """对文本逐字符应用 RGB 渐变色。"""
    if not t.color or not text:
        return text
    n = len(text)
    out = []
    for i, ch in enumerate(text):
        pos = i / max(1, n - 1) * (len(stops) - 1)
        idx = min(int(pos), len(stops) - 2)
        frac = pos - idx
        c1, c2 = stops[idx], stops[idx + 1]
        out.append(t.truecolor(int(c1[0] + (c2[0] - c1[0]) * frac),
                               int(c1[1] + (c2[1] - c1[1]) * frac),
                               int(c1[2] + (c2[2] - c1[2]) * frac)) + ch)
    return "".join(out) + t.RESET


BLOCKS = "▁▂▃▄▅▆▇█"


def sparkline(values: list[float], width: int = 24) -> str:
    """把时序数据压成 Unicode 火花线(超长自动等距降采样)。"""
    vals = values or []
    if len(vals) > width:
        step = len(vals) / width
        vals = [vals[int(i * step)] for i in range(width)]
    if not vals:
        return ""
    lo, hi = min(vals), max(vals)
    if hi - lo < 1e-6:
        return BLOCKS[0] * len(vals)
    return "".join(BLOCKS[min(7, int((v - lo) / (hi - lo) * 7.999))] for v in vals)


def fmt(v, nd: int = 1, unit: str = "") -> str:
    """数值格式化: None 显示为 em-dash, 不会出现 'nan ms' 之类。"""
    return "—" if v is None else f"{v:.{nd}f}{unit}"


def color_of(ms) -> int:
    """延迟 -> 颜色: <20ms 绿, <60ms 黄, 其余红, None 灰。"""
    if ms is None:
        return int(C_MUTE)
    return int(C_OK) if ms < 20 else int(C_WARN) if ms < 60 else int(C_BAD)


def rule(t: Term) -> None:
    print("  " + t.paint("─" * (t.width - 4), t.fg(int(C_DIM))))


# ══════════════════════════════════════════════════════════════════ DNS 协议


def build_opt(payload: int = 1232, do: bool = False, ecs: tuple[str, int] | None = None,
              nsid: bool = False) -> bytes:
    """构造 EDNS OPT 伪资源记录。可选 DO 位(DNSSEC)、ECS(客户端子网)、NSID(实例标识)。

    NSID(option 3) 发空 payload, 应答方在 OPT 里回填自身实例名 ——
    通常是最接近的 anycast PoP 标识(惯例为 IATA 机场码), 一查即知调度落点。
    """
    rdata = b""
    if ecs:
        ip, prefix = ecs
        raw = socket.inet_aton(ip)
        nbytes = (prefix + 7) // 8
        data = struct.pack(">HBB", 1, prefix, 0) + raw[:nbytes]
        rdata += struct.pack(">HH", 8, len(data)) + data
    if nsid:
        rdata += struct.pack(">HH", 3, 0)
    ttl = 0x8000 if do else 0            # DO 位 = TTL 扩展区最高位
    return b"\x00" + struct.pack(">HHIH", 41, payload, ttl, len(rdata)) + rdata


def build_query(domain: str, qtype: int = 1, do: bool = False,
                ecs: tuple[str, int] | None = None, qclass: int = 1,
                nsid: bool = False) -> tuple[int, bytes]:
    """构造 DNS 查询报文, 返回 (事务ID, 报文字节)。

    qtype/qclass 可指定(如 CHAOS 类 TXT 查 id.server); do/ecs/nsid
    非默认时自动附带 EDNS。
    """
    tid = random.randint(0, 0xFFFF)
    arcount = 1 if (do or ecs or nsid) else 0
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, arcount)
    q = b""
    for label in domain.split("."):
        if label:
            enc = label.encode("idna")
            q += bytes([len(enc)]) + enc
    q += b"\x00" + struct.pack(">HH", qtype, qclass)
    pkt = header + q
    if arcount:
        pkt += build_opt(do=do, ecs=ecs, nsid=nsid)
    return tid, pkt


def _skip_name(data: bytes, pos: int) -> int:
    """跳过报文中的域名(处理压缩指针), 返回下一位置。"""
    while pos < len(data) and data[pos] != 0:
        if data[pos] & 0xC0 == 0xC0:
            return pos + 2
        pos += data[pos] + 1
    return pos + 1


def parse(data: bytes, tid: int) -> dict | None:
    """完整解析 DNS 应答, 事务ID 不匹配返回 None; 报文残缺返回空壳 dict。

    返回字段: rcode / ad / tc / ips(A 记录) / txt(TXT) / ttls / opt(EDNS, 含 ecs) / ancount
    """
    if len(data) < 12:
        return None
    rtid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    if rtid != tid:
        return None
    pos = 12
    try:
        for _ in range(qd):
            pos = _skip_name(data, pos) + 4
        ips: list[str] = []
        txt: list[str] = []
        ttls: list[int] = []
        for _ in range(an):
            pos = _skip_name(data, pos)
            rtype, _rc, ttl, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
            pos += 10
            rdata = data[pos:pos + rdlen]
            pos += rdlen
            if rtype == 1 and rdlen == 4:
                ips.append(".".join(str(b) for b in rdata))
                ttls.append(ttl)
            elif rtype == 16:
                i = 0
                while i < len(rdata):
                    ln = rdata[i]
                    txt.append(rdata[i + 1:i + 1 + ln].decode("utf-8", "ignore"))
                    i += 1 + ln
                ttls.append(ttl)
        opt = None
        for _ in range(ar):
            if pos >= len(data):
                break
            if data[pos] == 0:
                pos += 1
            else:
                pos = _skip_name(data, pos)
            rtype, ups, ttl, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
            pos += 10
            rdata = data[pos:pos + rdlen]
            pos += rdlen
            if rtype == 41:
                opt = {"payload": ups, "ecs": None, "nsid": None}
                i = 0
                while i + 4 <= len(rdata):
                    ocode, olen = struct.unpack(">HH", rdata[i:i + 4])
                    if ocode == 8:
                        opt["ecs"] = rdata[i + 4:i + 4 + olen]
                    elif ocode == 3:
                        opt["nsid"] = rdata[i + 4:i + 4 + olen]
                    i += 4 + olen
        return {"rcode": flags & 0xF, "ad": bool(flags & 0x20), "tc": bool(flags & 0x200),
                "ips": ips, "txt": txt, "ttls": ttls, "opt": opt,
                "ancount": an}
    except (IndexError, struct.error):
        return {"rcode": None, "ad": False, "tc": False, "ips": [], "txt": [],
                "ttls": [], "opt": None, "ancount": 0}


def query(server: str, domain: str, qtype: int = 1, timeout: float = 2.0,
          do: bool = False, ecs: tuple[str, int] | None = None,
          qclass: int = 1, nsid: bool = False) -> tuple[float | None, dict | None]:
    """发起一次 UDP 查询, 返回 (RTT 毫秒, parse 结果)。超时/异常/事务ID 不符返回 (None, None)。"""
    tid, pkt = build_query(domain, qtype, do, ecs, qclass, nsid)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        t0 = time.perf_counter()
        sock.sendto(pkt, (server, DNS_PORT))
        data, _ = sock.recvfrom(4096)
        rtt = (time.perf_counter() - t0) * 1000
        p = parse(data, tid)
        return (rtt, p) if p else (None, None)
    except (socket.timeout, socket.gaierror, OSError, struct.error):
        return None, None
    finally:
        sock.close()


def query_dot(server: str, domain: str, qtype: int = 1, timeout: float = 3.0,
              verify: bool = False) -> tuple[float | None, dict | None]:
    """DNS-over-TLS 查询(TCP 853 + TLS), 返回 (RTT 毫秒, parse 结果)。

    verify=False 时不校验证书(探测支持性与延迟); 严格校验需证书含 IP SAN,
    公共解析器普遍只有域名证书, 因此默认关闭。
    """
    tid, pkt = build_query(domain, qtype)
    try:
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((server, 853), timeout=timeout) as raw:
            with ctx.wrap_socket(raw) as tls:
                t0 = time.perf_counter()
                tls.sendall(struct.pack(">H", len(pkt)) + pkt)
                hdr = b""
                while len(hdr) < 2:
                    chunk = tls.recv(2 - len(hdr))
                    if not chunk:
                        return None, None
                    hdr += chunk
                (mlen,) = struct.unpack(">H", hdr)
                data = b""
                while len(data) < mlen:
                    chunk = tls.recv(mlen - len(data))
                    if not chunk:
                        return None, None
                    data += chunk
                rtt = (time.perf_counter() - t0) * 1000
                p = parse(data, tid)
                return (rtt, p) if p else (None, None)
    except (OSError, ssl.SSLError, socket.timeout, struct.error):
        return None, None


def pop_site(server: str, timeout: float = 2.0) -> str | None:
    """识别 anycast 调度落点(RIPE Atlas 技巧)。

    优先发 NSID(EDNS option 3) 随真实查询, 服务器在 OPT 回填实例标识;
    不支持 NSID 的退回 id.server CHAOS TXT(RFC 4892)。
    返回实例名(常为机场码如 "hkg"/"SJC")或 None。单次抖动会重试一次。
    """
    for domain in ("www.apple.com", "www.wikipedia.org"):   # 两次机会, 换域名避开缓存污染
        _, p = query(server, domain, timeout=timeout, nsid=True)
        if p and p.get("opt") and p["opt"].get("nsid"):
            name = p["opt"]["nsid"].decode("ascii", "ignore").strip()
            if name:
                return name
    _, p = query(server, "id.server", qtype=16, qclass=3, timeout=timeout)
    if p and p.get("txt"):
        return p["txt"][0]
    return None


def rand_sub(parent: str) -> str:
    """生成 parent 的随机子域, 必然未被任何缓存收录(冷查询的基石)。"""
    r = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=14))
    return f"{r}.{parent}"


def is_private(ip: str) -> bool:
    """判断是否为不应出现在公网解析结果里的私有/保留地址。"""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    return (a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)
            or a == 127 or a == 0 or (a == 100 and 64 <= b <= 127)
            or (a == 169 and b == 254))


# ══════════════════════════════════════════════════════════════════ 探测辅助


# 劫持确证探针: 已知存在、无泛解析、极少被针对性劫持的真实域名
HIJACK_PROBE_DOMAIN = "www.wikipedia.org"


def detect_hijack(server: str, timeout: float, suffix: str = NX_SUFFIX,
                  probe_domain: str = HIJACK_PROBE_DOMAIN) -> tuple[bool, str | None]:
    """两阶段劫持检测(nxscanner 方法论, 降低假阳性):

    阶段一 NXDOMAIN 插页: 随机 .invalid 域名(保留 TLD, 不可能被正常解析出
    答案)返回 NOERROR 且带 A 记录 → 存在劫持/广告插页。
    阶段二 三查询确证: 对真实域名查 apex / www / random.www, 若三者返回
    同一 IP(劫持者不校验子域是否存在) → 全域重定向, 属更严重等级。
    返回 (是否劫持, 说明); 说明为 None 表示干净。
    """
    rand = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=12))
    _rtt, p = query(server, f"{rand}.{suffix}", timeout=timeout)
    suspicious = bool(p and p["rcode"] == 0 and p["ancount"] > 0)
    if not suspicious:
        return False, None

    apex = probe_domain.removeprefix("www.")
    names = [apex, f"www.{apex}", f"{rand}.{apex}"]
    answers: list[tuple[str, ...] | None] = []
    for n in names:
        _r, pp = query(server, n, timeout=timeout)
        answers.append(tuple(pp["ips"][:1]) if pp and pp.get("ips") else None)
    if answers[0] and answers[0] == answers[1] == answers[2]:
        return True, "全域重定向: 真实域名与其随机子域返回同一 IP(封锁页/劫持)"
    return True, "NXDOMAIN 插页: 不存在的域名被解析出答案(广告/劫持)"


def ping_host(host: str, count: int = 3, timeout: float = 2.0) -> dict | None:
    """调用系统 ping, 返回 {'avg': ms 或 None, 'loss': 百分比 或 None}; 失败返回 None。"""
    system = platform.system().lower()
    if system == "darwin":
        cmd = ["ping", "-c", str(count), "-t", str(max(1, int(timeout))), host]
    elif system == "linux":
        cmd = ["ping", "-c", str(count), "-W", str(max(1, int(timeout))), host]
    else:  # windows
        cmd = ["ping", "-n", str(count), "-w", str(int(timeout * 1000)), host]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=timeout * count + 6).stdout
    except (subprocess.SubprocessError, OSError, UnicodeDecodeError):
        return None
    loss = None
    m = re.search(r"([\d.]+)\s*%?\s*packet loss", out)
    if m:
        loss = float(m.group(1))
    # macOS: round-trip min/avg/max/stddev = ... ; Linux: rtt min/avg/max/mdev = ...
    m = re.search(r"(?:round-trip|rtt)[^=]*=\s*([\d.]+)/([\d.]+)/([\d.]+)", out)
    if m:
        return {"avg": float(m.group(2)), "loss": loss if loss is not None else 0.0}
    return {"avg": None, "loss": loss}


def system_dns(limit: int = 4) -> list[str]:
    """读取本机当前生效的 DNS(macOS 用 scutil --dns, 其余读 /etc/resolv.conf)。"""
    found: list[str] = []
    pattern = re.compile(r"nameserver.*?(\d{1,3}(?:\.\d{1,3}){3})")
    try:
        if platform.system().lower() == "darwin":
            out = subprocess.run(["scutil", "--dns"], capture_output=True, text=True,
                                 timeout=6).stdout
        else:
            with open("/etc/resolv.conf", encoding="utf-8", errors="ignore") as fh:
                out = fh.read()
        # scutil 格式 "nameserver[0] : 1.2.3.4"; resolv.conf 格式 "nameserver 1.2.3.4"
        for line in out.splitlines():
            m = pattern.search(line)
            if m and m.group(1) not in found:
                found.append(m.group(1))
            if len(found) >= limit:
                break
    except Exception:
        pass
    return found


def has_fake_ip(system_dns_list: list[str]) -> bool:
    """系统 DNS 是否落在 fake-IP 段(198.18.0.0/15)。

    fake-IP 是代理 TUN 模式的标志: 它会接管所有 UDP 53 出站, 此时
    "在线/延迟/劫持/正确性"反映的是代理行为而非目标服务器。
    命中时记入 AGENT_EVENTS, 供 dnstk agent 模式的 envelope 汇总。
    """
    hit = any(ip.startswith(("198.18.", "198.19.")) for ip in system_dns_list)
    if hit:
        _agent_event("fake_ip_proxy")
    return hit


FAKE_IP_WARNING = ("检测到 fake-IP 代理接管 DNS (系统 DNS 在 198.18.x), "
                   "TUN 模式会拦截发往任何地址的 53 端口查询 —— "
                   "本报告的在线状态/延迟/劫持检测可能反映的是代理而非目标服务器, "
                   "建议暂时关闭代理增强/TUN 模式后重测")


# ══════════════════════════════════════════════════════════════════ Agent 集成

RELIABILITY_DEFAULT = 95.0     # GRC v2 口径: 应答率低于此即"不可靠", 不进推荐
ROUTER_CACHE_MS = 2.0          # 低于此延迟的"ISP DNS"多半是本机路由器缓存应答


def is_router_cache(rtt: float | None) -> bool:
    """延迟 <2ms 的 DNS 应答多半来自本机路由器的缓存(GRC 用户实测的经典陷阱),
    不是真实网络性能 —— 混入榜单会误导选型。"""
    return rtt is not None and rtt < ROUTER_CACHE_MS


def load_servers_file(path: str) -> list[tuple[str, str, str]]:
    """从文件加载自定义服务器清单。每行: IP [名称] [分组], # 后为注释。

    支持逗号或空白分隔; 只有 IP 时名称/分组自动补全。空文件抛 ValueError。
    """
    out: list[tuple[str, str, str]] = []
    with open(path, encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            parts = [p for p in line.replace(",", " ").split() if p]
            if len(parts) < 1:
                continue
            ip = parts[0]
            if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", ip):
                raise ValueError(f"{path}:{lineno}: '{ip}' 不是合法 IPv4")
            name = parts[1] if len(parts) > 1 else f"自定义 {ip}"
            group = parts[2] if len(parts) > 2 else "自定义"
            out.append((ip, name, group))
    if not out:
        raise ValueError(f"{path}: 未找到任何服务器条目")
    return out


def histogram(values: list[float], bins: int = 8) -> list[tuple[float, float, int]]:
    """线性桶直方图, 返回 [(下限, 上限, 计数)]。空样本返回空表。"""
    if not values:
        return []
    lo, hi = min(values), max(values)
    if hi - lo < 1e-9:
        return [(lo, hi, len(values))]
    width = (hi - lo) / bins
    counts = [0] * bins
    for v in values:
        counts[min(int((v - lo) / width), bins - 1)] += 1
    return [(lo + i * width, lo + (i + 1) * width, counts[i]) for i in range(bins)]


AGENT_EVENTS: list[str] = []        # 环境级事件(fake-IP 等), dnstk envelope 的 warnings 来源


def _agent_event(name: str) -> None:
    if name not in AGENT_EVENTS:
        AGENT_EVENTS.append(name)


def agent_envelope(mode: str, payload: dict, elapsed_s: float) -> dict:
    """把三个工具的 JSON payload 包成统一 envelope, 供 agent 一次读取。

    结构: ok / mode / elapsed_s / warnings / recommend / data。
    warnings = 环境事件(fake-IP) + 数据摘要(劫持服务器 / 并发限流)。
    recommend 按 score 降序给出 primary 与 backup(优先不同分组, 容灾)。
    """
    entries = payload.get("servers") or payload.get("results") or []
    warnings = list(AGENT_EVENTS)
    for e in entries:
        if e.get("hijack"):
            warnings.append(f"nxdomain_hijack:{e['ip']}")
        b = e.get("burst") or {}
        if b.get("loss_percent", 0) > 10:
            warnings.append(f"burst_throttle:{e['ip']}")
        if e.get("alive") is False:
            warnings.append(f"unreachable:{e['ip']}")
        if e.get("router_cache"):
            warnings.append(f"router_cache:{e['ip']}")

    usable = [e for e in entries
              if (e.get("dns_median_ms") or e.get("median_ms")
                  or (e.get("warm") or {}).get("p50")) and not e.get("hijack")]
    usable.sort(key=lambda e: e.get("score") or 0, reverse=True)
    primary = usable[0] if usable else None
    # backup 优先选不同分组(容灾); 全场同组时退化为次优, 比 null 有用
    backup = None
    if primary and len(usable) > 1:
        backup = next((e for e in usable[1:] if e.get("group") != primary.get("group")),
                      usable[1])

    def brief(e: dict) -> dict:
        out = {"ip": e["ip"], "name": e["name"], "group": e.get("group"),
               "score": e.get("score")}
        if "hk_ms" in e:
            out["hk_ms"], out["intl_ms"], out["cn_ms"] = e["hk_ms"], e["intl_ms"], e["cn_ms"]
        if "dns_median_ms" in e:
            out["median_ms"], out["p95_ms"] = e["dns_median_ms"], e["dns_p95_ms"]
        if "warm" in e:
            out["warm_p50_ms"] = e["warm"]["p50"]
            out["warm_p99_ms"] = e["warm"]["p99"]
        return out

    recommend = {"primary": brief(primary) if primary else None,
                 "backup": brief(backup) if backup else None}
    return {"ok": True, "mode": mode, "elapsed_s": round(elapsed_s, 1),
            "warnings": warnings, "recommend": recommend, "data": payload}


def reset_agent_events() -> None:
    AGENT_EVENTS.clear()
