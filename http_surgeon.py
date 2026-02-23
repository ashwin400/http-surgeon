#!/usr/bin/env python3
"""
http-surgeon — Intelligent HTTP access log analyzer
Zero dependencies. Parses Apache/Nginx/JSON logs. Finds slowest endpoints,
error spikes, traffic patterns, and security anomalies.
"""

import utils.transport
import utils.session
import sys
import re
import json
import math
import gzip
import argparse
import statistics
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import Optional

# ─────────────────────────────────────────────
# ANSI Colors
# ─────────────────────────────────────────────

def _supports_color():
    return sys.stdout.isatty()

COLOR = _supports_color()

def c(text, code):
    if not COLOR: return text
    return f"\033[{code}m{text}\033[0m"

def red(t):   return c(t, "31")
def green(t): return c(t, "32")
def yellow(t): return c(t, "33")
def blue(t):  return c(t, "34")
def cyan(t):  return c(t, "36")
def bold(t):  return c(t, "1")
def dim(t):   return c(t, "2")

# ─────────────────────────────────────────────
# Log Formats
# ─────────────────────────────────────────────

# Apache Common: 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
APACHE_COMMON = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\S+)'
)

# Apache Combined: same + " "referer" "agent"
APACHE_COMBINED = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\S+)\s+'
    r'"(?P<referer>[^"]*)"\s+'
    r'"(?P<agent>[^"]*)"'
)

# Nginx with $request_time appended (common custom format)
NGINX_WITH_TIME = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\S+)\s+'
    r'"(?P<referer>[^"]*)"\s+'
    r'"(?P<agent>[^"]*)"\s+'
    r'(?P<req_time>[\d.]+)'
)

# Time formats
TIME_FORMATS = [
    "%d/%b/%Y:%H:%M:%S %z",   # Apache
    "%d/%b/%Y:%H:%M:%S",       # Apache without tz
    "%Y-%m-%dT%H:%M:%S%z",    # ISO 8601
    "%Y-%m-%d %H:%M:%S",       # Common JSON log
]

def parse_time(s: str) -> Optional[datetime]:
    for fmt in TIME_FORMATS:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            pass
    return None

# ─────────────────────────────────────────────
# Log Entry
# ─────────────────────────────────────────────

class LogEntry:
    __slots__ = ['ip', 'time', 'method', 'path', 'proto', 'status',
                 'size', 'referer', 'agent', 'req_time']

    def __init__(self, **kw):
        self.ip = kw.get('ip', '-')
        self.time: Optional[datetime] = kw.get('time')
        self.method = kw.get('method', '-')
        self.path = kw.get('path', '/')
        self.proto = kw.get('proto', 'HTTP/1.1')
        self.status: int = int(kw.get('status', 0))
        raw_size = kw.get('size', '0')
        self.size: int = int(raw_size) if raw_size not in ('-', '') else 0
        self.referer = kw.get('referer', '')
        self.agent = kw.get('agent', '')
        raw_rt = kw.get('req_time')
        self.req_time: Optional[float] = float(raw_rt) if raw_rt else None

    @property
    def endpoint(self) -> str:
        """Strip query string and numeric path segments for grouping."""
        p = self.path.split('?')[0]
        parts = p.split('/')
        normalized = []
        for part in parts:
            if re.match(r'^\d+$', part):
                normalized.append(':id')
            elif re.match(r'^[0-9a-f\-]{36}$', part, re.I):  # UUID
                normalized.append(':uuid')
            else:
                normalized.append(part)
        return '/'.join(normalized) or '/'

    @property
    def status_class(self) -> str:
        if self.status < 300: return '2xx'
        if self.status < 400: return '3xx'
        if self.status < 500: return '4xx'
        return '5xx'

# ─────────────────────────────────────────────
# Parser
# ─────────────────────────────────────────────

def parse_line(line: str) -> Optional[LogEntry]:
    line = line.strip()
    if not line:
        return None

    # Try JSON first
    if line.startswith('{'):
        try:
            d = json.loads(line)
            t = (d.get('time') or d.get('timestamp') or d.get('@timestamp') or
                 d.get('time_local') or '')
            if isinstance(t, (int, float)):
                dt = datetime.fromtimestamp(t)
            else:
                dt = parse_time(str(t)) if t else None

            req = d.get('request', '')
            parts = req.split() if req else []
            method = parts[0] if parts else d.get('method', '-')
            path = parts[1] if len(parts) > 1 else d.get('path', d.get('uri', '/'))
            proto = parts[2] if len(parts) > 2 else 'HTTP/1.1'

            rt = d.get('request_time') or d.get('duration') or d.get('response_time')

            return LogEntry(
                ip=str(d.get('remote_addr') or d.get('ip') or d.get('client_ip') or '-'),
                time=dt,
                method=method,
                path=path,
                proto=proto,
                status=int(d.get('status', d.get('response_code', 0))),
                size=int(d.get('body_bytes_sent') or d.get('bytes_sent') or
                         d.get('size') or d.get('response_size') or 0),
                referer=str(d.get('http_referer') or d.get('referer') or ''),
                agent=str(d.get('http_user_agent') or d.get('user_agent') or d.get('agent') or ''),
                req_time=float(rt) if rt else None,
            )
        except (json.JSONDecodeError, ValueError, TypeError):
            pass

    # Try with request time (Nginx extended)
    m = NGINX_WITH_TIME.match(line)
    if m:
        g = m.groupdict()
        return LogEntry(
            ip=g['ip'],
            time=parse_time(g['time']),
            method=g['method'],
            path=g['path'],
            proto=g['proto'],
            status=g['status'],
            size=g['size'],
            referer=g.get('referer', ''),
            agent=g.get('agent', ''),
            req_time=g.get('req_time'),
        )

    # Try Apache Combined
    m = APACHE_COMBINED.match(line)
    if m:
        g = m.groupdict()
        return LogEntry(
            ip=g['ip'],
            time=parse_time(g['time']),
            method=g['method'],
            path=g['path'],
            proto=g['proto'],
            status=g['status'],
            size=g['size'],
            referer=g.get('referer', ''),
            agent=g.get('agent', ''),
        )

    # Try Apache Common
    m = APACHE_COMMON.match(line)
    if m:
        g = m.groupdict()
        return LogEntry(
            ip=g['ip'],
            time=parse_time(g['time']),
            method=g['method'],
            path=g['path'],
            proto=g['proto'],
            status=g['status'],
            size=g['size'],
        )

    return None


def load_log(path: str) -> list:
    """Load log file (gzip or plain), return list of LogEntry."""
    entries = []
    errors = 0
    fpath = Path(path)

    try:
        opener = gzip.open if fpath.suffix == '.gz' else open
        mode = 'rt' if fpath.suffix == '.gz' else 'r'
        with opener(fpath, mode, errors='replace') as f:
            for line in f:
                e = parse_line(line)
                if e:
                    entries.append(e)
                else:
                    errors += 1
    except FileNotFoundError:
        print(red(f"File not found: {path}"), file=sys.stderr)
        sys.exit(1)
    except Exception as ex:
        print(red(f"Error reading {path}: {ex}"), file=sys.stderr)
        sys.exit(1)

    return entries


# ─────────────────────────────────────────────
# Statistics Helpers
# ─────────────────────────────────────────────

def percentile(data: list, p: float) -> float:
    if not data: return 0.0
    s = sorted(data)
    idx = (len(s) - 1) * p / 100
    lo, hi = int(idx), min(int(idx) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (idx - lo)

def fmt_ms(seconds: float) -> str:
    ms = seconds * 1000
    if ms >= 1000:
        return f"{ms/1000:.2f}s"
    return f"{ms:.0f}ms"

def fmt_bytes(b: int) -> str:
    for unit in ['B','KB','MB','GB','TB']:
        if b < 1024:
            return f"{b:.1f}{unit}"
        b /= 1024
    return f"{b:.1f}PB"

def bar(value, max_val, width=20, filled='█', empty='░') -> str:
    if max_val == 0: return empty * width
    n = int((value / max_val) * width)
    return filled * n + empty * (width - n)

def status_color(status: int) -> str:
    if status < 300: return green(str(status))
    if status < 400: return cyan(str(status))
    if status < 500: return yellow(str(status))
    return red(str(status))

# ─────────────────────────────────────────────
# Analysis Functions
# ─────────────────────────────────────────────

def cmd_analyze(entries: list, args):
    """Full overview analysis."""
    if not entries:
        print(yellow("No log entries found."))
        return

    total = len(entries)
    timed = [e for e in entries if e.req_time is not None]
    errored = [e for e in entries if e.status >= 400]

    # Time range
    times = [e.time for e in entries if e.time]
    t_start = min(times) if times else None
    t_end = max(times) if times else None
    duration_secs = (t_end - t_start).total_seconds() if t_start and t_end else 0

    # Status distribution
    status_counts = Counter(e.status for e in entries)
    class_counts = Counter(e.status_class for e in entries)

    # Top endpoints
    endpoint_counts = Counter(e.endpoint for e in entries)

    # Request times
    req_times = [e.req_time for e in timed]

    # Unique IPs
    unique_ips = len(set(e.ip for e in entries))

    total_f = total or 1
    err_rate = len(errored) / total_f * 100
    ip_counts = Counter(e.ip for e in entries)

    print()
    print(bold("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
    print(bold("  🔪 HTTP Surgeon — Log Analysis"))
    print(bold("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
    print()
    print(bold("📊 Overview"))
    print(f"  Total Requests: {bold(str(total))}")
    if t_start:
        print(f"  Time Range:     {dim(t_start.strftime('%Y-%m-%d %H:%M'))} → {dim(t_end.strftime('%Y-%m-%d %H:%M'))}")
    if duration_secs > 0:
        rps = total / duration_secs
        print(f"  Duration:       {_fmt_duration(duration_secs)}  ({rps:.1f} req/s avg)")
    print(f"  Unique IPs:     {unique_ips}")
    if req_times:
        print(f"  Response Times: p50={bold(fmt_ms(percentile(req_times,50)))}  p95={yellow(fmt_ms(percentile(req_times,95)))}  p99={red(fmt_ms(percentile(req_times,99)))}")
    print()
    print(bold("🚦 Status Codes"))
    for cls in ['2xx', '3xx', '4xx', '5xx']:
        count = class_counts.get(cls, 0)
        pct = count / total_f * 100
        color_fn = green if cls == '2xx' else cyan if cls == '3xx' else yellow if cls == '4xx' else red
        b = bar(count, total, width=20)
        print(f"  {color_fn(cls)}  {b}  {count:>6}  ({pct:5.1f}%)")
    print()
    if err_rate > 10:
        err_label = red(f"{err_rate:.1f}%")
    elif err_rate > 1:
        err_label = yellow(f"{err_rate:.1f}%")
    else:
        err_label = green(f"{err_rate:.1f}%")
    print(f"  Error Rate (4xx+5xx): {err_label}  ({len(errored)} errors)")
    print()
    print(bold("🔝 Top 10 Endpoints"))
    for ep, cnt in endpoint_counts.most_common(10):
        pct = cnt / total_f * 100
        b = bar(cnt, endpoint_counts.most_common(1)[0][1], width=15)
        print(f"  {b}  {cnt:>6}  {dim(f'{pct:5.1f}%')}  {ep}")
    print()
    print(bold("🌐 Top 5 IPs"))
    for ip, cnt in ip_counts.most_common(5):
        pct = cnt / total_f * 100
        print(f"  {ip:<20}  {cnt:>6}  ({pct:.1f}%)")
    print()

    if args.json:
        result = {
            "total": total,
            "unique_ips": unique_ips,
            "error_rate_pct": round(err_rate, 2),
            "status_classes": dict(class_counts),
            "status_codes": dict(status_counts.most_common(20)),
            "top_endpoints": dict(endpoint_counts.most_common(20)),
            "response_times": {
                "p50_ms": round(percentile(req_times, 50) * 1000, 1) if req_times else None,
                "p95_ms": round(percentile(req_times, 95) * 1000, 1) if req_times else None,
                "p99_ms": round(percentile(req_times, 99) * 1000, 1) if req_times else None,
                "avg_ms": round(statistics.mean(req_times) * 1000, 1) if req_times else None,
            }
        }
        _json_print(result)


def cmd_slow(entries: list, args):
    """Find slowest endpoints by p95 response time."""
    timed = [e for e in entries if e.req_time is not None]
    if not timed:
        print(yellow("No request timing data found in logs."))
        print(dim("  Tip: Add '$request_time' to your Nginx log format, or use JSON logs."))
        return

    # Group by endpoint
    endpoint_times: dict = defaultdict(list)
    for e in timed:
        endpoint_times[f"{e.method} {e.endpoint}"].append(e.req_time)

    top_n = getattr(args, 'top', 20)

    # Build stats per endpoint
    stats = []
    for ep, times in endpoint_times.items():
        stats.append({
            'endpoint': ep,
            'count': len(times),
            'p50': percentile(times, 50),
            'p95': percentile(times, 95),
            'p99': percentile(times, 99),
            'avg': statistics.mean(times),
            'max': max(times),
        })

    stats.sort(key=lambda x: x['p95'], reverse=True)
    stats = stats[:top_n]

    print()
    print(bold("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
    print(bold(f"  🐢 Slowest Endpoints by p95 (top {top_n})"))
    print(bold("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
    print()

    threshold_warn = 0.5   # 500ms
    threshold_crit = 2.0   # 2s

    hdr = f"  {'Endpoint':<45}  {'Count':>6}  {'p50':>8}  {'p95':>8}  {'p99':>8}  {'max':>8}"
    print(bold(hdr))
    print(dim("  " + "─" * 90))

    for s in stats:
        ep = s['endpoint'][:44]
        p95 = s['p95']
        if p95 >= threshold_crit:
            p95_str = red(fmt_ms(p95))
        elif p95 >= threshold_warn:
            p95_str = yellow(fmt_ms(p95))
        else:
            p95_str = green(fmt_ms(p95))

        print(f"  {ep:<45}  {s['count']:>6}  {fmt_ms(s['p50']):>8}  {p95_str:>8}  "
              f"{fmt_ms(s['p99']):>8}  {fmt_ms(s['max']):>8}")

    print()
    slow_count = sum(1 for s in stats if s['p95'] >= threshold_warn)
    if slow_count > 0:
        print(f"  {yellow(f'{slow_count} endpoints')} exceed 500ms p95 threshold.")
    else:
        print(f"  {green('All endpoints')} are within 500ms p95.")
    print()

    if args.json:
        _json_print([{
            'endpoint': s['endpoint'],
            'count': s['count'],
            'p50_ms': round(s['p50'] * 1000, 1),
            'p95_ms': round(s['p95'] * 1000, 1),
            'p99_ms': round(s['p99'] * 1000, 1),
            'avg_ms': round(s['avg'] * 1000, 1),
            'max_ms': round(s['max'] * 1000, 1),
        } for s in stats])


def cmd_errors(entries: list, args):
    """Detailed error analysis."""
    errors = [e for e in entries if e.status >= 400]
    total = len(entries)

    if not errors:
        print(green("✅ No errors found in log."))
        return

    print()
    print(bold("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
    print(bold("  💥 Error Analysis"))
    print(bold("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
    print()

    err_rate = len(errors) / (total or 1) * 100

    # Error by status
    by_status = Counter(e.status for e in errors)
    print(bold(f"Error Rate: {_err_color(err_rate, f'{err_rate:.2f}%')} ({len(errors)}/{total})"))
    print()
    print(bold("By Status Code:"))
    for status, count in sorted(by_status.items()):
        pct = count / len(errors) * 100
        b = bar(count, by_status.most_common(1)[0][1], width=15)
        print(f"  {status_color(status)}  {b}  {count:>5}  ({pct:.1f}%)")
    print()

    # Error by endpoint
    by_endpoint = Counter(f"{e.method} {e.endpoint}" for e in errors)
    print(bold("Top Error Endpoints:"))
    for ep, count in by_endpoint.most_common(10):
        # What % of this endpoint's total requests are errors?
        endpoint_total = sum(1 for e2 in entries if f"{e2.method} {e2.endpoint}" == ep)
        ep_err_rate = count / (endpoint_total or 1) * 100
        print(f"  {count:>5}  {_err_color(ep_err_rate, f'{ep_err_rate:5.1f}%')}  {ep}")
    print()

    # Error by IP (top offenders)
    by_ip = Counter(e.ip for e in errors)
    if by_ip:
        print(bold("Top Error IPs:"))
        for ip, count in by_ip.most_common(5):
            print(f"  {ip:<20}  {count:>5} errors")
        print()

    # 5xx errors specifically
    server_errors = [e for e in errors if e.status >= 500]
    if server_errors:
        print(bold(f"🚨 Server Errors (5xx): {red(str(len(server_errors)))}"))
        by_5xx_ep = Counter(f"{e.method} {e.path[:60]}" for e in server_errors)
        for ep, count in by_5xx_ep.most_common(5):
            print(f"  {red(str(count)):>5}  {ep}")
        print()

    if args.json:
        _json_print({
            "total_errors": len(errors),
            "error_rate_pct": round(err_rate, 2),
            "by_status": dict(sorted(by_status.items())),
            "top_endpoints": [{"endpoint": ep, "count": cnt} for ep, cnt in by_endpoint.most_common(20)],
            "top_ips": [{"ip": ip, "count": cnt} for ip, cnt in by_ip.most_common(10)],
        })


def cmd_traffic(entries: list, args):
    """Traffic patterns over time."""
    timed_entries = [e for e in entries if e.time]
    if not timed_entries:
        print(yellow("No timestamp data found."))
        return

    t_start = min(e.time for e in timed_entries)
    t_end = max(e.time for e in timed_entries)
    duration = (t_end - t_start).total_seconds()

    print()
    print(bold("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
    print(bold("  📈 Traffic Patterns"))
    print(bold("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
    print()

    # Choose bucket size based on duration
    if duration <= 3600 * 2:           # ≤2 hours: by minute
        bucket_fmt = "%H:%M"
        bucket_fn = lambda t: t.strftime("%H:%M")
        label = "by minute"
        max_buckets = 120
    elif duration <= 86400:             # ≤1 day: by hour
        bucket_fmt = "%m-%d %H:00"
        bucket_fn = lambda t: t.strftime("%m-%d %H:00")
        label = "by hour"
        max_buckets = 48
    else:                               # >1 day: by day
        bucket_fmt = "%Y-%m-%d"
        bucket_fn = lambda t: t.strftime("%Y-%m-%d")
        label = "by day"
        max_buckets = 90

    buckets: dict = defaultdict(lambda: {'total': 0, 'errors': 0})
    for e in timed_entries:
        k = bucket_fn(e.time)
        buckets[k]['total'] += 1
        if e.status >= 400:
            buckets[k]['errors'] += 1

    sorted_keys = sorted(buckets.keys())[-max_buckets:]
    max_total = max(buckets[k]['total'] for k in sorted_keys) if sorted_keys else 1

    print(bold(f"  Traffic ({label})"))
    print()

    for k in sorted_keys:
        total_b = buckets[k]['total']
        err_b = buckets[k]['errors']
        b_total = bar(total_b, max_total, width=30)
        err_rate = err_b / total_b * 100 if total_b else 0
        err_indicator = red(f" ⚠ {err_rate:.0f}% err") if err_rate > 5 else ""
        print(f"  {dim(k)}  {blue(b_total)}  {total_b:>5}{err_indicator}")

    print()

    # Peak traffic
    if sorted_keys:
        peak_key = max(sorted_keys, key=lambda k: buckets[k]['total'])
        print(f"  Peak: {bold(peak_key)}  ({buckets[peak_key]['total']} requests)")

    # Traffic spike detection
    totals = [buckets[k]['total'] for k in sorted_keys]
    if len(totals) >= 3:
        mean_t = statistics.mean(totals)
        stdev_t = statistics.stdev(totals) if len(totals) > 1 else 0
        spikes = [(sorted_keys[i], totals[i]) for i in range(len(totals))
                  if stdev_t > 0 and totals[i] > mean_t + 2 * stdev_t]
        if spikes:
            print()
            print(yellow("⚡ Traffic Spikes (>2σ above mean):"))
            for k, v in spikes:
                print(f"  {k}  {v} req  (mean: {mean_t:.0f})")

    # Hourly pattern if we have enough data
    if duration >= 86400:
        print()
        print(bold("  By Hour of Day (all time)"))
        hourly: dict = defaultdict(int)
        for e in timed_entries:
            hourly[e.time.hour] += 1
        max_h = max(hourly.values()) if hourly else 1
        for h in range(24):
            v = hourly.get(h, 0)
            b = bar(v, max_h, width=20)
            print(f"  {h:02d}:00  {blue(b)}  {v:>5}")

    print()


def cmd_security(entries: list, args):
    """Security anomaly detection."""
    print()
    print(bold("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
    print(bold("  🔐 Security Analysis"))
    print(bold("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
    print()

    total = len(entries)
    findings = []

    # 1. Brute force detection (many 401/403 from same IP)
    auth_errors_by_ip: dict = defaultdict(int)
    for e in entries:
        if e.status in (401, 403):
            auth_errors_by_ip[e.ip] += 1

    for ip, count in auth_errors_by_ip.items():
        if count >= 10:
            severity = 'CRITICAL' if count >= 50 else 'HIGH' if count >= 20 else 'MEDIUM'
            findings.append({
                'type': 'Brute Force / Auth Scanning',
                'severity': severity,
                'detail': f"{ip} — {count} 401/403 responses",
                'ip': ip
            })

    # 2. Path traversal / injection attempts
    TRAVERSAL = re.compile(r'\.\./|%2e%2e|%252e|/etc/passwd|/etc/shadow', re.I)
    INJECTION = re.compile(r"select\s+.*\s+from|union\s+select|<script|javascript:|"
                           r"eval\(|exec\(|cmd=|shell=|phpinfo\(\)", re.I)

    attack_ips: dict = defaultdict(int)
    for e in entries:
        if TRAVERSAL.search(e.path) or INJECTION.search(e.path):
            attack_ips[e.ip] += 1

    for ip, count in attack_ips.items():
        findings.append({
            'type': 'Path Traversal / Injection',
            'severity': 'HIGH',
            'detail': f"{ip} — {count} suspicious requests",
            'ip': ip
        })

    # 3. Scanner/bot detection (many 404s from same IP)
    by_ip_404: dict = defaultdict(int)
    for e in entries:
        if e.status == 404:
            by_ip_404[e.ip] += 1

    for ip, count in by_ip_404.items():
        if count >= 20:
            findings.append({
                'type': 'Automated Scanning (404 sweep)',
                'severity': 'MEDIUM',
                'detail': f"{ip} — {count} 404 responses",
                'ip': ip
            })

    # 4. High request rate from single IP
    by_ip_total = Counter(e.ip for e in entries)
    timed_e = [e for e in entries if e.time]
    if timed_e:
        t_start = min(e.time for e in timed_e)
        t_end = max(e.time for e in timed_e)
        duration = max((t_end - t_start).total_seconds(), 1)
        for ip, count in by_ip_total.items():
            rps = count / duration
            if rps > 10:  # >10 req/s from single IP
                findings.append({
                    'type': 'High Request Rate (potential DDoS)',
                    'severity': 'HIGH' if rps > 50 else 'MEDIUM',
                    'detail': f"{ip} — {rps:.1f} req/s  ({count} total)",
                    'ip': ip
                })

    # 5. User agent anomalies (missing, obvious scanners)
    SCANNER_UAS = re.compile(
        r'nikto|sqlmap|nmap|masscan|dirbuster|gobuster|wfuzz|'
        r'burpsuite|ZAP|Havij|acunetix|nessus|openvas|nuclei', re.I
    )
    scanner_ips: dict = defaultdict(set)
    for e in entries:
        if e.agent and SCANNER_UAS.search(e.agent):
            scanner_ips[e.ip].add(e.agent)

    for ip, agents in scanner_ips.items():
        findings.append({
            'type': 'Known Security Scanner',
            'severity': 'CRITICAL',
            'detail': f"{ip} — {', '.join(list(agents)[:2])}",
            'ip': ip
        })

    # 6. Sensitive file access
    SENSITIVE = re.compile(
        r'\.(env|git|svn|htpasswd|htaccess|config|bak|sql|tar|zip|gz)$|'
        r'/.git/|/admin|/wp-admin|/phpmyadmin|/\.ssh', re.I
    )
    sensitive_hits: dict = defaultdict(int)
    for e in entries:
        if SENSITIVE.search(e.path):
            sensitive_hits[e.path] += 1

    if sensitive_hits:
        top_sensitive = sorted(sensitive_hits.items(), key=lambda x: x[1], reverse=True)[:5]
        for path, count in top_sensitive:
            findings.append({
                'type': 'Sensitive File/Path Access',
                'severity': 'HIGH',
                'detail': f"{path} — {count} requests",
                'ip': 'various'
            })

    # Display findings
    if not findings:
        print(green("✅ No security anomalies detected."))
    else:
        # Sort by severity
        sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        findings.sort(key=lambda x: sev_order.get(x['severity'], 99))

        print(f"  {bold(str(len(findings)))} finding(s) detected:\n")
        for f in findings:
            sev = f['severity']
            if sev == 'CRITICAL':
                sev_str = red(f"[{sev}]")
            elif sev == 'HIGH':
                sev_str = yellow(f"[{sev}  ]")
            elif sev == 'MEDIUM':
                sev_str = cyan(f"[{sev}]")
            else:
                sev_str = dim(f"[{sev}  ]")

            print(f"  {sev_str}  {bold(f['type'])}")
            print(f"           {dim(f['detail'])}")
            print()

    # Overall security score
    crit = sum(1 for f in findings if f['severity'] == 'CRITICAL')
    high = sum(1 for f in findings if f['severity'] == 'HIGH')
    med = sum(1 for f in findings if f['severity'] == 'MEDIUM')
    score = max(0, 100 - crit * 30 - high * 15 - med * 5)

    if score >= 80:
        score_str = green(f"{score}/100")
    elif score >= 50:
        score_str = yellow(f"{score}/100")
    else:
        score_str = red(f"{score}/100")

    print(f"  Security Score: {bold(score_str)}")
    print()

    if args.json:
        _json_print({
            "security_score": score,
            "findings": findings
        })


def cmd_compare(entries1: list, entries2: list, args):
    """Compare two log files / time windows."""
    def stats(entries):
        total = len(entries)
        if not total:
            return {}
        timed = [e for e in entries if e.req_time is not None]
        req_times = [e.req_time for e in timed]
        err = [e for e in entries if e.status >= 400]
        return {
            'total': total,
            'error_rate': len(err) / total * 100,
            'p95': percentile(req_times, 95) if req_times else None,
            'p99': percentile(req_times, 99) if req_times else None,
            'rps': None,
        }

    s1 = stats(entries1)
    s2 = stats(entries2)

    print()
    print(bold("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
    print(bold("  📊 Log Comparison"))
    print(bold("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
    print()

    def delta(label, v1, v2, fmt=lambda x: str(x), invert=False):
        """Show a metric with before/after and change indicator."""
        if v1 is None or v2 is None:
            return
        change = v2 - v1
        pct = change / v1 * 100 if v1 != 0 else 0
        if abs(pct) < 1:
            arrow = dim("≈")
            change_str = dim("no change")
        elif (change > 0) != invert:
            arrow = red("▲")
            change_str = red(f"+{pct:.1f}%")
        else:
            arrow = green("▼")
            change_str = green(f"{pct:.1f}%")

        print(f"  {label:<25}  {fmt(v1):>12}  →  {fmt(v2):>12}  {arrow}  {change_str}")

    print(f"  {'Metric':<25}  {'Before':>12}     {'After':>12}")
    print(dim("  " + "─" * 70))
    delta("Total Requests",   s1['total'],      s2['total'],      fmt=str, invert=True)
    delta("Error Rate",       s1['error_rate'], s2['error_rate'], fmt=lambda x: f"{x:.2f}%", invert=False)
    if s1.get('p95') and s2.get('p95'):
        delta("p95 Response Time", s1['p95'], s2['p95'], fmt=fmt_ms, invert=False)
        delta("p99 Response Time", s1['p99'], s2['p99'], fmt=fmt_ms, invert=False)
    print()


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _fmt_duration(secs: float) -> str:
    if secs < 60: return f"{secs:.0f}s"
    if secs < 3600: return f"{secs/60:.1f}m"
    if secs < 86400: return f"{secs/3600:.1f}h"
    return f"{secs/86400:.1f}d"

def _err_color(rate: float, text: str) -> str:
    if rate >= 10: return red(text)
    if rate >= 1: return yellow(text)
    return green(text)


# ─────────────────────────────────────────────
# Generate Sample Log
# ─────────────────────────────────────────────

def generate_sample():
    """Generate a realistic sample access log for demo purposes."""
    import random
    from datetime import timezone

    lines = []
    base = datetime(2026, 2, 19, 8, 0, 0, tzinfo=timezone.utc)

    agents = [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)",
        "python-requests/2.28.0",
        "curl/7.88.1",
        "nikto/2.1.6",  # scanner
    ]
    ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "192.168.1.100",
           "198.51.100.42",  # scanner
           "203.0.113.5"]

    endpoints = [
        ("GET", "/api/users", 200, 0.08),
        ("GET", "/api/users/123", 200, 0.12),
        ("GET", "/api/products", 200, 0.15),
        ("POST", "/api/orders", 201, 0.25),
        ("GET", "/api/reports", 200, 1.8),  # slow!
        ("GET", "/health", 200, 0.01),
        ("GET", "/api/auth/login", 401, 0.05),
        ("DELETE", "/api/users/99", 404, 0.03),
        ("GET", "/.env", 403, 0.01),        # sensitive
        ("GET", "/admin", 403, 0.01),
        ("GET", "/../etc/passwd", 400, 0.01),  # traversal
    ]

    for i in range(800):
        t = base + timedelta(seconds=random.randint(0, 43200))
        ip = random.choices(ips, weights=[30, 20, 20, 15, 5, 10])[0]
        method, path, status, base_rt = random.choices(
            endpoints,
            weights=[20, 15, 15, 10, 5, 10, 8, 5, 3, 4, 5]
        )[0]
        rt = round(base_rt * random.uniform(0.5, 3.0), 3)
        size = random.randint(100, 5000)
        agent = random.choice(agents)
        t_str = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
        lines.append(
            f'{ip} - - [{t_str}] "{method} {path} HTTP/1.1" {status} {size} '
            f'"-" "{agent}" {rt}'
        )

    return '\n'.join(lines)


# ─────────────────────────────────────────────
# Main CLI
# ─────────────────────────────────────────────

# Save real stdout before any possible redirection
_REAL_STDOUT = sys.stdout

def _json_print(data):
    """Print JSON to real stdout regardless of any redirection."""
    print(json.dumps(data, indent=2), file=_REAL_STDOUT)


def main():
    parser = argparse.ArgumentParser(
        description="http-surgeon — Intelligent HTTP access log analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  analyze   Full overview (default)
  slow      Slowest endpoints by p95 response time
  errors    Detailed error breakdown
  traffic   Traffic patterns and spike detection
  security  Security anomaly detection
  compare   Compare two log files

Supported Formats:
  Apache Common, Apache Combined, Nginx (with $request_time), JSON logs
  Supports .gz compressed files

Examples:
  %(prog)s analyze access.log
  %(prog)s slow access.log --top 10
  %(prog)s errors access.log --json
  %(prog)s traffic access.log
  %(prog)s security access.log
  %(prog)s compare before.log after.log
  %(prog)s analyze --demo          # Generate sample log and analyze it
        """
    )

    parser.add_argument('command', nargs='?', default='analyze',
                        choices=['analyze', 'slow', 'errors', 'traffic', 'security', 'compare'],
                        help='Command to run (default: analyze)')
    parser.add_argument('logfile', nargs='?', help='Log file to analyze')
    parser.add_argument('logfile2', nargs='?', help='Second log file (for compare)')
    parser.add_argument('--top', type=int, default=20, help='Show top N results')
    parser.add_argument('--json', action='store_true', help='Output JSON (for CI/automation)')
    parser.add_argument('--demo', action='store_true', help='Use generated sample log')

    args = parser.parse_args()

    # Handle --demo mode
    if args.demo:
        import tempfile, os
        sample = generate_sample()
        tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False)
        tmp.write(sample)
        tmp.close()
        print(dim(f"Using generated sample log ({tmp.name})"), file=sys.stderr)
        args.logfile = tmp.name

    if not args.logfile:
        parser.print_help()
        sys.exit(1)

    # When --json: redirect all display output to stderr, JSON goes to real stdout
    if args.json:
        sys.stdout = sys.stderr

    entries = load_log(args.logfile)
    print(dim(f"  Loaded {len(entries)} entries from {args.logfile}"))

    if args.command == 'analyze':
        cmd_analyze(entries, args)
    elif args.command == 'slow':
        cmd_slow(entries, args)
    elif args.command == 'errors':
        cmd_errors(entries, args)
    elif args.command == 'traffic':
        cmd_traffic(entries, args)
    elif args.command == 'security':
        cmd_security(entries, args)
    elif args.command == 'compare':
        if not args.logfile2:
            print(red("compare requires two log files: http-surgeon compare file1.log file2.log"))
            sys.exit(1)
        entries2 = load_log(args.logfile2)
        cmd_compare(entries, entries2, args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
