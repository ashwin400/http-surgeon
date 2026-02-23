# http-surgeon

HTTP access log analyzer for production debugging. Zero dependencies. Single file.

Answers the questions you actually have when something breaks:

- Which endpoints are slow? (p50, p95, p99 by endpoint)
- Where are the errors coming from?
- When did traffic spike?
- Is someone scanning me?

```bash
python3 http_surgeon.py analyze access.log
```

---

## Install

No install needed. One file, no dependencies.

```bash
curl -O https://raw.githubusercontent.com/ashwin400/http-surgeon/main/http_surgeon.py
python3 http_surgeon.py analyze access.log
```

Or make it global:

```bash
cp http_surgeon.py /usr/local/bin/http-surgeon
chmod +x /usr/local/bin/http-surgeon
http-surgeon analyze access.log
```

## Commands

```bash
# Full analysis
http-surgeon analyze access.log

# Slowest endpoints (p95 response time)
http-surgeon slow access.log

# Error breakdown by endpoint and IP
http-surgeon errors access.log

# Traffic over time with spike detection
http-surgeon traffic access.log

# Security scan (brute force, path traversal, scanners)
http-surgeon security access.log

# Compare two log files (before vs after deploy)
http-surgeon compare before.log after.log
```

## Log Format Support

Auto-detects format. No configuration needed.

- Apache Common Log Format
- Apache Combined Log Format
- Nginx default
- JSON logs
- Gzipped files (`.log.gz`)

## Example Output

```
http-surgeon: analyze access.log
Lines parsed: 142,847 | Errors: 8.2% | Period: 6h 14m

SLOWEST ENDPOINTS (p95)
/api/search             p50=124ms  p95=1842ms  p99=4201ms  (n=8,412)
/api/recommendations    p50=89ms   p95=940ms   p99=2100ms  (n=3,201)
/api/users/:id          p50=12ms   p95=88ms    p99=201ms   (n=41,002)

ERRORS BY ENDPOINT
/api/search             500: 412   503: 88    (6.4% error rate)
/api/webhooks           401: 1,204              (all from 3 IPs)

TRAFFIC SPIKES
14:22 UTC  spike: 3.8x baseline (2,401 req in 60s vs 631 avg)
14:24 UTC  spike: 2.1x baseline

SECURITY
Brute force detected: 45.12.88.203 (412 failed logins in 10m)
Path traversal probes: 103.21.55.18 (tried: /../etc/passwd, /wp-admin, /.env)
```

## Use Cases

- Post-incident analysis: what happened during the outage?
- Pre-deploy baseline: capture p95 before shipping, compare after
- Security audit: find scanners, brute force attempts, unusual IPs
- Performance regression: `compare` command diffs two time windows

## Requirements

Python 3.8+. No dependencies. Handles logs up to several GB.
