# 🐱 SiteGrade

### Check your AI slop for holes your AI left behind.

You vibe-coded a site in a weekend. Nice. Your AI probably also skipped the security headers, maybe dropped an API key into your JavaScript, and might have left your `.env` file public.

**SiteGrade finds that stuff in seconds.** Paste a URL, pick a cat, get a letter grade, then copy one prompt that tells your AI agent exactly how to fix it.

Built for **Founders Hackathon Night**. Python + FastAPI + one HTML file. No database, no build step, no API keys.

---

## ⚡ Try it in 30 seconds

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m uvicorn app:app --host 127.0.0.1 --port 8000 --reload
```

Open http://127.0.0.1:8000 and paste a website (`https://your-site.com`) or a public GitHub repo (`https://github.com/owner/repo`). Tick the permission box, then pick your cat.

## 😺 Easy vs 😈 Demon

|  | 😺 Easy | 😈 Demon |
|---|---|---|
| **Vibe** | Quick health check | Full X-ray of your attack surface |
| **Time** | ~2–4 s | ~6–12 s |
| **Requests to your site** | up to 30 | up to 60, plus up to 50 public-data lookups |
| **JavaScript read** | 6 bundles, 2 source maps | 14 bundles, 5 source maps |
| **GitHub repo mode** | 16 files, 5 dependencies | 30 files, 12 dependencies |

Both modes are **read-only**. No attacks, ever. See **How it stays safe** below.

## 🔍 What it catches

### 😺 Easy mode

- **Missing security headers:** CSP (including risky rules like inline scripts or `eval`), HSTS, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`
- **Clickjacking:** if your site can be framed, you see it live inside a sandboxed frame with a fake button on top
- **Weak cookies:** missing `Secure`, `HttpOnly` or `SameSite`
- **Leaked keys in your JavaScript:** OpenAI, Anthropic, Stripe, Supabase `service_role`, GitHub tokens, AWS, database URLs with passwords, private keys
- **Files that should never be public:** `/.env`, `/.git/HEAD`, `/.git/config`
- **Open API docs:** `/docs`, `/openapi.json`, `/redoc`
- **The usual suspects:** CORS that trusts any origin with credentials, no HTTP→HTTPS redirect, server version leaks
- **Your public footprint:** cloud services your JS talks to (Supabase, Stripe, Cloud Run…) and subdomains from certificate logs (`crt.sh`)

### 😈 Demon mode: everything above, plus

- **Where your server lives:** IP, city and country, hosting provider (ASN), reverse DNS
- **TLS check:** protocol version, cipher, issuer, days until your certificate expires, every hostname on it
- **Can someone spoof your email?** SPF, DMARC, CAA, MX and NS records, plus SaaS verification tokens (Vercel, Google, OpenAI, Stripe…)
- **Subdomain hunt and takeover check:** combines certificate names, CertSpotter, HackerTarget and `crt.sh`, then flags dangling CNAMEs someone could take over
- **More forgotten files:** `security.txt`, `.DS_Store`, `phpinfo.php`, `/actuator/env`, `/server-status`, GraphQL IDE, `swagger.json`, `robots.txt`, `sitemap.xml`
- **API route probe:** finds `/api/...` routes in your JS, checks each with a plain `GET` to see if it's locked or open, and shows the exact `bundle:line` where it was found
- **Vulnerable libraries:** detects exact client library versions and matches them against GitHub's reviewed advisories (HIGH and CRITICAL only)

### 📦 GitHub repo mode

- Committed `.env` files and secrets
- Row-Level Security turned off, "allow everyone" database and Firebase rules
- SQL built by gluing strings together, raw HTML insertion, disabled JWT verification
- User input flowing straight into HTTP clients (SSRF), payment amounts or AI system prompts
- Risky GitHub Actions workflows, secrets baked into Dockerfiles, secret variables exposed through public prefixes like `NEXT_PUBLIC_`
- Vulnerable pinned dependencies from `package-lock.json`, `package.json` or `requirements.txt`

## 🎓 How the grade works

You start at **100**. Each problem costs points: Critical −25 · High −15 · Medium −8 · Low −3.

Some problems are bad enough to **cap you at C**, whatever your score: a leaked private key, a public `.env` or `.git`, a broken TLS certificate, or a subdomain someone could take over.

**A+** 97+ · **A** 90+ · **B** 80+ · **C** 70+ · **D** 60+ · **F** below 60

If a check couldn't run, it shows as **unknown**. It never counts as a pass.

## 🤖 The fix prompt

One click copies a prompt for Claude Code, Cursor or Codex. It lists every finding, where it is, why it matters, and how to fix it for your stack (Next.js, FastAPI, Express…).

Your AI made the mess. Let it clean up.

## 🛡️ How it stays safe (the nerdy part)

- **Read-only.** Only `GET` requests, plus one normal TLS handshake in Demon mode. No SQL injection or XSS payloads, no brute force, no logins. Cookies are never sent back (`Cookie: ""`).
- **Can't be aimed at private networks.** Every hostname and every redirect must resolve to a public IP. `127.0.0.1`, `10.x.x.x`, `169.254.169.254` (cloud metadata), `::1` and friends are blocked. Each request is pinned to the IP that was checked, keeping `Host` and TLS SNI, so DNS rebinding tricks don't work.
- **Polite.** Hard request caps, small delays between requests, short timeouts (about 4 s), 750 KB max per response, 3 scans at a time. Easy stops after 40 s, Demon after 75 s.
- **Never shows your secrets.** A leaked key appears only as a short SHA-256 fingerprint in the UI, the JSON report and the fix prompt. SiteGrade never tries a key it finds.
- **Heads-up:** Demon mode looks up public data through third-party services (ipwho.is, ipinfo.io, Cloudflare DNS-over-HTTPS, `crt.sh`, CertSpotter, HackerTarget), so those services see the domain you scan.

## 🔌 API

| Endpoint | What it does |
|---|---|
| `POST /scan` | Runs a scan and returns the full JSON report |
| `POST /scan/stream` | Same scan, streamed live as newline-delimited JSON events: `phase`, `check`, `result`, `error` |
| `GET /health` | Readiness check |

Request body:

```json
{"target": "https://example.com", "consent": true, "mode": "easy"}
```

`mode` is `"easy"` or `"demon"`. `consent` must be `true`, or the scan is refused.

## 🚀 Deploy on Render (free tier)

The repo ships with [`render.yaml`](render.yaml), [`Procfile`](Procfile) and [`.python-version`](.python-version), so there's nothing to configure.

1. **Blueprint (easiest):** Render dashboard → **New +** → **Blueprint** → pick `Aktanbekov/founders_hacks` → **Apply**.
2. **Or by hand:** Render dashboard → **New +** → **Web Service** → pick the repo, then set:
   - **Build command:** `pip install -r requirements.txt`
   - **Start command:** `uvicorn app:app --host 0.0.0.0 --port $PORT --proxy-headers --forwarded-allow-ips="*"`
   - **Health check path:** `/health`

## ✅ Tests

```sh
.venv/bin/python -m unittest discover -s tests -v
```

32 tests, under a second. Network calls are mocked, so no real website is contacted.

## 🙃 Honest limits

- A good grade doesn't mean you're secure. SiteGrade reads a sample of your site, not all of it.
- Leaked-key matches are patterns. SiteGrade never tries a key to see if it works.
- It can't see behind a login, so real RLS enforcement, rate limits and business logic aren't tested.
- **Only scan sites you own or have permission to test.**

## License

MIT © 2026 Aktai Aktanbekov
