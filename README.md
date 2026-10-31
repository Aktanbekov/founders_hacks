# SiteGrade

A fast, stateless, live security posture scorecard built for Founders Hackathon Night. Pure Python (`FastAPI` + `httpx` + stdlib `ssl`) and a single vanilla HTML/JS/CSS frontend. No Docker containers, no synthetic demo fixtures, no hardcoded domain allowlists, no database, and no build step.

## Run

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m uvicorn app:app --host 127.0.0.1 --port 8000 --reload
```

Open `http://127.0.0.1:8000`, enter any public website URL (`https://your-site.com`) or public GitHub repository (`https://github.com/owner/repo`), confirm permission, and pick a mode:

- **Easy (~2–4s, up to 30 target requests):** Entry-page security headers & CSP script semantics, live sandboxed clickjacking PoC when framing is unguarded, cookie flags (`Secure`, `HttpOnly`, `SameSite`), server/version disclosure, HTTP→HTTPS redirect, root CORS reflection, sensitive root files (`/.env`, `/.git/HEAD`, `/.git/config`), OpenAPI docs, up to 6 same-origin JS bundles + 2 source maps for redacted secret fingerprints, external cloud host extraction (`*.supabase.co`, Cloud Run, Stripe, etc.), and Certificate Transparency (`crt.sh`) subdomain discovery.
- **Demon (~6–12s, up to 65 target requests + parallel OSINT):** Everything in Easy mode **plus** a full **Collected Recon & Attack Surface X-Ray** (`result.recon`):
  - **Server location & network intel:** Resolved IP, physical Geo location (city, region, country), ASN/hosting provider, and reverse DNS (`PTR`).
  - **Live TLS & X.509 certificate inspection:** Negotiated TLS protocol (`TLSv1.2` / `TLSv1.3`), cipher suite & bit strength, CA issuer, certificate expiry countdown, and X.509 `SubjectAltName` (`SAN`) hostnames.
  - **Live DNS & email spoofing architecture:** Queries DNS-over-HTTPS for `NS`, `MX`, full **SPF** (`v=spf1`), **DMARC** (`_dmarc.<domain>`), **CAA** certificate restrictions, and third-party SaaS verification TXT tokens (`Vercel`, `Google`, `OpenAI`, `Stripe`, etc.).
  - **Multi-source subdomain & dangling-CNAME check:** Combines X.509 SANs, `CertSpotter`, `HackerTarget` passive DNS, `crt.sh`, and passive DoH resolution to list live subdomains, resolved IPs, CNAME targets, and dangling CNAME takeover risks (`NXDOMAIN` CNAMEs on cloud providers).
  - **Expanded exposure & diagnostic checks:** `/.well-known/security.txt`, `/.DS_Store` binary signature, `/phpinfo.php`, `/actuator/env`, `/server-status`, `/graphql` IDE exposure, `/swagger.json`, `/robots.txt`, and `/sitemap.xml`.
  - **Live Route & `/api/*` Probe with `file:line` provenance:** Probes JS-discovered `/api/...` routes and crawled public sub-pages with read-only unauthenticated `GET` requests, recording exact `bundle:line` discovery location, HTTP status, `Content-Type`, byte size, CORS/cache headers, and auth-gate verdict.
  - **Expanded JS, external service map & live CVE matching:** Maps external SaaS/cloud hosts embedded in up to 14 JS bundles + 5 source maps with `bundle:line` provenance, extracts exact client library versions, and matches them against GitHub Reviewed Advisories (`HIGH`/`CRITICAL`).
  - **Deep GitHub repository mode:** Expands repository sampling up to 30 files (prioritizing `.env`, SQL RLS migrations, Firebase rules, `.github/workflows/*.yml` CI injection/`pull_request_target` patterns, `Dockerfile` build secrets, and server routes) and matches up to 12 exact direct dependencies against GitHub Reviewed Advisories.

## Safety & Engineering Boundaries

- **Real, non-intrusive observations only:** Sends only read-only `GET` requests (plus a standard TLS handshake on port 443 in Demon mode) with `Cookie: ""`. Sends **no** SQLi/XSS payloads, **no** malformed inputs, and **no** credential or brute-force attempts.
- **SSRF & DNS-rebinding defense:** Every hostname (including every redirect hop) must resolve exclusively to globally routable public IPs; private, loopback, and link-local networks (`127.0.0.1`, `10.0.0.0/8`, `169.254.169.254`, `::1`, etc.) are blocked. Connections are pinned directly to the validated IP while preserving `Host` and TLS `SNI`.
- **Zero secret or payload echoing:** Credential matches are hashed to SHA-256 fingerprints before being emitted to the UI, JSON export, or AI fix prompt. Sensitive file format checks and `/api/*` gate checks never retain or echo response contents.

## API

- `POST /scan` — returns full JSON report (`{"target": "https://example.com", "consent": true, "mode": "easy" | "demon"}`).
- `POST /scan/stream` — streams newline-delimited JSON events (`phase`, `check`, `result`, `error`) in real time (`X-Accel-Buffering: no` enabled for cloud reverse proxies).
- `GET /health` — server readiness check.

## Deploy on Render.com (via GitHub)

This repository includes [`render.yaml`](render.yaml), [`Procfile`](Procfile), and [`.python-version`](.python-version) for zero-config deployment:

1. **Blueprint deploy (recommended):** In Render Dashboard → **New +** → **Blueprint** → select `Aktanbekov/founders_hacks` → click **Apply**.
2. **Or manual Web Service:** In Render Dashboard → **New +** → **Web Service** → select `Aktanbekov/founders_hacks`:
   - **Runtime:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn app:app --host 0.0.0.0 --port $PORT --proxy-headers --forwarded-allow-ips="*"`
   - **Health Check Path:** `/health`

## Verification

```sh
.venv/bin/python -m unittest discover -s tests -v
```
