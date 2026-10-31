# SiteGrade — Build Brief

> **Architecture note:** Both **Easy** and **Demon** modes run live, pure-Python, non-intrusive security posture checks against any consented public website or GitHub repository — no synthetic demo data, no Docker containers, and no domain locklists. See `README.md` for full Easy vs. Demon check coverage.

> Working name. An instant, read-only **security scorecard**: paste a URL (or GitHub repo),
> get a letter grade, see the specific findings, and copy a ready-to-paste fix prompt for an
> AI coding agent. Built for a 5-hour hackathon with a rotating-table demo (90-second runs).

---

## 0. The one-line pitch

"Point me at anything you've built and get an instant security grade — plus the exact prompt
to fix what's wrong."

The demo lands whether the site is clean (scores an A) or a disaster (scores an F). The wow
is the **live scorecard generating in real time**, not finding a victim.

---

## 1. SAFETY RULES — these are hard constraints, not suggestions

This tool is a **consented, passive audit**. Every feature below respects these. Do not add
anything that breaks them.

- **Owner-provided targets only.** The tool scans only a URL or repo the user types in. The UI
  shows a one-line consent notice: *"Only scan sites you own or have permission to test."*
- **Read-only / passive only.** Allowed: `GET` requests to public paths, reading public JS,
  reading public Certificate Transparency logs, rendering a public page in an iframe, reading a
  public GitHub repo.
- **Never:** send injection or malformed payloads, flood or repeat requests, use any discovered
  credential to authenticate anywhere, log in, modify or delete anything, or touch anything
  non-public.
- **Throttle yourself.** Cap total requests per scan (~30 max), short timeouts (3–5s), small
  delays. A scan should look like a careful visitor, never a stress test.
- No SQL-injection probing, no DoS, no brute force. We detect *patterns* and *exposure*, we do
  not attack.

If a check can't be done within these rules, it doesn't ship.

---

## 2. Stack (chosen for speed + your Python background)

- **Backend:** Python + **FastAPI**, `httpx` (async) for concurrent checks.
- **Frontend:** single `index.html` with **Tailwind via CDN** + vanilla JS. One file, no build step.
- **Fix prompts:** **template-based** (deterministic — reliable for a live demo). Optional LLM
  polish later, but templates are the default so nothing hallucinates on stage.
- **No database.** Each scan is stateless: request in, JSON out.

```
Browser (index.html)
   │  POST /scan { target }
   ▼
FastAPI  ──▶ run all checks concurrently (httpx)
   │         header checks · cookie flags · CORS · exposed files · swagger
   │         secret scan · API surface · tech+CVE · crt.sh subdomains
   ▼
JSON { grade, score, checks[], findings[], fix_prompt, clickjack_ok }
   │
   ▼
Frontend renders: big grade · green/red checklist · live clickjack iframe · copy-prompt button
```

---

## 3. The checks

### URL mode (works on any site, no repo needed)

| # | Check | How (passive) | Typical hit rate |
|---|-------|---------------|------------------|
| 1 | Security headers | Read response headers: CSP, HSTS, X-Frame-Options/`frame-ancestors`, X-Content-Type-Options, Referrer-Policy, Permissions-Policy | Very high (esp. CSP) |
| 2 | Cookie flags | Parse `Set-Cookie`: HttpOnly, Secure, SameSite | Medium |
| 3 | CORS wildcard | Send an `Origin:` header, check for `Access-Control-Allow-Origin: *` | High on apps w/ backend |
| 4 | Exposed files | `GET` `/.env`, `/.git/HEAD`, `/.git/config`, `.js.map` files | Low on hosted, higher on VPS |
| 5 | Open API docs | `GET` `/docs`, `/openapi.json`, `/redoc` | High on FastAPI backends |
| 6 | Version leak | `Server:` and `X-Powered-By:` headers | Medium |
| 7 | **Secrets in JS** | Fetch linked `<script>` bundles, regex for `sk-…`, `sk_live_…`, AWS, Google keys | Medium–high 🔥 |
| 8 | HTTPS enforced | Does `http://` redirect to `https://`? | Low (good hosts fix it) |
| 9 | Tech + CVE | Fingerprint framework/version from headers+bundles → **OSV.dev** lookup | Medium |
| 10 | **Subdomains** | **crt.sh** CT-log query for `%.domain` → list forgotten `staging.`, `admin.` | High 🔥 |
| 11 | **API surface** | Regex endpoint paths out of the JS bundles → map their "hidden" backend | High |
| 12 | **Clickjack PoC** | If `X-Frame-Options`/`frame-ancestors` missing → render live iframe demo | High 🔥 |

**Secret-scan false-positive guard:** Supabase `anon` keys and Firebase config are *meant* to be
public — do NOT flag them as leaks. Reclassify as: *"Public key detected — confirm Row-Level
Security / DB rules are enabled."*

### Repo mode (if the target is a GitHub URL — this is where depth lives)

| # | Check | How |
|---|-------|-----|
| 13 | Unparameterized SQL | Grep for f-strings / string-concat inside `execute(...)` / `db.query(...)` |
| 14 | DOM XSS pattern | `dangerouslySetInnerHTML`, `innerHTML =` with a variable |
| 15 | Committed secrets | Scan tracked files + `.env` committed to the repo |
| 16 | Dependency CVEs | Parse `package-lock.json` / `requirements.txt` → OSV.dev (show only HIGH/CRITICAL in direct deps) |

---

## 4. The wow features (build these well — they are the demo)

1. **Live clickjacking proof** *(the headline)*. When frame protection is missing, show their
   real site in an `<iframe>` on your page with a semi-transparent fake "Claim $500" button
   overlaid. "This is your live site, embedded in mine, with my button on top." Pure frontend,
   harmless, visually undeniable.
2. **Subdomain reveal (crt.sh).** Lists subdomains from public certificate logs — feels like
   recon, surfaces forgotten `staging.`/`dev-api.` hosts. 100% public data.
3. **Leaked-key blast radius.** On a secret hit, show *what it unlocks* ("anyone who finds this
   can run up your API bill") as a little consequence map. Detect and show — never use the key.
4. **API surface map.** Draw the endpoints pulled from their JS as a diagram of their backend.

---

## 5. Grading rubric

- Start at 100. Each failed check subtracts weighted points by severity
  (CRITICAL −25, HIGH −15, MEDIUM −8, LOW −3).
- **Caps:** any live leaked key or exposed `.git`/`.env` caps the grade at **C** regardless of score.
- Map score → letter: A+ (97+), A (90+), B (80+), C (70+), D (60+), F (<60).
- Always render the passing checks in green too — a clean site earns a visible, satisfying A.

---

## 6. Fix-prompt generator (the differentiator)

Each finding type has a template. **Detect the stack first** (Next.js / Vite / FastAPI /
Express) so the fix is specific, then aggregate all findings into one master prompt. Template shape:

```
You are a senior security engineer. Fix the following issue without changing UI or behavior.

[VULNERABILITY]  <type>
[LOCATION]       <file/route/header>
[IMPACT]         <one plain sentence>
[FIX]            <specific instruction for THIS stack>
[CONSTRAINTS]    Don't alter styling or state logic. No eval/unencoded innerHTML.

Output only the diff or the fully patched file.
```

Example tailored line: *"Move the OpenAI call into a Next.js route handler at
`app/api/chat/route.ts` and delete `NEXT_PUBLIC_OPENAI_KEY`."* — far better than "don't expose keys."

---

## 7. UI (single page, high contrast, built for a crowd)

- Big input + **Scan** button. Accepts URL or GitHub link (auto-detect).
- Scanning animation (checks lighting up one by one feels fast and alive).
- **Giant letter grade**, color-coded. Below it: the green/red checklist with CRITICAL/HIGH/LOW
  severity chips.
- Split view on a finding: **left** the problem, **right** the fix + **Copy prompt** button.
- The clickjack iframe panel.
- A simple risk meter that visibly drops to green "after applying fix" (qualitative, not fake dollars).

---

## 8. Five-hour timeline

- **0:00–0:30 — Skeleton end to end.** FastAPI `/scan` returns *fake* JSON; frontend renders a
  scorecard from it. Get the whole pipe working before any real check.
- **0:30–1:30 — One-request checks.** Headers, cookies, CORS, exposed files, open docs, version
  leak, HTTPS redirect. Real grades now appear.
- **1:30–2:30 — Secrets + API surface.** Fetch JS bundles, run the regex set + Supabase/Firebase
  guard, extract endpoints.
- **2:30–3:30 — Wow tier.** Clickjack iframe PoC, crt.sh subdomains, tech fingerprint + OSV CVE.
- **3:30–4:15 — Grade + fix prompts + polish.** Rubric, templated prompt generator, severity
  chips, split view, scan animation.
- **4:15–5:00 — Harden + rehearse.** Deploy backup flawed sites, test on 8–10 real URLs, handle
  timeouts/blocked sites gracefully (a Cloudflare block must degrade to a clean message, never a
  crash), rehearse the 90-second run.

**Build order rule:** get the skeleton rendering first, then add checks one at a time, each
returning real data before moving on. Never leave the pipe broken.

---

## 9. Pre-event prep (do NOT skip)

Deploy **two of your own deliberately flawed sites** as guaranteed demos:
- **Site A (Next.js):** a `NEXT_PUBLIC_…` leaked key, no CSP, clickjackable.
- **Site B (FastAPI):** `CORS *`, open `/docs`, `Server:` version leak.

Keep their URLs pinned. If a judge's site scores clean: *"Yours is an A — here's what it catches
on one that isn't,"* then show the dramatic one. You never end on a blank screen.

---

## 10. The 90-second demo script

1. "Give me any site you've built — URL or GitHub." *(judge types it)*
2. Scan runs; **grade appears in ~3 seconds.**
3. "You got a C — here's why." Point at the two red findings.
4. "Watch this." → **live clickjacking iframe.**
5. "And here's the fix." → **Copy the agent prompt** (optionally paste into Cursor/Claude Code live).
6. "Apply it and you're back to an A." Done — reset for the next group.

---

## 11. Stretch goals (only if ahead of schedule)

- Wayback Machine check: scan archived JS for keys that are still live in the archive.
- `security.txt` presence as a positive signal.
- Shareable result link / downloadable PDF report.
- LLM polish layer on top of the templated fix prompts.

---

## 12. Kickoff prompt for Claude Code

> Read `PROJECT_BRIEF.md`. Build SiteGrade exactly to the SAFETY RULES in section 1 — passive,
> read-only, owner-provided targets only, no attack traffic, no use of discovered credentials.
> Start with the section 8 skeleton: FastAPI `/scan` returning stub JSON and an `index.html`
> (Tailwind CDN + vanilla JS) that renders the scorecard from it. Get that running, then
> implement the section 3 checks one at a time, each returning real data before the next. Keep
> it to two files where possible. Ask me before adding any dependency beyond FastAPI, httpx, and
> uvicorn.
