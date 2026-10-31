"""Offline evidence detectors. Never authenticate, execute code, or echo secrets."""
import base64
import hashlib
import json
import re

CATEGORIES = [
    ("database", "Database rules & RLS", "Deployed policies and cross-user access require policy source and controlled accounts."),
    ("authorization", "Authentication & ownership", "Role and object ownership enforcement requires server review and separate test accounts."),
    ("secrets", "Exposed credentials", "Only downloaded content is sampled. Credential validity is never tested."),
    ("configuration", "Headers, TLS & domain posture", "Public response policies, transport metadata and explicit source patterns only."),
    ("rate_limits", "Rate limits & AI spend", "Enforcement, quotas and paid endpoint behavior require controlled tests."),
    ("injection", "XSS, SQL & CI injection", "Static source patterns do not establish data flow, sanitization or exploitability. Log injection is not assessed."),
    ("ssrf", "Server-side request forgery", "Direct request-to-fetch patterns only; URL validation and reachability require review."),
    ("business_logic", "Payments & business logic", "Client-controlled payment patterns only; workflow correctness requires controlled tests."),
    ("dependencies", "Dependencies & client libraries", "Exact resolved versions only. No transitive execution or slopsquatting proof."),
    ("prompt_injection", "AI prompt trust boundaries", "Direct request-to-system-prompt patterns only; tools, retrieval and MCP are not exercised."),
]

SEMVER_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$")


def observation(key, title, detail, severity, fix, location, category, *, confidence="review", cap=False, status="fail", line=None):
    return dict(id=key, title=title, status=status, detail=detail, severity=severity, fix=fix,
                location=location, category=category, confidence=confidence, cap=cap, line=line)


def credential_findings(text, location):
    out = []
    def hit(kind, raw, impact):
        fp = hashlib.sha256(raw.encode()).hexdigest()[:12]
        out.append(observation("credential-" + fp, kind,
            impact + f" Fingerprint {fp}. Format/claims observed only; validity, signature and permissions were not verified. The credential was never used.",
            "critical", "Revoke or rotate the credential if real. Remove it from public assets and repository history; keep privileged operations server-side and enforce per-user authorization. Rebuild deployed bundles and review access logs.",
            location, "secrets", confidence="pattern", cap=True))
    patterns = [
        ("Supabase privileged secret key", r"\bsb_secret_[A-Za-z0-9_-]{20,}", "This secret-key format is intended for privileged server access and can bypass RLS if valid."),
        ("Database connection credential", r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis(?:s)?)://[^\s:'\"<>/]+:[^\s@'\"<>]+@[^\s'\"<>]+", "A connection URL containing a username and password is exposed. If valid, it may grant direct database access."),
        ("Anthropic-style API secret", r"\bsk-ant-[A-Za-z0-9_-]{24,}", "A private AI-provider key pattern could permit unauthorized API spending if valid."),
        ("Stripe restricted secret", r"\brk_live_[A-Za-z0-9]{16,}", "A restricted payment-service secret pattern is exposed; permissions were not tested."),
        ("GitHub fine-grained token", r"\bgithub_pat_[A-Za-z0-9_]{30,}", "A source-control token pattern may grant access to repositories or automation if valid."),
        ("AWS secret access key assignment", r'''(?i)(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)["']?\s*[:=]\s*["']([A-Za-z0-9/+=]{40})["']''', "An AWS secret access key assignment was observed; cloud permissions were not tested."),
    ]
    for kind, pattern, impact in patterns:
        for m in list(re.finditer(pattern, text))[:3]:
            hit(kind, m.group(1) if m.lastindex else m.group(), impact)
    roles = set()
    for m in re.finditer(r"\beyJ[A-Za-z0-9_-]{5,2048}\.[A-Za-z0-9_-]{5,4096}\.[A-Za-z0-9_-]{8,1024}\b", text):
        token = m.group()
        try:
            payload = token.split(".")[1]
            claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
            if not isinstance(claims, dict):
                continue
        except (ValueError, UnicodeError):
            continue
        role = claims.get("role")
        if role == "service_role":
            hit("Privileged service_role JWT", token, "JWT payload declares service_role. A valid Supabase service-role credential bypasses Row-Level Security.")
        elif role == "anon":
            roles.add("anon")
    if roles or "sb_publishable_" in text:
        out.append(observation("public-supabase-" + hashlib.sha256(location.encode()).hexdigest()[:8],
            "Public Supabase key",
            "An anon/publishable key pattern is present. This is expected in browser code and does not establish a secret leak or broken RLS. Deployed database policies were not inspected.",
            "info", "Review RLS and ownership policies with controlled accounts; never replace the public key with a privileged key.",
            location, "database", confidence="pattern", status="info"))
    return out


def source_findings(text, location, *, public=False):
    """Conservative same-statement heuristics; findings always require source review."""
    out = []
    suffix = location.lower().split("?")[0]
    is_sql = suffix.endswith(".sql")
    is_rules = suffix.endswith((".rules", "rules.json", "database.rules.json"))
    is_workflow = ".github/workflows/" in suffix and suffix.endswith((".yml", ".yaml"))
    is_dockerfile = suffix.endswith("dockerfile") or "/dockerfile." in suffix
    # Strip comments from policy files to avoid treating examples as enabled rules.
    code = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    if is_sql:
        code = re.sub(r"(?m)--[^\n]*", "", code)
    elif is_rules:
        code = re.sub(r"(?m)//[^\n]*", "", code)

    def detect(key, title, pattern, category, severity, impact, fix, flags=re.I, content=None):
        match = re.search(pattern, code if content is None else content, flags)
        if match:
            line = (code if content is None else content).count("\n", 0, match.start()) + 1
            out.append(observation(key + "-" + hashlib.sha256(location.encode()).hexdigest()[:10], title,
                impact + " Static pattern only; deployment state and exploitability are unverified.", severity,
                fix, location, category, line=line))

    if is_sql:
        detect("rls-disabled", "Row-Level Security explicitly disabled",
            r"ALTER\s+TABLE\s+[^;]{1,160}\s+DISABLE\s+ROW\s+LEVEL\s+SECURITY", "database", "high",
            "A SQL statement explicitly disables RLS. If applied to an API-exposed table, access may bypass intended per-user policies.",
            "Inspect the final deployed table state and grants. Enable RLS on exposed tables and add explicit ownership policies for each required operation; verify with separate test users.")
        detect("rls-open-write", "Unconditional database write policy",
            r"CREATE\s+POLICY\b[^;]{0,600}?FOR\s+(?:ALL|INSERT|UPDATE|DELETE)\b[^;]{0,600}?(?:USING|WITH\s+CHECK)\s*\(\s*true\s*\)", "database", "high",
            "A write-capable policy contains an unconditional true expression. Role scope, grants and later migrations may change its effect.",
            "Review policy roles, USING and WITH CHECK together. Restrict writes to the authenticated owner or explicit authorized role, and verify the final database policies with controlled accounts.")
    if is_rules:
        detect("firebase-open-write", "Unconditional Firebase write rule",
            r"allow\s+(?:[a-z,\s]*\b)?(?:write|create|update|delete)\b[a-z,\s]*:\s*if\s+true\s*;|[\"']\.write[\"']\s*:\s*true", "database", "high",
            "A Firebase rule grants unconditional writes at a matched scope. Inherited rules and deployment scope must be reviewed.",
            "Replace unconditional writes with authentication, ownership and schema checks at the intended path. Test allow/deny cases in the Firebase emulator before deployment.")
        detect("firebase-open-read", "Unconditional Firebase read rule",
            r"allow\s+(?:[a-z,\s]*\b)?(?:read|get|list)\b[a-z,\s]*:\s*if\s+true\s*;|[\"']\.read[\"']\s*:\s*true", "database", "medium",
            "An unconditional read rule is present. This may be intentional for public data; sensitive data classification is unknown.",
            "Confirm whether every record covered by this rule is intended to be public. Apply ownership rules to private data and test with separate users.")
    if is_workflow:
        if re.search(r"\bpull_request_target\b", text):
            detect("ci-pr-target", "Workflow checks out untrusted PR code under pull_request_target",
                r"github\.event\.pull_request\.head\.(?:sha|ref)", "configuration", "high",
                "Checking out untrusted pull request code inside a pull_request_target workflow can expose repository secrets or write tokens.",
                "Use pull_request for untrusted code builds, or isolate secret-bearing steps from untrusted code execution.", content=text)
        detect("ci-script-inject", "Untrusted GitHub event field interpolated in workflow",
            r"\$\{\{\s*github\.event\.(?:issue\.(?:title|body)|pull_request\.(?:title|body)|comment\.body|review\.body|head_commit\.message)", "injection", "high",
            "Interpolating user-controlled GitHub event text directly into a workflow step can allow shell command injection.",
            "Pass untrusted GitHub event fields through step environment variables rather than inline ${{ ... }} expressions.", content=text)
    if is_dockerfile:
        detect("docker-secret", "Secret-named build variable in Dockerfile",
            r"(?m)^\s*(?:ENV|ARG)\s+[A-Z0-9_]*(?:SECRET|PASSWORD|PRIVATE_KEY|API_KEY|SERVICE_ROLE)[A-Z0-9_]*\b", "secrets", "high",
            "Secrets passed via Dockerfile ENV or ARG persist in image metadata and layers.",
            "Mount build-time secrets via BuildKit --mount=type=secret and inject runtime secrets via orchestrator environment stores.", content=text)

    detect("public-env", "Privileged variable uses a browser-public prefix",
        r"\b(?:NEXT_PUBLIC_|VITE_|REACT_APP_)[A-Z0-9_]*(?:SERVICE_ROLE|SECRET|PRIVATE_KEY|DATABASE_URL|STRIPE_SECRET)[A-Z0-9_]*\b", "secrets", "high",
        "A variable name suggests privileged material is configured for browser exposure. Its actual value and build inclusion were not established.",
        "Verify the variable's contents and build output. Remove private secrets from browser-public variables, rotate exposed credentials, and move privileged calls to an authorized server route.")
    detect("dom-html", "Raw HTML insertion needs review",
        r"dangerouslySetInnerHTML\s*(?:=|:)|\.innerHTML\s*=\s*(?![\"'`])\w", "injection", "medium",
        "A raw HTML insertion sink is present. The scanner has not established whether its input is untrusted or sanitized.",
        "Trace the value reaching this sink. Prefer textContent/framework escaping, or a vetted HTML sanitizer where rich HTML is necessary. Add a targeted injection regression test.")
    if public:
        # Framework runtimes contain HTML sinks even when application input is safe.
        direct_input = re.search(r"\.innerHTML\s*=\s*(?:window\.)?(?:location\.|document\.(?:URL|documentURI)|event\.target\.value)", code)
        for item in out:
            if item["id"].startswith("dom-html") and not direct_input:
                item["status"], item["severity"] = "info", "info"
                item["detail"] = "A raw HTML sink exists in downloaded JavaScript, which may be framework runtime code. No direct untrusted-input flow was identified. This is not an XSS finding."
        detect("client-role", "Browser-side authorization clue",
            r'''localStorage\.getItem\(\s*["'](?:isAdmin|role|isAuthenticated|isPaid)["']\s*\)''', "authorization", "info",
            "A browser-controlled value appears to participate in an access decision. This does not establish missing server authorization.",
            "Verify the backend independently authenticates requests and enforces roles, ownership and entitlements. Browser checks should only control presentation.")
        for item in out:
            if item["id"].startswith("client-role"):
                item["status"] = "info"
    if not public:
        detect("jwt-no-verify", "JWT signature verification explicitly disabled",
            r'''verify_signature["']?\s*:\s*False|jwt\.decode\([^\n]{0,220}verify\s*=\s*False''', "authorization", "high",
            "A JWT decode configuration disables signature verification. Parsing alone is acceptable, but trusting these claims for authorization is unsafe.",
            "Trace how decoded claims are used. Authenticate with signature, algorithm, issuer, audience and expiry verification before making authorization decisions.")
        detect("sql-input", "Interpolated SQL query construction",
            r'''(?:execute|query)\s*\(\s*(?:f["']|["'][^\n]{0,200}["']\s*\+)''', "injection", "medium",
            "A query call uses interpolation or concatenation. Untrusted data flow is unverified.",
            "Replace untrusted query interpolation with driver-supported parameterized queries. Keep SQL identifiers on explicit allowlists.")
        detect("ssrf-input", "Request data passed directly to an HTTP client",
            r"(?:requests\.(?:get|post)|httpx\.(?:get|post)|fetch)\s*\(\s*(?:req\.(?:body|query|params)\.\w+|request\.(?:args|GET|query_params)\.get\([^\n]{0,100})", "ssrf", "high",
            "A fetch call receives request-derived input in the same statement. Upstream validation or a safe wrapper may exist outside the sample.",
            "Trace the URL input. Restrict destinations with an explicit allowlist, validate resolved addresses and every redirect, and block private/link-local destinations. Add controlled tests without contacting internal services.")
        detect("payment-input", "Payment amount appears client-controlled",
            r"(?:unit_amount|amount|price_data)\s*:\s*(?:req\.(?:body|query)\.[A-Za-z_]+|request\.(?:data|json)\[)", "business_logic", "medium",
            "A payment-related field is assigned directly from request data. Server validation or catalog lookup may exist elsewhere.",
            "Resolve prices and entitlements from a trusted server-side catalog, validate quantities, and verify payment completion before granting access. Test using the payment provider's sandbox.")
        detect("prompt-system", "Request data placed in a system prompt",
            r'''role\s*:\s*["']system["']\s*,\s*content\s*:\s*req\.(?:body|query)\.\w+''', "prompt_injection", "medium",
            "A message with the system role is populated directly from request input. Full prompt construction and tool permissions were not reviewed.",
            "Keep system instructions server-controlled. Treat user/retrieved content as untrusted input and enforce tool permissions independently of model output.")
        detect("debug", "Debug mode explicitly enabled",
            r"\b(?:DEBUG\s*=\s*True|app\.run\([^\n]{0,100}debug\s*=\s*True)", "configuration", "medium",
            "An explicit debug setting appears in source. It may be development-only; production settings are unknown.",
            "Ensure debug mode and interactive debuggers are disabled in production, and use generic error responses with server-side logs.")
    return out


def response_findings(text, location):
    patterns = [
        ("interactive-debugger", "Interactive debugger page exposed", r"Werkzeug Debugger|Debugger PIN|The debugger caught an exception", "high"),
        ("stacktrace", "Verbose server error details", r"Traceback \(most recent call last\):|django\.views\.debug|<title>[^<]*(?:Exception|Stack Trace)", "medium"),
        ("database-error", "Database error details in public response", r"SQLITE_ERROR:|psycopg2\.errors\.|PrismaClientKnownRequestError|You have an error in your SQL syntax|MongoServerError", "medium"),
    ]
    suffix = hashlib.sha256(location.encode()).hexdigest()[:8]
    return [observation(f"{key}-{suffix}", title,
        "A public response contains a recognizable debug or server error marker. No error-inducing payloads were sent.", severity,
        "Disable production debug output and return generic client error messages. Keep stack traces and query diagnostics in access-controlled server logs.",
        location, "configuration", confidence="pattern")
        for key, title, pattern, severity in patterns if re.search(pattern, text, re.I)]


def extract_client_versions(script_urls, texts, sourcemap_items=()):
    """Extract only exact library versions from CDN URLs, sourcemaps, or bundle banners."""
    found = []
    seen = set()

    def record(name, version, where):
        name = name.strip().lower()
        version = version.strip()
        if not name or not SEMVER_RE.fullmatch(version) or (name, version) in seen:
            return
        seen.add((name, version))
        found.append(("npm", name, version, where))

    cdn_patterns = [
        r"cdn\.jsdelivr\.net/npm/(@?[a-z0-9_.-]+(?:/[a-z0-9_.-]+)?)@([0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?)",
        r"unpkg\.com/(@?[a-z0-9_.-]+(?:/[a-z0-9_.-]+)?)@([0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?)",
        r"cdnjs\.cloudflare\.com/ajax/libs/([a-z0-9_.-]+)/([0-9]+\.[0-9]+\.[0-9]+)/",
    ]
    for u in script_urls:
        for pat in cdn_patterns:
            m = re.search(pat, u, re.I)
            if m:
                pkg = m.group(1)
                if pkg.endswith(".js") and "/" not in pkg:
                    pkg = pkg[:-3]
                record(pkg, m.group(2), u)

    banners = [
        ("jquery", r"jQuery\s+v([0-9]+\.[0-9]+\.[0-9]+)"),
        ("bootstrap", r"Bootstrap\s+v([0-9]+\.[0-9]+\.[0-9]+)"),
        ("lodash", r'''lodash[\s\S]{0,120}?VERSION\s*=\s*["']([0-9]+\.[0-9]+\.[0-9]+)["']'''),
        ("axios", r'''axios\s+v([0-9]+\.[0-9]+\.[0-9]+)'''),
        ("dompurify", r'''DOMPurify\s+([0-9]+\.[0-9]+\.[0-9]+)'''),
        ("marked", r'''marked\s+v([0-9]+\.[0-9]+\.[0-9]+)'''),
        ("handlebars", r'''Handlebars(?:\.VERSION)?\s*[=:]?\s*["']?v?([0-9]+\.[0-9]+\.[0-9]+)'''),
    ]
    for loc, text in texts:
        head = text[:40000]
        for pkg, pat in banners:
            m = re.search(pat, head)
            if m:
                record(pkg, m.group(1), loc)

    for map_url, sources, contents in sourcemap_items:
        for src in sources[:200]:
            if not isinstance(src, str):
                continue
            m = re.search(r"node_modules/\.pnpm/(@?[a-z0-9_+-]+)@([0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?)/", src, re.I)
            if m:
                pkg = m.group(1)
                if pkg.startswith("@") and "+" in pkg:
                    pkg = pkg.replace("+", "/", 1)
                record(pkg, m.group(2), map_url)
        for i, content in enumerate(contents[:60]):
            if not isinstance(content, str) or len(content) > 50_000:
                continue
            src_name = sources[i] if i < len(sources) and isinstance(sources[i], str) else ""
            if src_name.endswith("package.json") and "node_modules/" in src_name:
                try:
                    pkg_json = json.loads(content)
                    if isinstance(pkg_json, dict) and isinstance(pkg_json.get("name"), str) and isinstance(pkg_json.get("version"), str):
                        record(pkg_json["name"], pkg_json["version"], map_url + "#" + src_name)
                except ValueError:
                    continue
    return found


def assessment(checks, mode, source_files=(), *, deep=False):
    out = []
    for key, title, limitation in CATEGORIES:
        related = [c for c in checks if c.get("category") == key and c["status"] != "unknown"]
        if key == "configuration" and mode == "url":
            state = "sampled"
            depth = "Multi-route headers, TLS handshake, DNS & API posture" if deep else "Entry-page response observations"
        elif key == "secrets":
            state, depth = "sampled", ("Expanded bundle, sourcemap & repository secret patterns" if deep else "Credential patterns in downloaded content")
        elif key == "dependencies" and (mode == "repo" or related):
            state = "limited"
            depth = "Exact direct-version advisory matching" if mode == "repo" else "Exact client library / CDN advisory matching"
        elif mode == "repo" and key == "database" and not any(p.endswith((".sql", ".rules", "rules.json")) for p in source_files):
            state, depth = "not_assessed", "No database policy source was sampled"
        elif related:
            state, depth = "review", "Static or unauthenticated response clues; not verified"
            if mode == "url" and key == "database":
                depth = "Public configuration clues; deployed rules not inspected"
            elif mode == "url" and key == "authorization":
                depth = "Sampled unauthenticated /api/* responses and client clues; role/ownership not tested"
            elif key == "rate_limits":
                depth = "Response signals only; enforcement not tested" if mode == "url" else "Source signals only; enforcement not tested"
        elif mode == "repo" and key in ("database", "authorization", "injection", "ssrf", "business_logic", "prompt_injection", "configuration"):
            state, depth = "limited", "Sampled source patterns; no matching finding"
        elif key == "injection" and mode == "url":
            state, depth = "limited", "Sampled browser-code HTML sinks only"
        else:
            state, depth = "not_assessed", "Requires source or controlled tests"
        out.append(dict(id=key, title=title, state=state, depth=depth, limitation=limitation,
                        findings=sum(c["status"] == "fail" for c in related)))
    return out


def csp_findings(policy, location):
    """Assess script policy semantics rather than only header presence."""
    if not policy:
        return []
    directives = {}
    for segment in policy.split(";"):
        tokens = segment.strip().split()
        if tokens and tokens[0].lower() not in directives:
            directives[tokens[0].lower()] = tokens[1:]
    sources = directives.get("script-src-elem", directives.get("script-src", directives.get("default-src")))
    if "sandbox" in directives and "allow-scripts" not in directives["sandbox"]:
        return []
    risks = []
    if sources is None:
        risks.append("No script-src or default-src restriction")
    else:
        nonce = any(v.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for v in sources)
        if "'unsafe-inline'" in sources and not nonce:
            risks.append("Inline scripts allowed without a nonce/hash restriction")
        if any(v in sources for v in ("*", "http:", "https:", "data:")) and not (nonce and "'strict-dynamic'" in sources):
            risks.append("Broad script source allowed")
    # unsafe-eval is governed by script-src/default-src, not script-src-elem.
    eval_sources = directives.get("script-src", directives.get("default-src", []))
    if "'unsafe-eval'" in eval_sources:
        risks.append("String-to-code evaluation allowed")
    if not risks:
        return []
    return [observation("csp-weak", "Content Security Policy permits risky script execution",
        "; ".join(risks) + ". Policy weakness does not prove XSS exists.", "medium",
        "Review CSP in report-only mode first. Restrict script sources, use per-response nonces or hashes where appropriate, and remove unsafe-eval where dependencies permit. Preserve required application behavior.",
        location, "configuration", confidence="review")]


IGNORE_DOC_HOSTS = {
    "www.w3.org", "w3.org", "reactjs.org", "react.dev", "developer.mozilla.org", "mozilla.org",
    "schema.org", "example.com", "www.example.com", "localhost", "127.0.0.1", "github.com",
    "www.npmjs.com", "npmjs.com", "apache.org", "www.apache.org", "opensource.org", "fb.me",
    "rome.tools", "vitejs.dev", "nextjs.org", "webpack.js.org", "tc39.es", "whatwg.org",
}


def classify_external_host(host: str, reg_domain: str) -> tuple[str, str] | None:
    h = host.lower().strip(".")
    if not h or "." not in h or h in IGNORE_DOC_HOSTS or any(h.endswith("." + d) for d in IGNORE_DOC_HOSTS):
        return None
    if h == reg_domain or h.endswith("." + reg_domain):
        return ("First-party host", "Subdomain")
    rules = [
        (".supabase.co", ("Supabase", "Backend / DB")),
        (".supabase.in", ("Supabase", "Backend / DB")),
        (".firebaseio.com", ("Firebase Realtime DB", "Backend / DB")),
        (".firebaseapp.com", ("Firebase", "Backend / DB")),
        ("firestore.googleapis.com", ("Google Firestore", "Backend / DB")),
        ("identitytoolkit.googleapis.com", ("Firebase Auth", "Auth")),
        (".run.app", ("Google Cloud Run", "Cloud API")),
        (".cloudfunctions.net", ("Cloud Functions", "Cloud API")),
        (".railway.app", ("Railway", "Cloud API")),
        (".onrender.com", ("Render", "Cloud API")),
        (".workers.dev", ("Cloudflare Workers", "Edge API")),
        (".pages.dev", ("Cloudflare Pages", "Hosting")),
        (".vercel.app", ("Vercel", "Hosting")),
        (".netlify.app", ("Netlify", "Hosting")),
        (".herokuapp.com", ("Heroku", "Cloud API")),
        (".fly.dev", ("Fly.io", "Cloud API")),
        (".amazonaws.com", ("AWS / S3", "Cloud")),
        (".azurewebsites.net", ("Azure App Service", "Cloud API")),
        ("stripe.com", ("Stripe", "Payments")),
        ("clerk.", ("Clerk", "Auth")),
        (".auth0.com", ("Auth0", "Auth")),
        ("api.openai.com", ("OpenAI", "AI API")),
        ("api.anthropic.com", ("Anthropic", "AI API")),
        ("sentry.io", ("Sentry", "Telemetry")),
        ("posthog.com", ("PostHog", "Analytics")),
        ("googletagmanager.com", ("Google Tag Manager", "Analytics")),
        ("google-analytics.com", ("Google Analytics", "Analytics")),
        ("intercom.io", ("Intercom", "Support")),
        ("mapbox.com", ("Mapbox", "Maps")),
    ]
    for needle, pair in rules:
        if needle in h:
            return pair
    if h.startswith(("api.", "backend.", "graphql.", "auth.", "ws.", "realtime.")):
        return ("External API", "API")
    return None


def extract_js_surface(texts, target_host: str, reg_domain: str):
    """Extract API route provenance, external cloud/service hosts, and per-bundle telemetry."""
    endpoint_sources: dict[str, str] = {}
    external_map: dict[str, dict] = {}
    bundles = []
    api_re = re.compile(r'''["'`](\/(?:api|trpc|graphql|v1|v2)(?:\/[A-Za-z0-9_.:{}-]{1,60})+)["'`?]''')
    url_re = re.compile(r'''https?:\/\/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,24})(?::\d{2,5})?(\/[A-Za-z0-9_./:-]{0,80})?''')

    for location, text in texts:
        short_name = location.rsplit("/", 1)[-1].split("?")[0] or "index.html"
        ep_here = []
        ext_here = []
        for m in api_re.finditer(text):
            ep = m.group(1)
            if re.search(r"\.(?:png|jpe?g|svg|css|m?js|woff2?|ico)$", ep, re.I):
                continue
            if ep not in ep_here:
                ep_here.append(ep)
            if ep not in endpoint_sources:
                line = text.count("\n", 0, m.start()) + 1
                endpoint_sources[ep] = f"{short_name}:{line}"

        for m in url_re.finditer(text):
            host = m.group(1).lower().strip(".")
            if host == target_host.lower():
                continue
            classified = classify_external_host(host, reg_domain)
            if not classified:
                continue
            service, category = classified
            if host not in ext_here:
                ext_here.append(host)
            if host not in external_map:
                line = text.count("\n", 0, m.start()) + 1
                sample_path = (m.group(2) or "/").rstrip(").,;\"'`")
                external_map[host] = {
                    "host": host,
                    "service": service,
                    "category": category,
                    "sample_path": sample_path[:60] or "/",
                    "found_in": f"{short_name}:{line}",
                }

        bundles.append({
            "url": location,
            "name": short_name,
            "bytes": len(text.encode("utf-8", errors="ignore")),
            "api_count": len(ep_here),
            "endpoints": ep_here[:20],
            "external_hosts": ext_here[:20],
        })

    return endpoint_sources, list(external_map.values())[:30], bundles
