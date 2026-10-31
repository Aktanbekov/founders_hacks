import base64
import json
import unittest
from unittest.mock import AsyncMock, patch

import httpx
import app
from detectors import (
    assessment,
    credential_findings,
    csp_findings,
    extract_client_versions,
    extract_js_surface,
    response_findings,
    source_findings,
)


def jwt(role):
    payload = base64.urlsafe_b64encode(json.dumps({"role": role, "iss": "supabase"}).encode()).decode().rstrip("=")
    return "eyJhbGciOiJIUzI1NiJ9." + payload + "." + "x" * 43


class DetectorTests(unittest.TestCase):
    def test_privileged_jwt_without_using_key(self):
        token = jwt("service_role")
        hits = credential_findings(token, "bundle.js")
        self.assertEqual(hits[0]["severity"], "critical")
        self.assertTrue(hits[0]["cap"])
        self.assertNotIn(token, json.dumps(hits))
        self.assertEqual(hits[0]["confidence"], "pattern")
        self.assertIn("unverified", hits[0]["detail"].lower().replace("not verified", "unverified"))

    def test_public_jwt_and_publishable_not_leaks(self):
        for token in (jwt("anon"), "sb_publishable_" + "x" * 30):
            hits = credential_findings(token, "bundle.js")
            self.assertTrue(hits)
            self.assertTrue(all(h["status"] == "info" for h in hits))
        self.assertEqual(credential_findings("eyJabc.invalidpayload." + "x" * 20, "x"), [])

    def test_supabase_database_and_anthropic_redaction(self):
        values = ["sb_secret_" + "x" * 30, "postgresql://admin:samplePassword@db.example/app", "sk-ant-api03-" + "x" * 40]
        for value in values:
            hits = app.secrets(value, "bundle.js")
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["severity"], "critical")
            self.assertNotIn(value, json.dumps(hits))

    def test_policy_patterns_and_comments(self):
        fixtures = [
            ("firestore.rules", "allow read, write: if true;", "firebase-open-write"),
            ("database.rules.json", '{"rules":{".write":true}}', "firebase-open-write"),
            ("migration.sql", "ALTER TABLE public.profiles DISABLE ROW LEVEL SECURITY;", "rls-disabled"),
            ("migration.sql", "CREATE POLICY x ON profiles FOR ALL TO anon USING (true);", "rls-open-write"),
        ]
        for path, text, key in fixtures:
            self.assertTrue(any(h["id"].startswith(key) for h in source_findings(text, path)))
        self.assertEqual(source_findings("-- ALTER TABLE users DISABLE ROW LEVEL SECURITY;", "x.sql"), [])
        self.assertEqual(source_findings("// allow write: if true;", "firestore.rules"), [])
        self.assertEqual(source_findings("allow write: if request.auth.uid == userId;", "firestore.rules"), [])

    def test_ci_workflow_and_dockerfile_detectors(self):
        wf = "on: pull_request_target\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - run: echo ${{ github.event.issue.title }}"
        hits = source_findings(wf, ".github/workflows/ci.yml")
        self.assertTrue(any(h["id"].startswith("ci-pr-target") for h in hits))
        self.assertTrue(any(h["id"].startswith("ci-script-inject") for h in hits))
        docker_hits = source_findings("FROM node:20\nENV STRIPE_SECRET_KEY=placeholder\n", "Dockerfile")
        self.assertTrue(any(h["id"].startswith("docker-secret") for h in docker_hits))

    def test_dangerous_source_patterns_require_review(self):
        fixtures = [
            ('import jwt\nx=jwt.decode(token, options={"verify_signature": False})', "jwt-no-verify"),
            ('requests.get(request.args.get("url"))', "ssrf-input"),
            ("amount: req.body.amount", "payment-input"),
            ('role: "system", content: req.body.prompt', "prompt-system"),
            ("DEBUG = True", "debug"),
            ("div.innerHTML = userInput", "dom-html"),
        ]
        for text, key in fixtures:
            hits = source_findings(text, "server.ts")
            self.assertTrue(any(h["id"].startswith(key) and h["confidence"] == "review" for h in hits), key)
        self.assertFalse(any(h["category"] == "ssrf" for h in source_findings("fetch(req.query.url)", "bundle.js", public=True)))
        self.assertEqual(source_findings("requests.get(validated_url)", "server.py"), [])

    def test_client_version_extraction(self):
        urls = [
            "https://cdn.jsdelivr.net/npm/lodash@4.17.15/lodash.min.js",
            "https://unpkg.com/@supabase/supabase-js@2.39.0/dist/umd/supabase.js",
        ]
        texts = [("https://example.com/vendor.js", "/*! jQuery v3.4.1 | (c) JS Foundation */")]
        maps = [
            (
                "https://example.com/app.js.map",
                ["../../node_modules/.pnpm/axios@0.21.1/node_modules/axios/index.js", "../node_modules/marked/package.json"],
                ["module.exports = {}", '{"name": "marked", "version": "4.0.10"}'],
            )
        ]
        extracted = extract_client_versions(urls, texts, maps)
        by_name = {name: ver for _, name, ver, _ in extracted}
        self.assertEqual(by_name["lodash"], "4.17.15")
        self.assertEqual(by_name["@supabase/supabase-js"], "2.39.0")
        self.assertEqual(by_name["jquery"], "3.4.1")
        self.assertEqual(by_name["axios"], "0.21.1")
        self.assertEqual(by_name["marked"], "4.0.10")

    def test_response_error_markers(self):
        hits = response_findings("PrismaClientKnownRequestError: Invalid invocation", "https://example.com/api/users")
        self.assertTrue(any(h["id"].startswith("database-error") for h in hits))

    def test_auth_clue_not_vulnerability(self):
        hits = source_findings('localStorage.getItem("isAdmin")', "bundle.js", public=True)
        self.assertEqual(hits[0]["status"], "info")
        self.assertEqual(hits[0]["category"], "authorization")

    def test_coverage_and_priority(self):
        data = app.result("https://example.com", app.secrets("sb_secret_" + "x" * 30, "bundle.js") + [app.check("csp", "CSP", "fail", "missing", "medium")])
        self.assertEqual(data["findings"][0]["severity"], "critical")
        categories = {c["id"]: c for c in data["assessment"]}
        self.assertEqual(len(categories), 10)
        self.assertEqual(categories["authorization"]["state"], "not_assessed")
        self.assertTrue(data["partial"])

    def test_framework_sink_is_not_xss_finding(self):
        generic = source_findings("node.innerHTML = html", "bundle.js", public=True)
        self.assertEqual(generic[0]["status"], "info")
        direct = source_findings("node.innerHTML = location.hash", "bundle.js", public=True)
        self.assertEqual(direct[0]["status"], "fail")
        self.assertEqual(assessment([app.check("cve", "CVE", "unknown", "unavailable")], "url")[8]["state"], "not_assessed")

    def test_csp_semantics(self):
        self.assertTrue(csp_findings("script-src 'self' 'unsafe-inline' 'unsafe-eval'", "x"))
        self.assertFalse(csp_findings("script-src 'nonce-abc' 'strict-dynamic' https: 'unsafe-inline'", "x"))
        self.assertFalse(csp_findings("default-src 'none'", "x"))
        self.assertTrue(csp_findings("frame-ancestors 'none'", "x"))
        self.assertFalse(csp_findings("sandbox; frame-ancestors 'none'", "x"))

    def test_duplicate_secret_penalty_once(self):
        key = "sb_secret_" + "x" * 30
        hits = app.secrets(key, "one.js") + app.secrets(key, "two.js")
        data = app.result("https://example.com", hits)
        self.assertEqual(len(data["findings"]), 1)
        self.assertEqual(data["score"], 75)

    def test_extract_js_surface_provenance_and_external_hosts(self):
        texts = [
            ("https://www.example.com/", "<html><script src='/assets/index-123.js'></script></html>"),
            (
                "https://www.example.com/assets/index-123.js",
                'const ns="http://www.w3.org/2000/svg";\n'
                'const db="https://abcxyz.supabase.co/rest/v1";\n'
                'fetch("/api/v1/questions");\n'
                'fetch("https://js.stripe.com/v3/");',
            ),
        ]
        ep_sources, ext_services, bundles = extract_js_surface(texts, "www.example.com", "example.com")
        self.assertEqual(ep_sources["/api/v1/questions"], "index-123.js:3")
        hosts = {s["host"]: s for s in ext_services}
        self.assertIn("abcxyz.supabase.co", hosts)
        self.assertEqual(hosts["abcxyz.supabase.co"]["service"], "Supabase")
        self.assertEqual(hosts["abcxyz.supabase.co"]["found_in"], "index-123.js:2")
        self.assertIn("js.stripe.com", hosts)
        self.assertNotIn("www.w3.org", hosts)
        self.assertEqual(bundles[1]["name"], "index-123.js")
        self.assertEqual(bundles[1]["api_count"], 1)


class ExpandedScanTests(unittest.IsolatedAsyncioTestCase):
    async def test_module_and_sourcemap_secrets_bounded_and_distinct(self):
        f = app.Fetcher(spacing=0.0)
        await f.client.aclose()
        token = jwt("service_role")
        seen = []
        headers = {
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "Strict-Transport-Security": "max-age=99",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "camera=()",
        }

        def handler(req):
            seen.append(req)
            self.assertNotIn("authorization", req.headers)
            self.assertNotIn("apikey", req.headers)
            self.assertEqual(req.headers.get("cookie"), "")
            if req.headers.get("host") == "crt.sh":
                return httpx.Response(200, json=[])
            if req.url.scheme == "http":
                return httpx.Response(301, headers={"location": "https://public.example/"})
            if req.url.path == "/":
                return httpx.Response(200, headers=headers, text='<script src="/app.js"></script><script src="/second.js"></script>')
            if req.url.path == "/app.js":
                return httpx.Response(200, text='import("./child.js");\n//# sourceMappingURL=app.js.map')
            if req.url.path == "/second.js":
                return httpx.Response(200, text="//# sourceMappingURL=missing.js.map")
            if req.url.path == "/child.js":
                return httpx.Response(200, text='const secret="' + token + '";')
            if req.url.path == "/app.js.map":
                return httpx.Response(200, json={"version": 3, "sources": ["source.ts"], "sourcesContent": ['const secret="' + token + '";']})
            return httpx.Response(404)

        f.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

        async def emit(e):
            pass

        with patch.object(app, "Fetcher", return_value=f), patch.object(app, "public_ip", AsyncMock(return_value="93.184.216.34")):
            res = await app.scan_url("https://public.example/", emit)
        hits = [c for c in res["findings"] if "service_role" in c["title"]]
        self.assertEqual(len(hits), 1)
        # First sourcemap (info) is preserved even when second sourcemap 404s.
        sourcemaps = [c for c in res["checks"] if c["id"].startswith("sourcemap-")]
        self.assertEqual(len(sourcemaps), 2)
        self.assertIn("info", {c["status"] for c in sourcemaps})
        self.assertNotIn(token, json.dumps(res))
        self.assertTrue(any(r.url.path == "/child.js" for r in seen))
        self.assertLessEqual(len(seen), 30)

    async def test_repository_policy_and_demon_workflows_selected(self):
        f = app.Fetcher(max_requests=app.DEMON_MAX_REQUESTS, spacing=0.0)
        await f.client.aclose()

        def handler(req):
            path = req.url.path
            if path == "/repos/owner/repo":
                return httpx.Response(200, json={"default_branch": "main"})
            if "/git/trees/" in path:
                return httpx.Response(
                    200,
                    json={
                        "tree": [
                            {"path": "firestore.rules", "type": "blob", "size": 100},
                            {"path": "supabase/migration.sql", "type": "blob", "size": 100},
                            {"path": ".github/workflows/ci.yml", "type": "blob", "size": 120},
                        ]
                    },
                )
            if path.endswith("firestore.rules"):
                return httpx.Response(200, text="allow write: if true;")
            if path.endswith("migration.sql"):
                return httpx.Response(200, text="ALTER TABLE public.users DISABLE ROW LEVEL SECURITY;")
            if path.endswith("ci.yml"):
                return httpx.Response(200, text="on: push\njobs:\n  b:\n    steps:\n      - run: echo ${{ github.event.issue.title }}")
            return httpx.Response(404)

        f.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

        async def emit(e):
            pass

        with patch.object(app, "Fetcher", return_value=f), patch.object(app, "public_ip", AsyncMock(return_value="93.184.216.34")):
            data = await app.scan_repo("https://github.com/owner/repo", emit, mode="demon")
        self.assertEqual(len([h for h in data["findings"] if h["category"] == "database"]), 2)
        self.assertTrue(any(h["id"].startswith("ci-script-inject") for h in data["findings"]))
