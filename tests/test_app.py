import gzip
import json
import unittest
from unittest.mock import AsyncMock, patch

import httpx
import app


class Tests(unittest.IsolatedAsyncioTestCase):
    async def test_private_addresses_blocked(self):
        for host in ("127.0.0.1", "::1", "10.0.0.1", "169.254.169.254"):
            with self.assertRaises(ValueError):
                await app.public_ip(host)

    async def test_redirect_revalidated(self):
        f = app.Fetcher()

        async def resolve(host):
            if host == "private.example":
                raise ValueError("blocked private destination")
            return "93.184.216.34"

        def handler(request):
            return httpx.Response(302, headers={"location": "http://private.example/"})

        await f.client.aclose()
        f.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            with patch.object(app, "public_ip", side_effect=resolve):
                with self.assertRaisesRegex(ValueError, "blocked"):
                    await f.get("https://public.example")
        finally:
            await f.close()

    async def test_pinning_and_budget(self):
        seen = []

        def handler(request):
            seen.append(request)
            return httpx.Response(200, text="ok")

        f = app.Fetcher()
        await f.client.aclose()
        f.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            with patch.object(app, "public_ip", AsyncMock(return_value="93.184.216.34")):
                await f.get("https://public.example/a")
            self.assertEqual(seen[0].url.host, "93.184.216.34")
            self.assertEqual(seen[0].headers["host"], "public.example")
            self.assertEqual(seen[0].extensions["sni_hostname"], "public.example")
            f.count = 30
            with self.assertRaisesRegex(ValueError, "budget"):
                await f.get("https://public.example")
        finally:
            await f.close()

    async def test_compressed_response_decoded_once(self):
        f = app.Fetcher()
        await f.client.aclose()
        f.client = httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda r: httpx.Response(
                    200, headers={"content-encoding": "gzip"}, content=gzip.compress(b"<html>compressed site</html>")
                )
            )
        )
        try:
            with patch.object(app, "public_ip", AsyncMock(return_value="93.184.216.34")):
                r = await f.get("https://public.example")
            self.assertEqual(r.text, "<html>compressed site</html>")
            self.assertNotIn("content-encoding", r.headers)
        finally:
            await f.close()

    async def test_body_limit(self):
        f = app.Fetcher()
        await f.client.aclose()
        f.client = httpx.AsyncClient(
            transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b"a" * (app.MAX_BYTES + 1)))
        )
        try:
            with patch.object(app, "public_ip", AsyncMock(return_value="93.184.216.34")):
                r = await f.get("https://public.example")
            self.assertEqual(len(r.content), app.MAX_BYTES)
            self.assertTrue(r.extensions["truncated"])
        finally:
            await f.close()

    async def test_scan_soft_404_and_public_cors(self):
        f = app.Fetcher()
        await f.client.aclose()
        headers = {
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "camera=()",
            "Access-Control-Allow-Origin": "*",
        }

        def handler(req):
            if req.headers.get("host") == "crt.sh":
                return httpx.Response(200, json=[])
            if req.url.scheme == "http":
                return httpx.Response(301, headers={"location": "https://public.example/"})
            return httpx.Response(200, headers=headers, text="<html>A single page app fallback</html>")

        f.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        events = []

        async def emit(e):
            events.append(e)

        with patch.object(app, "Fetcher", return_value=f), patch.object(app, "public_ip", AsyncMock(return_value="93.184.216.34")):
            data = await app.scan_url("https://public.example/", emit, mode="easy")
        self.assertFalse(data["findings"])
        self.assertFalse(data["clickjack_ok"])
        self.assertTrue(data["partial"])
        self.assertLessEqual(data["requests"], 30)
        self.assertTrue(events)

    async def test_demon_mode_works_on_any_public_site_with_deep_checks(self):
        f = app.Fetcher(max_requests=app.DEMON_MAX_REQUESTS, spacing=0.0)
        await f.client.aclose()
        root_headers = {
            "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "camera=()",
        }

        def handler(req):
            host = req.headers.get("host", "")
            path = req.url.path
            if host == "cloudflare-dns.com":
                qname = req.url.params.get("name", "")
                qtype = req.url.params.get("type", "")
                if qname == "_dmarc.arbitrary-startup.io" and qtype == "TXT":
                    return httpx.Response(200, json={"Status": 3, "Answer": []})
                if qname == "arbitrary-startup.io" and qtype == "TXT":
                    return httpx.Response(
                        200,
                        json={
                            "Status": 0,
                            "Answer": [
                                {"type": 16, "data": '"v=spf1 include:_spf.google.com ~all"'},
                                {"type": 16, "data": '"vercel-domain-verification=vc123456"'},
                            ],
                        },
                    )
                if qname == "arbitrary-startup.io" and qtype == "NS":
                    return httpx.Response(200, json={"Status": 0, "Answer": [{"type": 2, "data": "ns1.cloudflare.com."}]})
                if qname == "arbitrary-startup.io" and qtype == "MX":
                    return httpx.Response(200, json={"Status": 0, "Answer": [{"type": 15, "data": "10 mx.google.com."}]})
                if qname == "old.arbitrary-startup.io" and qtype == "A":
                    return httpx.Response(
                        200,
                        json={"Status": 3, "Answer": [{"type": 5, "data": "stale-app.herokuapp.com."}]},
                    )
                if qname == "staging.arbitrary-startup.io" and qtype == "A":
                    return httpx.Response(200, json={"Status": 0, "Answer": [{"type": 1, "data": "93.184.216.35"}]})
                return httpx.Response(200, json={"Status": 0, "Answer": []})
            if host == "ipwho.is":
                return httpx.Response(
                    200,
                    json={
                        "success": True,
                        "city": "San Francisco",
                        "region": "California",
                        "country": "United States",
                        "connection": {"asn": 13335, "org": "Cloudflare, Inc.", "isp": "Cloudflare"},
                    },
                )
            if host == "crt.sh":
                return httpx.Response(200, json=[{"name_value": "staging.arbitrary-startup.io"}])
            if host == "api.certspotter.com":
                return httpx.Response(200, json=[{"dns_names": ["old.arbitrary-startup.io"]}])
            if host == "api.hackertarget.com":
                return httpx.Response(200, text="api.arbitrary-startup.io,93.184.216.36\n")
            if host == "api.github.com":
                return httpx.Response(200, json=[{"ghsa_id": "GHSA-lodash-test", "severity": "high", "summary": "Prototype pollution"}])
            if req.url.scheme == "http":
                return httpx.Response(301, headers={"location": "https://www.arbitrary-startup.io/"})
            if path == "/":
                html = (
                    '<html><a href="/pricing">Pricing</a>'
                    '<script src="https://cdn.jsdelivr.net/npm/lodash@4.17.15/lodash.min.js"></script>'
                    '<script src="/app.js"></script></html>'
                )
                return httpx.Response(200, headers=root_headers, text=html)
            if path == "/app.js":
                return httpx.Response(
                    200,
                    text='const sb = "https://xyzcompany.supabase.co/rest/v1";\nfetch("/api/v1/stats");',
                )
            if path == "/api/v1/stats":
                return httpx.Response(200, headers={"content-type": "application/json"}, text='{"users": 42}')
            if path == "/pricing":
                # Sub-route drops CSP header -> header drift
                return httpx.Response(200, headers={"content-type": "text/html"}, text="<html>Pricing</html>")
            if path == "/.DS_Store":
                return httpx.Response(200, content=b"\x00\x00\x00\x01Bud1directorydata")
            return httpx.Response(404)

        f.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        fake_tls = (
            [
                app.check("tls-protocol", "TLS protocol & cipher", "pass", "Negotiated TLSv1.3 (TLS_AES_128_GCM_SHA256)."),
                app.check("tls-cert", "TLS certificate validity", "pass", "Valid certificate issued by Let's Encrypt; expires in 68 days."),
            ],
            {
                "protocol": "TLSv1.3",
                "cipher": "TLS_AES_128_GCM_SHA256",
                "bits": 128,
                "issuer": "Let's Encrypt",
                "subject": "www.arbitrary-startup.io",
                "days_remaining": 68,
                "sans": ["www.arbitrary-startup.io"],
            },
        )
        events = []

        async def emit(e):
            events.append(e)

        with (
            patch.object(app, "Fetcher", return_value=f),
            patch.object(app, "public_ip", AsyncMock(return_value="93.184.216.34")),
            patch.object(app, "inspect_tls", AsyncMock(return_value=fake_tls)),
        ):
            data = await app.scan_url("https://www.arbitrary-startup.io/", emit, mode="demon")

        finding_ids = {c["id"] for c in data["findings"]}
        self.assertIn("dns-dmarc", finding_ids)
        self.assertIn("exposure/.ds_store", finding_ids)
        self.assertIn("api-surface-open", finding_ids)
        self.assertIn("route-header-drift", finding_ids)
        self.assertIn("dep-lodash-GHSA-lodash-test", finding_ids)
        self.assertTrue(any(fid.startswith("dangling-") for fid in finding_ids))
        self.assertEqual(data["scan_mode"], "demon")
        self.assertIn("staging.arbitrary-startup.io", data["subdomains"])
        self.assertIn("api.arbitrary-startup.io", data["subdomains"])

        recon = data["recon"]
        self.assertIn("San Francisco", recon["infrastructure"]["location"])
        self.assertEqual(recon["infrastructure"]["org"], "Cloudflare, Inc.")
        self.assertEqual(recon["tls"]["protocol"], "TLSv1.3")
        self.assertEqual(recon["dns"]["domain"], "arbitrary-startup.io")
        self.assertIn("ns1.cloudflare.com", recon["dns"]["ns_records"])
        self.assertTrue(any("Vercel" in t for t in recon["dns"]["txt_verifications"]))
        api_route = next(r for r in recon["routes"] if r["path"] == "/api/v1/stats")
        self.assertEqual(api_route["found_in"], "app.js:2")
        self.assertIn("OPEN JSON", api_route["verdict"])
        self.assertTrue(any(s["service"] == "Supabase" for s in recon["external_services"]))

        prompt = data["fix_prompt"]
        self.assertIn("Environment & Recon Context", prompt)
        self.assertIn("/api/v1/stats", prompt)
        self.assertIn("app.js:2", prompt)
        self.assertIn("_dmarc.arbitrary-startup.io", prompt)
        self.assertIn("rg -n", prompt)
        self.assertIn("dig +short TXT _dmarc.arbitrary-startup.io", prompt)

    async def test_api_and_stream_require_consent_and_have_no_demo_mode(self):
        f = app.Fetcher(spacing=0.0)
        await f.client.aclose()
        f.client = httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda r: httpx.Response(200, json=[])
                if r.headers.get("host") == "crt.sh"
                else httpx.Response(200, text="<html>ok</html>")
            )
        )
        try:
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app.app), base_url="http://test") as c:
                self.assertEqual((await c.get("/")).status_code, 200)
                self.assertEqual((await c.get("/health")).status_code, 200)
                self.assertEqual((await c.post("/scan", json={"target": "https://example.com"})).status_code, 400)
                r = await c.post("/scan", json={"target": "https://127.0.0.1", "consent": True})
                self.assertEqual(r.status_code, 422)
                with patch.object(app, "Fetcher", return_value=f), patch.object(app, "public_ip", AsyncMock(return_value="93.184.216.34")):
                    r = await c.post("/scan/stream", json={"target": "https://any-domain.example", "consent": True, "mode": "easy"})
                self.assertEqual(r.status_code, 200)
                events = [json.loads(line) for line in r.text.splitlines()]
                self.assertEqual(events[-1]["type"], "result")
                self.assertNotIn("demo", events[-1]["result"])
        finally:
            await f.close()

    def test_fingerprint_ignores_english_prose(self):
        self.assertEqual(app.fingerprint("<html><h1>Express Visa Processing Services</h1></html>", {"server": "Vercel"}), "Unknown stack")
        self.assertEqual(app.fingerprint("<html></html>", {"x-powered-by": "Express"}), "Express")
        self.assertEqual(app.fingerprint('<script src="/_next/static/chunks/main.js"></script>', {}), "Next.js")

    def test_secrets_redacted_and_multiple_keys_captured(self):
        key1 = "sk-proj-" + "a" * 40
        key2 = "sk-proj-" + "b" * 40
        hits = app.secrets(key1 + " " + key2, "bundle.js")
        self.assertEqual(len(hits), 2)
        self.assertNotIn(key1, json.dumps(hits))
        self.assertNotIn(key2, json.dumps(hits))
        self.assertTrue(all(h["cap"] for h in hits))
        self.assertFalse(any(c["status"] == "fail" for c in app.secrets("sb_publishable_abc firebase supabase", "x")))

    async def test_dependency_advisory_filter(self):
        class Fake:
            count = 0
            max_requests = 30

            async def get(self, url, redirects=0, **kwargs):
                self.count += 1
                return httpx.Response(
                    200,
                    json=[
                        {"ghsa_id": "GHSA-test", "severity": "high", "summary": "Test vulnerability"},
                        {"ghsa_id": "GHSA-low", "severity": "low"},
                        {"ghsa_id": "GHSA-withdrawn", "severity": "critical", "withdrawn_at": "2026-01-01"},
                    ],
                )

        checks = []

        async def add(c):
            checks.append(c)

        await app.dependency_checks(Fake(), [("requirements.txt", "fastapi==0.100.0")], add)
        self.assertEqual(len([c for c in checks if c["status"] == "fail"]), 1)
        self.assertEqual(checks[-1]["status"], "info")

    def test_direct_dependency_resolution(self):
        lock = {
            "packages": {
                "": {"dependencies": {"react": "^18.0.0"}},
                "node_modules/react": {"version": "18.0.0"},
                "node_modules/transitive": {"version": "1.0.0"},
            }
        }
        deps, unknown = app.direct_dependencies(
            [("package-lock.json", json.dumps(lock)), ("requirements.txt", "fastapi==0.100.0\nhttpx>=0.28")]
        )
        self.assertEqual(len(deps), 2)
        self.assertEqual(unknown, 1)
        self.assertNotIn("transitive", str(deps))

    def test_grade_cap(self):
        c = app.check("x", "exposure", "fail", "observed", "high", "fix", "x", True)
        data = app.result("https://example.com", [c])
        self.assertEqual(data["grade"], "C")
        self.assertEqual(data["score"], 79)

    def test_invalid_targets(self):
        for target in ("https://user:password@example.com", "https://example.com:8080", "https://"):
            with self.assertRaises(ValueError):
                app.normalize(target)


if __name__ == "__main__":
    unittest.main()
