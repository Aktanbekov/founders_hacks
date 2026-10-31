import unittest
import httpx
import app


class CatUITests(unittest.IsolatedAsyncioTestCase):
    async def test_images_served_without_exposing_workspace(self):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app.app), base_url="http://test") as client:
            for image in ("easy-cat.jpg", "demon-cat.jpg", "running-cat.jpg"):
                response = await client.get("/assets/" + image)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.headers["content-type"], "image/jpeg")
                self.assertTrue(response.content.startswith(b"\xff\xd8"))
            self.assertEqual((await client.get("/assets/../app.py")).status_code, 404)

    async def test_synthetic_demo_and_docker_routes_removed(self):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app.app), base_url="http://test") as client:
            home = await client.get("/")
            self.assertEqual(home.status_code, 200)
            self.assertNotIn("SYNTHETIC LAB", home.text)
            self.assertNotIn("demo=1", home.text)
            self.assertNotIn("altovisas", home.text.lower())
            for legacy_route in ("/engines", "/jobs", "/lab/cookies/status", "/lab/records/demo-bob"):
                self.assertEqual((await client.get(legacy_route)).status_code, 404)
