"""Offline tests. Browser output and InternetDB are fixtures; IPs are from documentation ranges (RFC 5737)."""
import email
import importlib.util
import io
import json
import os
import re
import tempfile
import unittest
from contextlib import redirect_stdout
from email import policy
from pathlib import Path
from urllib.error import HTTPError

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("shodan_cert", ROOT / "scripts" / "shodan_cert.py")
sc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sc)

# What shodan-hostcheck.js leaves in window.__hp, as JSON.stringify prints it.
HOSTCHECK = {
    "192.0.2.10": {"ip": "192.0.2.10", "honeypot": False, "tags": [], "ports": [5900], "lastSeen": "2026-11-01",
                   "org": "Example Bredband AB", "isp": "Example Bredband AB", "city": "Ort",
                   "hostnames": ["h-10.example.net"], "domains": [], "screenshots": 1},
    "198.51.100.7": {"ip": "198.51.100.7", "honeypot": True, "tags": ["honeypot"], "ports": [102],
                     "org": "Example Hosting", "screenshots": 0},
    "203.0.113.5": {"ip": "203.0.113.5", "honeypot": False, "tags": [], "ports": [102, 502, 2404, 44818],
                    "org": "Amazon.com", "screenshots": 0},
    "192.0.2.99": {"err": "not in Shodan"},
}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp.name) / "out"
        self.downloads = Path(self.tmp.name) / "Downloads"
        self.downloads.mkdir()
        os.environ["SHODAN_CERT_OUT"] = str(self.out)
        (self.downloads / "shodan-192.0.2.10-1.jpg").write_bytes(b"\xff\xd8" + b"x" * 5000)
        self.hp = Path(self.tmp.name) / "hp.json"
        self.hp.write_text(json.dumps(json.dumps(HOSTCHECK)))  # the browser tool often returns a quoted string

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = sc.main(list(argv))
        return code, buf.getvalue()

    def imported(self):
        self.run_cli("import", str(self.hp), "--downloads", str(self.downloads))


class Import(Base):
    def test_import_moves_screenshot_and_flags(self):
        _, out = self.run_cli("import", str(self.hp), "--downloads", str(self.downloads))
        self.assertIn("192.0.2.10  looks real", out)
        self.assertIn("198.51.100.7  HONEYPOT", out)
        self.assertIn("203.0.113.5  DOUBT", out)
        self.assertIn("192.0.2.99  ERROR not in Shodan", out)
        info = json.loads((self.out / "hosts" / "192.0.2.10.json").read_text())
        self.assertEqual(len(info["screenshots"]), 1)
        self.assertFalse((self.downloads / "shodan-192.0.2.10-1.jpg").exists())

    def test_doubts(self):
        doubts = sc.summarise(HOSTCHECK["203.0.113.5"])["doubts"]
        self.assertTrue(any("industrial protocols" in d for d in doubts))
        self.assertTrue(any("cloud" in d for d in doubts))


class Draft(Base):
    def test_inline_image_and_links(self):
        self.imported()
        body = ("Hej!\n\nSökning:\nhttps://www.shodan.io/search?query=port%3A5900&page=1\n\n"
                "**Öppna paneler**\n- 192.0.2.10: VNC utan lösenord.\n  {{host:192.0.2.10}}\n\n"
                "Länk till värden: http://192.0.2.10/\n")
        msg = email.message_from_bytes(bytes(sc.build_draft(body, "cert@cert.se", "Test")), policy=policy.default)
        self.assertEqual(msg["X-Unsent"], "1")
        parts = list(msg.walk())
        html_part = next(p for p in parts if p.get_content_type() == "text/html").get_content()
        images = [p for p in parts if p.get_content_maintype() == "image"]
        self.assertEqual(len(images), 1)
        self.assertIn(f"cid:{images[0]['Content-ID'].strip('<>')}", html_part)
        self.assertIn("<b>Öppna paneler</b>", html_part)
        self.assertIn('href="https://www.shodan.io/host/192.0.2.10"', html_part)
        self.assertNotIn('href="http://192.0.2.10/', html_part)  # never a link to the host itself
        text_part = next(p for p in parts if p.get_content_type() == "text/plain").get_content()
        self.assertIn("https://www.shodan.io/host/192.0.2.10", text_part)
        self.assertNotIn("**", text_part)

    def test_honeypot_refused_even_with_allow(self):
        self.imported()
        with self.assertRaises(SystemExit):
            sc.build_draft("{{host:198.51.100.7}}", "cert@cert.se", "T", allow_doubtful=True)

    def test_doubtful_needs_allow(self):
        self.imported()
        with self.assertRaises(SystemExit):
            sc.build_draft("{{host:203.0.113.5}}", "cert@cert.se", "T")
        sc.build_draft("{{host:203.0.113.5}}", "cert@cert.se", "T", allow_doubtful=True)

    def test_missing_host_check(self):
        with self.assertRaises(SystemExit):
            sc.build_draft("{{host:192.0.2.50}}", "cert@cert.se", "T")


class Self(Base):
    def fake(self, internetdb):
        def http_get(url):
            if url == sc.MYIP:
                return "192.0.2.1\n"
            if internetdb is None:
                raise HTTPError(url, 404, "Not Found", {}, None)
            return json.dumps(internetdb)
        self.real, sc.http_get = sc.http_get, http_get

    def tearDown(self):
        if hasattr(self, "real"):
            sc.http_get = self.real
        super().tearDown()

    def test_not_indexed(self):
        self.fake(None)
        code, out = self.run_cli("self")
        self.assertEqual(code, 0)
        self.assertIn("192.0.2.1: Shodan lists nothing open", out)

    def test_open_port(self):
        self.fake({"ip": "192.0.2.1", "ports": [22, 443], "vulns": [], "tags": [], "hostnames": [], "cpes": []})
        code, out = self.run_cli("self")
        self.assertEqual(code, 1)
        self.assertIn("unexpected open ports: [22, 443]", out)

    def test_allowed_ports_only(self):
        self.fake({"ip": "192.0.2.1", "ports": [443], "vulns": [], "tags": [], "hostnames": [], "cpes": []})
        code, out = self.run_cli("self", "--allow", "443", "--json")
        self.assertEqual(code, 0)
        self.assertFalse(json.loads(out)["found"])

    def test_vulns_count_even_on_allowed_port(self):
        self.fake({"ip": "192.0.2.1", "ports": [443], "vulns": ["CVE-2024-0001"], "tags": [], "hostnames": [],
                   "cpes": []})
        code, _ = self.run_cli("self", "--allow", "443")
        self.assertEqual(code, 1)


class NoFindingsInRepo(unittest.TestCase):
    """The repository is public: no real IP may appear in it, only documentation ranges (RFC 5737)."""

    def test_only_documentation_ips(self):
        doc = ("192.0.2.", "198.51.100.", "203.0.113.")
        public = {"1.1.1.1"}  # Cloudflare's public resolver, the parser check in SKILL.md; never a finding
        for path in ROOT.rglob("*"):
            if ".git" in path.parts or path.suffix not in {".md", ".py", ".txt", ".json", ".js", ".sh"}:
                continue
            for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", path.read_text()):
                self.assertTrue(ip.startswith(doc) or ip in public, f"{ip} in {path.relative_to(ROOT)}")


    def test_only_known_hostnames(self):
        # A finding's reverse DNS or domain (its reverse DNS name) must not land here either.
        # Allowed: the services the skill uses, the CERT, and example domains (RFC 2606).
        tlds = "se|com|net|org|io|nu|lt|dk|no|fi|gov|dev|cloud|app|me|eu|de|uk|info|ru|ai"
        pattern = re.compile(rf"\b(?:[a-z0-9-]+\.)+(?:{tlds})\b", re.I)
        allowed = ("shodan.io", "cert.se", "cisa.gov", "github.com", "api.ipify.org", "google.com", "amazon.com",
                   "example.com", "example.net", "example.org")
        for path in ROOT.rglob("*"):
            if ".git" in path.parts or path.suffix not in {".md", ".py", ".txt", ".json", ".js", ".sh"} \
                    or not path.is_file():
                continue
            for name in pattern.findall(path.read_text()):
                low = name.lower()
                self.assertTrue(any(low == a or low.endswith("." + a) for a in allowed),
                                f"{name} in {path.relative_to(ROOT)}: findings never go in this repository")


class NoPlaceholders(unittest.TestCase):
    """Install commands must work when copied: no <owner>-style placeholders in the README."""

    def test_readme_has_real_urls(self):
        text = (ROOT / "README.md").read_text()
        self.assertNotIn("<owner>", text)
        self.assertIn("github.com/joelhagvall/shodan-cert-report", text)


if __name__ == "__main__":
    unittest.main()
