import unittest

from domains.onehosts.onehosts import extract_sld, extract_tld


class DomainExtractionTests(unittest.TestCase):
    def test_extract_sld_and_tld_preserves_subdomains(self):
        cases = [
            ("example.com", "example", "com"),
            ("mail.example.com", "mail.example", "com"),
            ("api.internal.example.com", "api.internal.example", "com"),
            ("localhost", "localhost", "localhost"),
            (".example.com", "example", "com"),
            ("example.com.", "example", "com"),
            ("a.b.c.d.example.co.uk", "a.b.c.d.example.co", "uk"),
        ]

        for domain, expected_sld, expected_tld in cases:
            with self.subTest(domain=domain):
                self.assertEqual(extract_sld(domain), expected_sld)
                self.assertEqual(extract_tld(domain), expected_tld)

    def test_extract_empty_or_whitespace_domain_returns_empty(self):
        for value in ("", "   ", "."):
            with self.subTest(value=value):
                self.assertEqual(extract_sld(value), "")
                self.assertEqual(extract_tld(value), "")


if __name__ == "__main__":
    unittest.main()