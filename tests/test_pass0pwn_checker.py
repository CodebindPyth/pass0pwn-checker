import unittest
from io import StringIO
from unittest import mock
from urllib.error import URLError

import pass0pwn_checker


class Pass0PwnCheckerTests(unittest.TestCase):
    def test_sha1_hash_is_uppercase(self):
        self.assertEqual(
            pass0pwn_checker.sha1_hash("password"),
            "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8",
        )

    def test_parse_pwned_response_finds_count(self):
        suffix = "ABCDE12345"
        response = "FFFFF:1\nABCDE12345:42\nAAAAA:9"
        self.assertEqual(pass0pwn_checker.parse_pwned_response(response, suffix), 42)

    def test_parse_pwned_response_returns_zero_when_not_found(self):
        response = "FFFFF:1\nAAAAA:9"
        self.assertEqual(pass0pwn_checker.parse_pwned_response(response, "ABCDE12345"), 0)

    def test_check_password_exposure_uses_range_api(self):
        expected_url = (
            "https://api.pwnedpasswords.com/range/5BAA6"
        )

        def fake_http_get(url: str) -> str:
            self.assertEqual(url, expected_url)
            return "1E4C9B93F3F0682250B6CF8331B7EE68FD8:123"

        self.assertEqual(
            pass0pwn_checker.check_password_exposure("password", http_get=fake_http_get),
            123,
        )

    def test_ai_dark_web_assessment_levels(self):
        self.assertIn("No dark-web exposure", pass0pwn_checker.ai_dark_web_assessment(0))
        self.assertIn("replace it", pass0pwn_checker.ai_dark_web_assessment(99))
        self.assertIn("High-risk", pass0pwn_checker.ai_dark_web_assessment(100))
        self.assertIn("Critical risk", pass0pwn_checker.ai_dark_web_assessment(10000))

    def test_main_returns_json_error_when_lookup_fails(self):
        with mock.patch("sys.argv", ["pass0pwn_checker.py", "password", "--json"]):
            with mock.patch(
                "pass0pwn_checker.check_password_exposure",
                side_effect=URLError("network down"),
            ):
                with mock.patch("sys.stdout", new_callable=StringIO) as out:
                    with self.assertRaises(SystemExit) as exit_info:
                        pass0pwn_checker.main()
        self.assertEqual(exit_info.exception.code, 1)
        self.assertIn("Unable to check dark-web data", out.getvalue())


if __name__ == "__main__":
    unittest.main()
