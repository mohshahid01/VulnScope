import unittest

from core.target_validator import (
    validate_target,
    TargetValidationError
)


class TargetValidationTests(unittest.TestCase):

    def test_localhost_http(self):

        target = validate_target(
            "http://localhost:8000"
        )

        self.assertEqual(
            target.scheme,
            "http"
        )

        self.assertEqual(
            target.port,
            8000
        )

        self.assertTrue(
            len(target.ips) > 0
        )

    def test_localhost_https(self):

        target = validate_target(
            "https://localhost"
        )

        self.assertEqual(
            target.scheme,
            "https"
        )

        self.assertEqual(
            target.port,
            443
        )

    def test_unlisted_hostname_rejected(self):

        with self.assertRaises(TargetValidationError):

            validate_target(
                "https://example.com"
            )

    def test_unsupported_scheme_rejected(self):

        with self.assertRaises(TargetValidationError):

            validate_target(
                "ftp://localhost"
            )

    def test_unconfigured_port_rejected(self):

        with self.assertRaises(TargetValidationError):

            validate_target(
                "http://localhost:9999"
            )


if __name__ == "__main__":
    unittest.main()
