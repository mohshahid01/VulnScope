import unittest

from core.target_validator import (
    validate_target,
    TargetValidationError
)


class TestTargetValidator(unittest.TestCase):

    def test_localhost(self):

        target = validate_target(
            "http://localhost"
        )

        self.assertEqual(
            target.hostname,
            "localhost"
        )

        self.assertEqual(
            target.port,
            80
        )

    def test_https(self):

        target = validate_target(
            "https://localhost"
        )

        self.assertEqual(
            target.port,
            443
        )

    def test_custom_port(self):

        target = validate_target(
            "http://localhost:5000"
        )

        self.assertEqual(
            target.port,
            5000
        )

    def test_invalid_scheme(self):

        with self.assertRaises(
            TargetValidationError
        ):

            validate_target(
                "ftp://localhost"
            )

    def test_credentials_rejected(self):

        with self.assertRaises(
            TargetValidationError
        ):

            validate_target(
                "http://user:password@localhost"
            )


if __name__ == "__main__":

    unittest.main()
