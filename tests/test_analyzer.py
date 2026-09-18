import unittest
from unittest.mock import patch, MagicMock
from src.network import inspect_dns


class TestNetworkRecon(unittest.TestCase):

    @patch("dns.resolver.resolve")
    def test_inspect_dns_success(self, mock_resolve):
        mock_record = MagicMock()
        mock_record.to_text.return_value = "192.0.2.1"
        mock_resolve.return_value = [mock_record]

        result = inspect_dns("example.com")
        self.assertIn("A", result)
        self.assertEqual(result["A"], ["192.0.2.1"])

    @patch("dns.resolver.resolve", side_effect=Exception("Timeout"))
    def test_inspect_dns_failure_handled(self, mock_resolve):
        result = inspect_dns("invalid-domain.test")
        self.assertEqual(result["A"], [])


if __name__ == "__main__":
    unittest.main()