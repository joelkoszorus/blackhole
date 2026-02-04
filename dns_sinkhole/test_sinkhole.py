import unittest
from unittest.mock import patch, MagicMock
from io import StringIO
import time
import sys
import os
import requests
from dns import message, rdatatype, rrset, query, exception, name

# Adjust the path to import main from the parent directory
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the main module to access its globals directly
import dns_sinkhole.main as main

class TestDNSSinkhole(unittest.TestCase):

    def setUp(self):
        # Reset global state before each test
        self.reset_global_state()

        # Mock CONFIG for tests
        self.original_config = main.CONFIG.copy()
        main.CONFIG.update({
            'UPSTREAM_DNS': '1.1.1.1',
            'SINKHOLE_IP': '0.0.0.0',
            'BLOCKLIST_URL': 'http://mock-blocklist.com/hosts',
            'DNS_PORT': 53,
            'DNS_HOST': '0.0.0.0',
        })

    def tearDown(self):
        # Restore original CONFIG after each test
        main.CONFIG.update(self.original_config)
        self.reset_global_state()

    def reset_global_state(self):
        # Reset global variables in the main module
        with main.stats_lock:
            main.total_queries = 0
            main.blocked_queries = 0
            main.dns_logs.clear()

        with main.list_lock:
            main.BLOCKLIST.clear()
            main.ALLOWLIST.clear()
            main.DENYLIST.clear()

    @patch('dns_sinkhole.main.query.udp')
    def test_dns_forwarding(self, mock_udp_query):
        # Arrange
        test_domain = "example.com."  # Use absolute name
        test_ip = "93.184.216.34"

        query_msg = message.make_query(test_domain, rdatatype.A)
        query_msg.id = 123
        query_data = query_msg.to_wire()
        client_addr = ('192.168.1.100', 12345)
        
        response_msg = message.make_response(query_msg)
        answer = rrset.from_text(test_domain, 60, 'IN', 'A', test_ip)
        response_msg.answer.append(answer)
        mock_udp_query.return_value = response_msg

        # Act
        response_wire = main.dns_response(query_data, client_addr)
        response_parsed = message.from_wire(response_wire)

        # Assert
        mock_udp_query.assert_called_with(query_msg, main.CONFIG['UPSTREAM_DNS'], timeout=5)
        self.assertEqual(str(response_parsed.question[0].name), test_domain)
        self.assertEqual(str(response_parsed.answer[0][0]), test_ip)
        self.assertEqual(main.total_queries, 1)
        self.assertEqual(main.blocked_queries, 0)

    @patch('dns_sinkhole.main.query.udp')
    def test_dns_blocking_blocklist(self, mock_udp_query):
        # Arrange
        test_domain = "blocked.com."
        main.BLOCKLIST.add("blocked.com") # qname has no trailing dot
        query_msg = message.make_query(test_domain, rdatatype.A)
        query_msg.id = 124
        query_data = query_msg.to_wire()
        client_addr = ('192.168.1.101', 12346)

        # Act
        response_wire = main.dns_response(query_data, client_addr)
        response_parsed = message.from_wire(response_wire)

        # Assert
        mock_udp_query.assert_not_called()
        self.assertEqual(str(response_parsed.question[0].name), test_domain)
        self.assertEqual(str(response_parsed.answer[0][0]), main.CONFIG['SINKHOLE_IP'])
        self.assertEqual(main.total_queries, 1)
        self.assertEqual(main.blocked_queries, 1)

    @patch('dns_sinkhole.main.query.udp')
    def test_dns_blocking_denylist_priority(self, mock_udp_query):
        # Arrange
        test_domain = "denied.com"
        main.BLOCKLIST.add(test_domain)
        main.ALLOWLIST.add(test_domain)
        main.DENYLIST.add(test_domain)
        query_msg = message.make_query(test_domain + ".", rdatatype.A)
        query_msg.id = 125
        query_data = query_msg.to_wire()
        client_addr = ('192.168.1.102', 12347)

        # Act
        response_wire = main.dns_response(query_data, client_addr)
        response_parsed = message.from_wire(response_wire)

        # Assert
        mock_udp_query.assert_not_called()
        self.assertEqual(str(response_parsed.question[0].name), test_domain + '.')
        self.assertEqual(str(response_parsed.answer[0][0]), main.CONFIG['SINKHOLE_IP'])
        self.assertEqual(main.total_queries, 1)
        self.assertEqual(main.blocked_queries, 1)

    @patch('dns_sinkhole.main.query.udp')
    def test_dns_allowing_allowlist_priority(self, mock_udp_query):
        # Arrange
        test_domain = "allowed.com"
        test_domain_abs = test_domain + "."
        main.BLOCKLIST.add(test_domain)
        main.ALLOWLIST.add(test_domain)

        query_msg = message.make_query(test_domain_abs, rdatatype.A)
        query_msg.id = 126
        query_data = query_msg.to_wire()
        client_addr = ('192.168.1.103', 12348)

        test_ip = "1.2.3.4"
        response_msg = message.make_response(query_msg)
        answer = rrset.from_text(test_domain_abs, 60, 'IN', 'A', test_ip)
        response_msg.answer.append(answer)
        mock_udp_query.return_value = response_msg
        
        # Act
        response_wire = main.dns_response(query_data, client_addr)
        response_parsed = message.from_wire(response_wire)

        # Assert
        mock_udp_query.assert_called_with(query_msg, main.CONFIG['UPSTREAM_DNS'], timeout=5)
        self.assertEqual(str(response_parsed.question[0].name), test_domain_abs)
        self.assertEqual(str(response_parsed.answer[0][0]), test_ip)
        self.assertEqual(main.total_queries, 1)
        self.assertEqual(main.blocked_queries, 0)

    @patch('requests.get')
    def test_download_blocklist_success(self, mock_requests_get):
        # Arrange
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.text = """
# This is a comment
127.0.0.1 localhost
0.0.0.0 example.com
0.0.0.0 another.org # Another comment
malicious.net
        """
        mock_requests_get.return_value = mock_response

        # Act
        main.download_blocklist()

        # Assert
        mock_requests_get.assert_called_with(main.CONFIG['BLOCKLIST_URL'], timeout=10)
        expected_blocklist = {"example.com", "another.org", "malicious.net", "localhost"}
        self.assertEqual(main.BLOCKLIST, expected_blocklist)

    @patch('requests.get')
    def test_download_blocklist_http_error(self, mock_requests_get):
        # Arrange
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("404 Not Found")
        mock_requests_get.return_value = mock_response

        # Capture stderr output
        with patch('sys.stderr', new=StringIO()) as fake_err:
            # Act
            main.download_blocklist()
            output = fake_err.getvalue()

        # Assert
        self.assertIn("Error downloading blocklist: 404 Not Found", output)
        self.assertEqual(len(main.BLOCKLIST), 0)

if __name__ == '__main__':
    unittest.main()