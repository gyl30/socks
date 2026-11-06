#!/usr/bin/env python3
"""延迟归因回归：origin 或调度开销不能直接判成 TCP 写停顿，真实传输错误仍须失败。"""

import subprocess
import unittest
from unittest.mock import patch

import test_reality_vision_load as load


class RequestLatencyTests(unittest.TestCase):
    def test_origin_delay_is_reported_without_socket_stall_verdict(self):
        probe = {
            "bytes": 1024,
            "appconnect_seconds": 0.06,
            "tls_setup_seconds": 0.059,
            "first_byte_wait_seconds": 0.05,
            "total_seconds": 0.12,
        }
        with patch.object(load, "run_curl_request", return_value=probe) as curl:
            summary = load.measure_request_latency({}, "1.3", 1024)
        self.assertEqual(curl.call_count, load.LATENCY_PROBE_REQUESTS)
        self.assertEqual(summary["appconnect_seconds_median"], 0.06)
        self.assertEqual(summary["first_byte_wait_seconds_median"], 0.05)
        self.assertTrue(summary["appconnect_budget_exceeded"])
        self.assertTrue(summary["first_byte_budget_exceeded"])
        self.assertEqual(len(summary["probes"]), load.LATENCY_PROBE_REQUESTS)

    def test_transfer_failure_is_not_suppressed(self):
        with patch.object(
            load, "run_curl_request", side_effect=RuntimeError("transfer failed")
        ):
            with self.assertRaisesRegex(RuntimeError, "transfer failed"):
                load.measure_request_latency({}, "1.3", 1024)

    def test_byte_count_check_is_preserved(self):
        stack = {"socks_port": 1, "cert_path": "unused.crt", "origin_port": 2}
        result = subprocess.CompletedProcess(
            [],
            0,
            "size_download=9 time_connect=0.001 time_appconnect=0.002 time_starttransfer=0.003 time_total=0.004\n",
            "",
        )
        with patch.object(load.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(RuntimeError, "unexpected bytes"):
                load.run_curl_request(stack, "1.3", 10)


if __name__ == "__main__":
    unittest.main()
