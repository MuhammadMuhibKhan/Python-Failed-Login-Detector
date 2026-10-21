"""
Automated tests for failed_login_detector.py

Run with:   python tests.py        (or: py tests.py on Windows)
Uses only Python's built-in unittest module. All data is fictional.
"""

import tempfile
import unittest
from pathlib import Path

import failed_login_detector as fld


def make_records(ip, usernames, status="FAILED"):
    """Build a list of fictional login records for one IP address."""
    return [{"ip": ip, "username": name, "status": status} for name in usernames]


class TestNormalRecords(unittest.TestCase):
    def test_mixed_records_are_counted_correctly(self):
        records = [
            {"ip": "192.0.2.10", "username": "alice", "status": "SUCCESS"},
            {"ip": "192.0.2.11", "username": "bob", "status": "FAILED"},
            {"ip": "192.0.2.11", "username": "bob", "status": "SUCCESS"},
        ]
        results = fld.analyze_logins(records)
        self.assertEqual(results["total_records"], 3)
        self.assertEqual(results["valid_records"], 3)
        self.assertEqual(results["successful_logins"], 2)
        self.assertEqual(results["failed_attempts"], 1)
        self.assertEqual(results["flagged"], {})

    def test_failures_are_counted_per_ip(self):
        records = (make_records("192.0.2.1", ["a", "a"])
                   + make_records("192.0.2.2", ["b"]))
        results = fld.analyze_logins(records)
        self.assertEqual(results["failures_by_ip"]["192.0.2.1"], 2)
        self.assertEqual(results["failures_by_ip"]["192.0.2.2"], 1)

    def test_failures_from_different_ips_are_not_combined(self):
        # 3 + 3 failures from two IPs must not add up to a flag.
        records = (make_records("192.0.2.1", ["admin"] * 3)
                   + make_records("192.0.2.2", ["admin"] * 3))
        self.assertEqual(fld.analyze_logins(records)["flagged"], {})

    def test_status_and_username_are_normalized(self):
        records = [
            {"ip": "192.0.2.1", "username": "Admin", "status": "failed"},
            {"ip": "192.0.2.1", "username": " admin ", "status": " FAILED "},
        ]
        results = fld.analyze_logins(records)
        self.assertEqual(results["failed_attempts"], 2)
        self.assertEqual(len(results["usernames_by_ip"]["192.0.2.1"]), 1)


class TestRepeatedFailedAttempts(unittest.TestCase):
    def test_five_failures_are_flagged(self):
        records = make_records("203.0.113.25", ["admin"] * 5)
        flagged = fld.analyze_logins(records)["flagged"]
        self.assertIn("203.0.113.25", flagged)
        self.assertEqual(flagged["203.0.113.25"]["failed_attempts"], 5)
        self.assertEqual(flagged["203.0.113.25"]["reasons"],
                         ["Repeated failed logins"])

    def test_four_failures_are_not_flagged(self):
        records = make_records("203.0.113.90", ["bob"] * 4)
        self.assertEqual(fld.analyze_logins(records)["flagged"], {})

    def test_more_than_five_failures_are_flagged(self):
        records = make_records("203.0.113.25", ["admin"] * 8)
        flagged = fld.analyze_logins(records)["flagged"]
        self.assertEqual(flagged["203.0.113.25"]["failed_attempts"], 8)


class TestMultipleUsernames(unittest.TestCase):
    def test_three_usernames_are_flagged(self):
        records = make_records("198.51.100.77", ["admin", "root", "guest"])
        flagged = fld.analyze_logins(records)["flagged"]
        self.assertIn("198.51.100.77", flagged)
        self.assertEqual(flagged["198.51.100.77"]["reasons"],
                         ["Multiple usernames targeted"])

    def test_two_usernames_are_not_flagged(self):
        records = make_records("198.51.100.77", ["admin", "root"])
        self.assertEqual(fld.analyze_logins(records)["flagged"], {})

    def test_both_rules_can_trigger_together(self):
        records = make_records("203.0.113.200",
                               ["admin", "root", "test", "oracle", "admin", "root"])
        flagged = fld.analyze_logins(records)["flagged"]["203.0.113.200"]
        self.assertEqual(flagged["reasons"],
                         ["Repeated failed logins", "Multiple usernames targeted"])
        self.assertEqual(len(flagged["usernames"]), 4)


class TestSuccessfulLogins(unittest.TestCase):
    def test_successful_logins_are_never_flagged(self):
        records = make_records("192.0.2.10", ["a", "b", "c", "d", "e", "f"],
                               status="SUCCESS")
        results = fld.analyze_logins(records)
        self.assertEqual(results["successful_logins"], 6)
        self.assertEqual(results["failed_attempts"], 0)
        self.assertEqual(results["flagged"], {})

    def test_successes_do_not_count_toward_failure_threshold(self):
        records = (make_records("192.0.2.10", ["admin"] * 4)
                   + make_records("192.0.2.10", ["admin"] * 3, status="SUCCESS"))
        self.assertEqual(fld.analyze_logins(records)["flagged"], {})


class TestEmptyInput(unittest.TestCase):
    def test_empty_list(self):
        results = fld.analyze_logins([])
        self.assertEqual(results["total_records"], 0)
        self.assertEqual(results["failed_attempts"], 0)
        self.assertEqual(results["flagged"], {})

    def test_none_input(self):
        results = fld.analyze_logins(None)
        self.assertEqual(results["total_records"], 0)

    def test_non_list_input(self):
        self.assertEqual(fld.analyze_logins(12345)["total_records"], 0)

    def test_report_for_empty_input_does_not_crash(self):
        report = fld.build_report(fld.analyze_logins([]))
        self.assertIn("Total login records:       0", report)
        self.assertIn("No IP addresses triggered an alert.", report)


class TestMalformedRecords(unittest.TestCase):
    def test_missing_field_is_skipped(self):
        results = fld.analyze_logins([{"ip": "192.0.2.1", "status": "FAILED"}])
        self.assertEqual(results["valid_records"], 0)
        self.assertEqual(len(results["malformed"]), 1)

    def test_invalid_ip_is_skipped(self):
        record = {"ip": "999.1.1.1", "username": "a", "status": "FAILED"}
        results = fld.analyze_logins([record])
        self.assertEqual(results["failed_attempts"], 0)
        self.assertEqual(len(results["malformed"]), 1)

    def test_unknown_status_is_skipped(self):
        record = {"ip": "192.0.2.1", "username": "a", "status": "MAYBE"}
        self.assertEqual(len(fld.analyze_logins([record])["malformed"]), 1)

    def test_empty_and_non_text_values_are_skipped(self):
        records = [
            {"ip": "192.0.2.1", "username": "   ", "status": "FAILED"},
            {"ip": None, "username": "a", "status": "FAILED"},
            {"ip": "192.0.2.1", "username": 42, "status": "FAILED"},
        ]
        results = fld.analyze_logins(records)
        self.assertEqual(len(results["malformed"]), 3)

    def test_non_dictionary_records_are_skipped(self):
        results = fld.analyze_logins(["text", 7, None, ["a", "b"]])
        self.assertEqual(len(results["malformed"]), 4)
        self.assertEqual(results["valid_records"], 0)

    def test_valid_records_are_still_processed_alongside_bad_ones(self):
        records = make_records("203.0.113.25", ["admin"] * 5) + [
            "garbage",
            {"ip": "not-an-ip", "username": "x", "status": "FAILED"},
        ]
        results = fld.analyze_logins(records)
        self.assertEqual(results["total_records"], 7)
        self.assertEqual(results["valid_records"], 5)
        self.assertEqual(len(results["malformed"]), 2)
        self.assertIn("203.0.113.25", results["flagged"])

    def test_malformed_record_numbers_are_one_based(self):
        records = [{"ip": "192.0.2.1", "username": "a", "status": "FAILED"}, "bad"]
        self.assertEqual(fld.analyze_logins(records)["malformed"][0][0], 2)


class TestReportAndSampleData(unittest.TestCase):
    def test_report_contains_key_sections_and_numbers(self):
        results = fld.analyze_logins(make_records("203.0.113.25", ["admin"] * 5))
        report = fld.build_report(results)
        for text in ("DETECTION RULES", "FLAGGED IP ADDRESSES", "LIMITATIONS",
                     "WARNING: 203.0.113.25", "Total failed attempts:     5",
                     "Total IPs flagged:         1"):
            self.assertIn(text, report)

    def test_save_report_writes_a_file(self):
        original = fld.__file__
        with tempfile.TemporaryDirectory() as folder:
            try:
                fld.__file__ = str(Path(folder) / "failed_login_detector.py")
                path = fld.save_report("hello report", "test_report.txt")
            finally:
                fld.__file__ = original
            self.assertEqual(path.read_text(encoding="utf-8").strip(), "hello report")

    def test_sample_data_gives_expected_results(self):
        results = fld.analyze_logins(fld.SAMPLE_LOGIN_LOGS)
        self.assertEqual(results["total_records"], 28)
        self.assertEqual(len(results["malformed"]), 4)
        self.assertEqual(set(results["flagged"]),
                         {"203.0.113.25", "198.51.100.77", "203.0.113.200"})

    def test_saved_sample_report_matches_program_output(self):
        saved = Path(__file__).resolve().parent / fld.REPORT_FILENAME
        if not saved.exists():
            self.skipTest("Sample report not generated yet.")
        expected = fld.build_report(fld.analyze_logins(fld.SAMPLE_LOGIN_LOGS))
        self.assertEqual(saved.read_text(encoding="utf-8").strip(), expected.strip())


if __name__ == "__main__":
    unittest.main(verbosity=2)
