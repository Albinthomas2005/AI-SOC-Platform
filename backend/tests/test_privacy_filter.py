import unittest

from privacy_filter import (
    new_privacy_context,
    sanitize_alert,
    sanitize_text,
)


class TestPrivacyFilter(unittest.TestCase):

    def test_redacts_email(self):
        result = sanitize_text("user email: analyst@example.com")
        self.assertNotIn("analyst@example.com", result)
        self.assertIn("[REDACTED_EMAIL]", result)

    def test_redacts_bearer_token(self):
        result = sanitize_text("Authorization: Bearer abc123token")
        self.assertNotIn("abc123token", result)
        self.assertIn("[REDACTED_TOKEN]", result)

    def test_redacts_password_field(self):
        result = sanitize_alert({"password": "MySecret123"})
        self.assertEqual(result["password"], "[REDACTED_SECRET]")

    def test_redacts_api_key_field(self):
        result = sanitize_alert({"api_key": "fake-test-key-123"})
        self.assertEqual(result["api_key"], "[REDACTED_SECRET]")

    def test_redacts_public_ipv4(self):
        result = sanitize_text("Source IP: 8.8.8.8")
        self.assertNotIn("8.8.8.8", result)
        self.assertIn("[REDACTED_PUBLIC_IP]", result)

    def test_redacts_public_ipv4_before_sentence_period(self):
        result = sanitize_text("Public IP 8.8.8.8.")
        self.assertNotIn("8.8.8.8", result)
        self.assertEqual(result, "Public IP [REDACTED_PUBLIC_IP].")

    def test_public_ipv6_and_integer_field_keep_public_redaction_policy(self):
        result = sanitize_text("8.8.8.8 2606:4700:4700::1111")
        self.assertEqual(result.count("[REDACTED_PUBLIC_IP]"), 2)
        alert = sanitize_alert({"srcip": 134744072})
        self.assertEqual(alert["srcip"], "[REDACTED_PUBLIC_IP]")

    def test_pseudonymizes_private_ipv4_consistently(self):
        result = sanitize_text("192.168.1.50 -> 192.168.1.50")
        self.assertNotIn("192.168.1.50", result)
        left, right = result.split(" -> ")
        self.assertEqual(left, right)
        self.assertTrue(left.startswith("[NONPUBLIC_IP_"))

    def test_pseudonymizes_non_global_reserved_and_shared_addresses(self):
        result = sanitize_text("198.51.100.9 100.64.0.8")
        self.assertNotIn("198.51.100.9", result)
        self.assertNotIn("100.64.0.8", result)
        self.assertEqual(result.count("[NONPUBLIC_IP_"), 2)

    def test_pseudonymizes_private_ipv6(self):
        result = sanitize_text("Source IP: fd12:3456:789a::1")
        self.assertNotIn("fd12:3456:789a::1", result)
        self.assertIn("[NONPUBLIC_IP_", result)

    def test_pseudonymizes_loopback_and_link_local_ipv4_and_ipv6(self):
        result = sanitize_text(
            "127.0.0.1 ::1 169.254.10.20 fe80::abcd"
        )
        for address in ("127.0.0.1", "::1", "169.254.10.20", "fe80::abcd"):
            self.assertNotIn(address, result)
        self.assertEqual(result.count("[NONPUBLIC_IP_"), 4)

    def test_bracketed_ipv6_is_masked_without_double_brackets(self):
        context = new_privacy_context()
        result = sanitize_text("[::1] ::1", context)
        bracketed, unbracketed = result.split()
        self.assertEqual(bracketed, unbracketed)
        self.assertTrue(bracketed.startswith("[NONPUBLIC_IP_"))
        self.assertNotIn("[[", result)

    def test_ipv4_mapped_ipv6_and_scoped_link_local_are_masked(self):
        result = sanitize_text(
            "::ffff:192.168.1.7 [fe80::1%eth0]"
        )
        self.assertNotIn("192.168.1.7", result)
        self.assertNotIn("fe80::1", result)
        self.assertNotIn("eth0", result)
        self.assertEqual(result.count("[NONPUBLIC_IP_"), 2)

    def test_percent_encoded_addresses_are_decoded_repeatedly(self):
        context = new_privacy_context()
        once = "192%2E168%2E1%2E7"
        twice = "%2531%2539%2532%252E%2531%2536%2538%252E%2531%252E%2537"
        decoded_ipv6 = "%253A%253Affff%253Ac0a8%253A107"
        loopback_ipv6 = "%253A%253A1"
        encoded_url = (
            "%68%74%74%70%3A%2F%2F%31%39%32%2E%31%36%38%2E%31%2E%37"
        )
        result = sanitize_text(
            f"{once} {twice} {decoded_ipv6} {loopback_ipv6} {encoded_url}",
            context,
        )
        first, second, mapped, loopback, url = result.split()
        self.assertEqual(first, second)
        self.assertEqual(first, mapped)
        self.assertEqual(loopback, sanitize_text("::1", context))
        self.assertEqual(url, f"http://{first}")
        self.assertNotIn("%", result)

    def test_unambiguous_integer_and_hex_ipv4_text_is_masked(self):
        result = sanitize_text(
            "srcip=3232235783 dstip:0xC0A80107 http://3232235783/path"
        )
        self.assertNotIn("3232235783", result)
        self.assertNotIn("0xC0A80107", result)
        self.assertEqual(result.count("[NONPUBLIC_IP_"), 3)

    def test_ambiguous_free_text_numbers_are_not_rewritten(self):
        value = "3232235783 443 rule 1001 port 443 12:34:56"
        self.assertEqual(sanitize_text(value), value)

    def test_structured_ip_fields_normalize_integer_and_hex_ipv4(self):
        alert = sanitize_alert(
            {
                "data": {
                    "srcip": 3232235783,
                    "dstip": "0xC0A80107",
                }
            }
        )
        self.assertEqual(alert["data"]["srcip"], alert["data"]["dstip"])
        self.assertTrue(alert["data"]["srcip"].startswith("[NONPUBLIC_IP_"))

    def test_malformed_ipv6_candidates_redact_but_clock_and_numbers_survive(self):
        value = (
            "fd00::gggg [fd00::gggg] fd00%3A%3Agggg "
            "12:34:56 2026-10-28T12:34:56Z "
            "port 443 rule 1001"
        )
        result = sanitize_text(value)
        self.assertEqual(result.count("[REDACTED_INVALID_IP]"), 3)
        for legitimate_text in (
            "12:34:56",
            "2026-10-28T12:34:56Z",
            "port 443",
            "rule 1001",
        ):
            self.assertIn(legitimate_text, result)

    def test_unspaced_ip_field_label_does_not_join_the_ipv6_candidate(self):
        context = new_privacy_context()
        result = sanitize_text("srcip:fd00::1 dstip:fd00::1", context)
        left, right = result.split()
        self.assertTrue(left.startswith("srcip:[NONPUBLIC_IP_"))
        self.assertTrue(right.startswith("dstip:[NONPUBLIC_IP_"))
        self.assertEqual(left.split(":", 1)[1], right.split(":", 1)[1])
        self.assertNotIn("fd00::1", result)

        v4_context = new_privacy_context()
        v4_result = sanitize_text(
            "srcip:192.168.1.7 dstip:192.168.1.7", v4_context
        )
        v4_left, v4_right = v4_result.split()
        self.assertEqual(v4_left.split(":", 1)[1], v4_right.split(":", 1)[1])
        self.assertNotIn("192.168.1.7", v4_result)

    def test_same_context_correlates_alert_and_notes(self):
        context = new_privacy_context()
        alert = sanitize_alert({"data": {"srcip": "10.0.0.7"}}, privacy_context=context)
        notes = sanitize_text("Observed again: 10.0.0.7", context)
        self.assertEqual(alert["data"]["srcip"], notes.split(": ", 1)[1])

    def test_pseudonyms_are_scoped_to_one_analysis(self):
        first = sanitize_text("10.0.0.7")
        second = sanitize_text("10.0.0.7")
        self.assertNotEqual(first, second)

    def test_malformed_ip_like_values_are_redacted_without_error(self):
        result = sanitize_text("999.999.999.999 2001:db8:0:0:0:0:0:0:1")
        self.assertNotIn("999.999.999.999", result)
        self.assertNotIn("2001:db8:0:0:0:0:0:0:1", result)
        self.assertEqual(result.count("[REDACTED_INVALID_IP]"), 2)

    def test_strict_privacy_is_opt_in_and_masks_common_identifiers(self):
        value = (
            "host ws-23.corp.example URL https://srv.internal.local/a "
            "MAC 02:00:5e:10:00:00 and aabb.ccdd.eeff "
            "user=alice path=/home/alice/case.txt"
        )
        default = sanitize_text(value)
        self.assertEqual(default, value)

        strict = sanitize_text(value, strict=True)
        for raw in (
            "ws-23.corp.example",
            "https://srv.internal.local/a",
            "02:00:5e:10:00:00",
            "aabb.ccdd.eeff",
            "alice",
            "/home/alice/case.txt",
        ):
            self.assertNotIn(raw, strict)
        for token in (
            "[REDACTED_HOST]",
            "[REDACTED_URL]",
            "[REDACTED_MAC]",
            "[REDACTED_USER]",
            "[REDACTED_PATH]",
        ):
            self.assertIn(token, strict)

    def test_default_mode_does_not_remove_hostnames_usernames_urls_macs_or_paths(self):
        value = (
            "host=ws-23.corp.example user=alice "
            "url=https://srv.internal.local/a mac=02:00:5e:10:00:00 "
            "path=/home/alice/case.txt"
        )
        result = sanitize_text(value)

        self.assertEqual(result, value)

    def test_recursively_sanitizes_nested_data(self):
        alert = {
            "data": {
                "email": "analyst@example.com",
                "password": "fake-password",
            }
        }
        result = sanitize_alert(alert)
        self.assertNotIn("analyst@example.com", str(result))
        self.assertNotIn("fake-password", str(result))

    def test_does_not_modify_input(self):
        alert = {"password": "fake-password"}
        sanitize_alert(alert)
        self.assertEqual(alert["password"], "fake-password")


if __name__ == "__main__":
    unittest.main()
