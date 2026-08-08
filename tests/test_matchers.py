import unittest

from agent_firewall import matchers


def match(pattern, value):
    matchers.compile(pattern, "test")
    return matchers.match(pattern, value)


class CompileTests(unittest.TestCase):
    def test_unknown_operator_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unknown matcher operator"):
            matchers.compile({"operator": "bogus"}, "rule.arguments.x")

    def test_unknown_typed_key_is_rejected(self):
        with self.assertRaisesRegex(
            ValueError, "unknown typed matcher key\\(s\\): rule.arguments.x.nope"
        ):
            matchers.compile({"operator": "url", "nope": 1}, "rule.arguments.x")

    def test_url_requires_at_least_one_field(self):
        with self.assertRaisesRegex(ValueError, "requires one of"):
            matchers.compile({"operator": "url"}, "x")

    def test_path_requires_within_or_equals(self):
        with self.assertRaisesRegex(ValueError, "requires one of"):
            matchers.compile({"operator": "path"}, "x")

    def test_domain_requires_equals_or_suffix(self):
        with self.assertRaisesRegex(ValueError, "requires one of"):
            matchers.compile({"operator": "domain"}, "x")

    def test_http_method_uses_either_equals_or_in(self):
        with self.assertRaisesRegex(ValueError, "not both"):
            matchers.compile(
                {"operator": "http_method", "equals": "GET", "in": ["GET"]}, "x"
            )

    def test_sql_uses_either_equals_or_in(self):
        with self.assertRaisesRegex(ValueError, "not both"):
            matchers.compile(
                {"operator": "sql", "equals": "select", "in": ["select"]}, "x"
            )

    def test_number_requires_min_or_max(self):
        with self.assertRaisesRegex(ValueError, "requires one of"):
            matchers.compile({"operator": "number"}, "x")

    def test_command_requires_executable_or_argv_prefix(self):
        with self.assertRaisesRegex(ValueError, "requires one of"):
            matchers.compile({"operator": "command"}, "x")

    def test_out_of_range_port_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "port"):
            matchers.compile({"operator": "url", "port": 70000}, "x")

    def test_empty_url_path_operator_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "exactly one of"):
            matchers.compile({"operator": "url", "path": {}}, "x")

    def test_empty_string_and_list_constraints_are_rejected(self):
        for pattern in (
            {"operator": "url", "scheme": ""},
            {"operator": "url", "hostname": []},
            {"operator": "http_method", "in": [""]},
        ):
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(ValueError, "non-empty"):
                    matchers.compile(pattern, "x")

    def test_non_finite_number_bounds_are_rejected(self):
        for value in ("NaN", "Infinity", float("inf")):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "finite"):
                    matchers.compile({"operator": "number", "max": value}, "x")


class UrlMatcherTests(unittest.TestCase):
    def test_scheme_hostname_match(self):
        self.assertTrue(
            match(
                {"operator": "url", "scheme": "https", "hostname": "example.com"},
                "https://example.com/path",
            )
        )
        self.assertFalse(
            match(
                {"operator": "url", "scheme": "http", "hostname": "example.com"},
                "https://example.com/path",
            )
        )

    def test_scheme_list_is_membership(self):
        self.assertTrue(
            match(
                {"operator": "url", "scheme": ["http", "https"]},
                "http://example.com/",
            )
        )

    def test_hostname_glob(self):
        self.assertTrue(
            match(
                {"operator": "url", "hostname": "*.example.com"},
                "https://api.example.com/v1",
            )
        )
        self.assertFalse(
            match(
                {"operator": "url", "hostname": "*.example.com"},
                "https://evil-example.com/v1",
            )
        )

    def test_userinfo_does_not_confuse_hostname(self):
        self.assertFalse(
            match(
                {"operator": "url", "hostname": "example.com"},
                "https://example.com@evil.com/path",
            )
        )
        self.assertTrue(
            match(
                {"operator": "url", "hostname": "evil.com"},
                "https://example.com@evil.com/path",
            )
        )

    def test_trailing_dot_hostname_is_not_equal(self):
        self.assertFalse(
            match(
                {"operator": "url", "hostname": "example.com"},
                "https://example.com./path",
            )
        )

    def test_lookalike_without_netloc_has_no_hostname(self):
        self.assertFalse(
            match(
                {"operator": "url", "hostname": "example.com"},
                "https:example.com/path",
            )
        )
        self.assertFalse(
            match(
                {"operator": "url", "hostname": "example.com"},
                "example.com/path",
            )
        )

    def test_literal_port(self):
        self.assertTrue(
            match({"operator": "url", "port": 8080}, "http://example.com:8080/x")
        )
        self.assertFalse(
            match({"operator": "url", "port": 8080}, "http://example.com/x")
        )
        self.assertTrue(
            match({"operator": "url", "port": [80, 8080]}, "http://example.com:80/x")
        )

    def test_malformed_port_and_ipv6_are_rejected(self):
        pattern = {"operator": "url", "hostname": "example.com"}
        self.assertFalse(match(pattern, "https://example.com:not-a-port/path"))
        self.assertFalse(match(pattern, "https://[broken/path"))

    def test_path_prefix_suffix_equals(self):
        self.assertTrue(
            match(
                {"operator": "url", "path": {"prefix": "/api"}},
                "https://example.com/api/v1",
            )
        )
        self.assertTrue(
            match(
                {"operator": "url", "path": {"suffix": ".json"}},
                "https://example.com/a.json",
            )
        )
        self.assertTrue(
            match(
                {"operator": "url", "path": {"equals": "/a.json"}},
                "https://example.com/a.json",
            )
        )

    def test_deny_private_networks_ipv4(self):
        for address in ("127.0.0.1", "10.0.0.1", "192.168.1.5", "169.254.1.1"):
            self.assertFalse(
                match(
                    {"operator": "url", "deny_private_networks": True},
                    f"http://{address}/x",
                ),
                address,
            )
        self.assertTrue(
            match(
                {"operator": "url", "deny_private_networks": True},
                "http://8.8.8.8/x",
            )
        )

    def test_deny_private_networks_ipv6(self):
        for address in ("[::1]", "[fe80::1]", "[2001:db8::1]"):
            self.assertFalse(
                match(
                    {"operator": "url", "deny_private_networks": True},
                    f"http://{address}/x",
                ),
                address,
            )
        self.assertTrue(
            match(
                {"operator": "url", "deny_private_networks": True},
                "http://[2606:4700::1111]/x",
            )
        )

    def test_deny_private_networks_skips_non_ip_hostnames(self):
        self.assertTrue(
            match(
                {"operator": "url", "deny_private_networks": True},
                "http://example.com/x",
            )
        )


class PathMatcherTests(unittest.TestCase):
    def test_equals_lexical_absolute_normalization(self):
        self.assertTrue(
            match({"operator": "path", "equals": "/etc/passwd"}, "/etc/passwd")
        )
        self.assertTrue(
            match({"operator": "path", "equals": "/etc/passwd"}, "etc/passwd")
        )
        self.assertTrue(
            match(
                {"operator": "path", "equals": "/etc/passwd"},
                "/etc/../etc/passwd",
            )
        )
        self.assertFalse(
            match({"operator": "path", "equals": "/etc/passwd"}, "/etc/passwd2")
        )

    def test_traversal_does_not_escape_the_anchor(self):
        self.assertFalse(
            match(
                {"operator": "path", "within": "/etc"},
                "/etc/../../outside",
            )
        )

    def test_within_is_directory_boundary_aware(self):
        self.assertTrue(match({"operator": "path", "within": "/etc"}, "/etc/passwd"))
        self.assertTrue(match({"operator": "path", "within": "/etc"}, "/etc"))
        self.assertFalse(match({"operator": "path", "within": "/etc"}, "/etc2/x"))

    def test_non_string_value_does_not_match(self):
        self.assertFalse(match({"operator": "path", "equals": "/etc"}, 42))


class DomainMatcherTests(unittest.TestCase):
    def test_equals_is_exact_and_case_insensitive(self):
        self.assertTrue(
            match({"operator": "domain", "equals": "example.com"}, "a@EXAMPLE.com")
        )
        self.assertFalse(
            match({"operator": "domain", "equals": "example.com"}, "a@sub.example.com")
        )

    def test_suffix_covers_domain_and_subdomains(self):
        self.assertTrue(
            match({"operator": "domain", "suffix": "example.com"}, "a@example.com")
        )
        self.assertTrue(
            match({"operator": "domain", "suffix": "example.com"}, "a@sub.example.com")
        )
        self.assertFalse(
            match(
                {"operator": "domain", "suffix": "example.com"},
                "a@evil-example.com",
            )
        )
        self.assertFalse(
            match(
                {"operator": "domain", "suffix": "example.com"},
                "a@example.com.evil.com",
            )
        )

    def test_value_without_at_sign_does_not_match(self):
        self.assertFalse(
            match({"operator": "domain", "suffix": "example.com"}, "example.com")
        )


class HttpMethodMatcherTests(unittest.TestCase):
    def test_equals_is_case_insensitive(self):
        self.assertTrue(match({"operator": "http_method", "equals": "get"}, "GET"))
        self.assertFalse(match({"operator": "http_method", "equals": "get"}, "DELETE"))

    def test_in_is_membership(self):
        self.assertTrue(
            match({"operator": "http_method", "in": ["post", "put"]}, "POST")
        )
        self.assertFalse(
            match({"operator": "http_method", "in": ["post", "put"]}, "DELETE")
        )

    def test_non_string_value_does_not_match(self):
        self.assertFalse(match({"operator": "http_method", "equals": "get"}, 1))


class NumberMatcherTests(unittest.TestCase):
    def test_inclusive_bounds(self):
        self.assertTrue(match({"operator": "number", "min": 1, "max": 10}, 5))
        self.assertTrue(match({"operator": "number", "min": 1, "max": 10}, 1))
        self.assertTrue(match({"operator": "number", "min": 1, "max": 10}, 10))
        self.assertFalse(match({"operator": "number", "min": 1, "max": 10}, 11))
        self.assertFalse(match({"operator": "number", "min": 1, "max": 10}, 0))

    def test_decimal_bounds_and_values(self):
        self.assertTrue(
            match({"operator": "number", "min": "0.10", "max": "0.20"}, "0.15")
        )
        self.assertTrue(match({"operator": "number", "min": 0.5}, "3.14"))
        self.assertFalse(match({"operator": "number", "max": 10}, 10.5))
        self.assertFalse(
            match({"operator": "number", "min": "0.10", "max": "0.20"}, "0.25")
        )

    def test_non_numeric_value_does_not_match(self):
        self.assertFalse(match({"operator": "number", "min": 0}, "nope"))


class SqlMatcherTests(unittest.TestCase):
    def test_leading_operation_is_extracted(self):
        self.assertTrue(
            match({"operator": "sql", "equals": "select"}, "SELECT * FROM users")
        )
        self.assertFalse(
            match({"operator": "sql", "equals": "select"}, "DELETE FROM users")
        )

    def test_comments_and_whitespace_are_ignored(self):
        self.assertTrue(
            match(
                {"operator": "sql", "equals": "select"},
                "  -- preamble comment\n/* block */ select 1",
            )
        )
        self.assertTrue(
            match(
                {"operator": "sql", "equals": "select"},
                "# hash comment\nselect 1",
            )
        )
        self.assertFalse(
            match(
                {"operator": "sql", "equals": "select"},
                "/* comment */ insert into t",
            )
        )

    def test_in_is_membership(self):
        self.assertTrue(
            match({"operator": "sql", "in": ["insert", "update"]}, "  update t")
        )
        self.assertFalse(
            match({"operator": "sql", "in": ["insert", "update"]}, "delete t")
        )

    def test_empty_statement_does_not_match(self):
        self.assertFalse(
            match({"operator": "sql", "equals": "select"}, "  -- only a comment")
        )


class CommandMatcherTests(unittest.TestCase):
    def test_executable_matches_basename_and_full_path(self):
        self.assertTrue(
            match({"operator": "command", "executable": "git"}, "git status")
        )
        self.assertTrue(
            match(
                {"operator": "command", "executable": "git"},
                "/usr/bin/git status",
            )
        )
        self.assertFalse(
            match({"operator": "command", "executable": "git"}, "gitt status")
        )

    def test_executable_glob(self):
        self.assertTrue(
            match({"operator": "command", "executable": "git*"}, "git-lfs status")
        )

    def test_argv_prefix_matches_the_full_argv(self):
        self.assertTrue(
            match(
                {
                    "operator": "command",
                    "executable": "git",
                    "argv_prefix": ["git", "commit"],
                },
                "git commit -m message",
            )
        )
        self.assertFalse(
            match(
                {
                    "operator": "command",
                    "executable": "git",
                    "argv_prefix": ["git", "commit"],
                },
                "git push",
            )
        )

    def test_list_values_are_argv(self):
        self.assertTrue(
            match(
                {"operator": "command", "argv_prefix": ["git", "push"]},
                ["git", "push", "origin"],
            )
        )
        self.assertFalse(
            match(
                {"operator": "command", "argv_prefix": ["git", "push"]},
                ["git", "pull"],
            )
        )

    def test_unbalanced_quotes_do_not_match(self):
        self.assertFalse(
            match({"operator": "command", "executable": "git"}, 'git commit "unclosed')
        )

    def test_shell_compounds_and_expansions_do_not_match(self):
        pattern = {"operator": "command", "executable": "git"}
        for value in (
            "git status; rm important.txt",
            "git status && rm important.txt",
            "git status | tee output.txt",
            "git $(cat command.txt)",
            "git ${SUBCOMMAND}",
        ):
            with self.subTest(value=value):
                self.assertFalse(match(pattern, value))


class ScalarBehaviourPreservationTests(unittest.TestCase):
    def test_scalar_string_patterns_stay_globs(self):
        self.assertFalse(matchers.is_typed("*.example.com"))

    def test_plain_dict_patterns_are_not_typed(self):
        self.assertFalse(matchers.is_typed({"to": "a@example.com"}))


if __name__ == "__main__":
    unittest.main()
