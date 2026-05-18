"""
Tests for Aho-Corasick multi-pattern matcher.

Coverage:
  - Single pattern match
  - Multiple overlapping patterns
  - Case-insensitive matching
  - Binary payload matching
  - No-match case
  - Overlapping / prefix patterns
  - Match position accuracy
  - Empty pattern / edge cases
  - Large pattern set (performance sanity)
  - Error on search before build
  - Error on add_pattern after build
"""

import pytest

from packetsentry.detection.aho_corasick import AhoCorasick, Match


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def sqli_engine() -> AhoCorasick:
    """Aho-Corasick loaded with SQL injection signatures."""
    ac = AhoCorasick()
    ac.add_pattern("SELECT * FROM")
    ac.add_pattern("UNION SELECT")
    ac.add_pattern("OR 1=1")
    ac.add_pattern("DROP TABLE")
    ac.add_pattern("'; --")
    ac.build()
    return ac


@pytest.fixture()
def xss_engine() -> AhoCorasick:
    ac = AhoCorasick()
    ac.add_pattern("<script>")
    ac.add_pattern("javascript:")
    ac.add_pattern("onerror=")
    ac.build()
    return ac


# ---------------------------------------------------------------------------
# Basic correctness
# ---------------------------------------------------------------------------

class TestSinglePattern:
    def test_found(self):
        ac = AhoCorasick()
        ac.add_pattern("hello")
        ac.build()
        matches = ac.search("say hello world")
        assert len(matches) == 1
        assert matches[0].pattern == "hello"

    def test_not_found(self):
        ac = AhoCorasick()
        ac.add_pattern("hello")
        ac.build()
        assert ac.search("goodbye world") == []

    def test_match_at_start(self):
        ac = AhoCorasick()
        ac.add_pattern("abc")
        ac.build()
        matches = ac.search("abcdef")
        assert matches[0].start == 0
        assert matches[0].end == 3

    def test_match_at_end(self):
        ac = AhoCorasick()
        ac.add_pattern("xyz")
        ac.build()
        matches = ac.search("abcxyz")
        assert matches[0].start == 3
        assert matches[0].end == 6

    def test_multiple_occurrences(self):
        ac = AhoCorasick()
        ac.add_pattern("ab")
        ac.build()
        matches = ac.search("ababab")
        assert len(matches) == 3


class TestMultiplePatterns:
    def test_two_patterns_both_match(self):
        ac = AhoCorasick()
        ac.add_pattern("foo")
        ac.add_pattern("bar")
        ac.build()
        text = "foobar"
        names = ac.match_names(text)
        assert "foo" in names
        assert "bar" in names

    def test_overlapping_patterns(self):
        """'he', 'she', 'his', 'hers' — classic Aho-Corasick example."""
        ac = AhoCorasick()
        for p in ["he", "she", "his", "hers"]:
            ac.add_pattern(p)
        ac.build()
        matches = ac.match_names("ushers")
        assert "he" in matches
        assert "she" in matches
        assert "hers" in matches

    def test_prefix_pattern(self):
        """Shorter pattern is prefix of longer; both must match."""
        ac = AhoCorasick()
        ac.add_pattern("SELECT")
        ac.add_pattern("SELECT * FROM")
        ac.build()
        matches = ac.match_names("SELECT * FROM users")
        assert "SELECT" in matches
        assert "SELECT * FROM" in matches


# ---------------------------------------------------------------------------
# Case insensitivity
# ---------------------------------------------------------------------------

class TestCaseInsensitive:
    def test_uppercase_pattern_lowercase_text(self, sqli_engine):
        assert sqli_engine.contains("select * from users")

    def test_lowercase_pattern_uppercase_text(self, sqli_engine):
        assert sqli_engine.contains("UNION SELECT id FROM secrets")

    def test_mixed_case(self, sqli_engine):
        assert sqli_engine.contains("Or 1=1")


# ---------------------------------------------------------------------------
# SQL injection signatures
# ---------------------------------------------------------------------------

class TestSQLiSignatures:
    def test_union_select(self, sqli_engine):
        assert sqli_engine.contains("1' UNION SELECT null,null--")

    def test_or_tautology(self, sqli_engine):
        assert sqli_engine.contains("admin' OR 1=1 --")

    def test_drop_table(self, sqli_engine):
        assert sqli_engine.contains("'; DROP TABLE users; --")

    def test_comment_injection(self, sqli_engine):
        # "'; --" pattern requires semicolon + space — not present in "admin'--"
        assert not sqli_engine.contains("admin'--")
        # Full pattern match: semicolon + space + dashes
        assert sqli_engine.contains("admin'; -- injected")

    def test_clean_query_no_match(self, sqli_engine):
        assert not sqli_engine.contains("GET /api/users?id=42 HTTP/1.1")


# ---------------------------------------------------------------------------
# XSS signatures
# ---------------------------------------------------------------------------

class TestXSSSignatures:
    def test_script_tag(self, xss_engine):
        assert xss_engine.contains('<img src=x onerror=alert(1)>')

    def test_javascript_protocol(self, xss_engine):
        assert xss_engine.contains('<a href="javascript:void(0)">')

    def test_script_element(self, xss_engine):
        assert xss_engine.contains("<script>alert('xss')</script>")

    def test_clean_html(self, xss_engine):
        assert not xss_engine.contains("<div class='container'>Hello</div>")


# ---------------------------------------------------------------------------
# Binary / bytes payload
# ---------------------------------------------------------------------------

class TestBinaryPayload:
    def test_null_byte_pattern(self):
        ac = AhoCorasick()
        ac.add_pattern("\x00\x00\x00\x00")
        ac.build()
        payload = b"\xff\x00\x00\x00\x00\xaa"
        assert ac.contains(payload)

    def test_no_match_in_binary(self):
        ac = AhoCorasick()
        ac.add_pattern("SSH-2.0")
        ac.build()
        assert not ac.contains(b"\x00\x01\x02\x03")


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_empty_text(self):
        ac = AhoCorasick()
        ac.add_pattern("hello")
        ac.build()
        assert ac.search("") == []

    def test_empty_pattern_ignored(self):
        ac = AhoCorasick()
        ac.add_pattern("")   # should not crash
        ac.add_pattern("hi")
        ac.build()
        assert ac.contains("say hi")

    def test_pattern_longer_than_text(self):
        ac = AhoCorasick()
        ac.add_pattern("verylongpattern")
        ac.build()
        assert not ac.contains("short")

    def test_single_char_pattern(self):
        ac = AhoCorasick()
        ac.add_pattern("a")
        ac.build()
        matches = ac.search("banana")
        assert len(matches) == 3  # positions 1, 3, 5

    def test_pattern_equals_text(self):
        ac = AhoCorasick()
        ac.add_pattern("exact")
        ac.build()
        matches = ac.search("exact")
        assert len(matches) == 1
        assert matches[0].start == 0
        assert matches[0].end == 5


# ---------------------------------------------------------------------------
# API contract / error handling
# ---------------------------------------------------------------------------

class TestAPIContract:
    def test_search_before_build_raises(self):
        ac = AhoCorasick()
        ac.add_pattern("test")
        with pytest.raises(RuntimeError, match="build()"):
            ac.search("test")

    def test_add_pattern_after_build_raises(self):
        ac = AhoCorasick()
        ac.add_pattern("test")
        ac.build()
        with pytest.raises(RuntimeError, match="build()"):
            ac.add_pattern("new")

    def test_pattern_count(self):
        ac = AhoCorasick()
        for p in ["a", "bb", "ccc"]:
            ac.add_pattern(p)
        assert ac.pattern_count == 3

    def test_contains_returns_bool(self):
        ac = AhoCorasick()
        ac.add_pattern("x")
        ac.build()
        result = ac.contains("xyz")
        assert isinstance(result, bool)
        assert result is True

    def test_match_names_deduplicates(self):
        ac = AhoCorasick()
        ac.add_pattern("ab")
        ac.build()
        names = ac.match_names("ababab")
        assert names.count("ab") == 1


# ---------------------------------------------------------------------------
# Performance sanity (not a benchmark, just proves O(n) doesn't time out)
# ---------------------------------------------------------------------------

class TestPerformance:
    def test_1000_patterns_large_text(self):
        ac = AhoCorasick()
        # 1000 patterns that won't match
        for i in range(1000):
            ac.add_pattern(f"PATTERN_{i:04d}")
        ac.add_pattern("TARGET")
        ac.build()

        text = "noise " * 10_000 + " TARGET " + "noise " * 10_000
        matches = ac.match_names(text)
        assert "TARGET" in matches
