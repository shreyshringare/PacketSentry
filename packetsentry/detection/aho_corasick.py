"""
Aho-Corasick multi-pattern string matching — implemented from scratch.

Algorithm overview:
  1. Build a trie from all patterns (goto function).
  2. BFS over the trie to compute failure links (suffix links).
  3. Build output links so every node knows all patterns that match there.
  4. Search: walk the automaton in O(n) time regardless of pattern count.

Time complexity:
  - Build: O(total pattern characters)
  - Search: O(text length + match count)

Interview answer:
  Naive regex runs each pattern independently → O(n × m) where m = pattern count.
  Aho-Corasick builds an automaton once → O(n) search for any number of patterns.
  At 10,000 packets/sec with 1,000 signatures, this is the difference between
  keeping up and falling behind.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field


@dataclass
class TrieNode:
    """Single node in the Aho-Corasick automaton."""

    children: dict[int, "TrieNode"] = field(default_factory=dict)
    fail: "TrieNode | None" = None
    output: list[str] = field(default_factory=list)
    """Patterns that end at this node (including via output links)."""


@dataclass
class Match:
    """A pattern match found in the text."""

    pattern: str
    start: int
    end: int  # exclusive


class AhoCorasick:
    """
    Multi-pattern string matcher using the Aho-Corasick algorithm.

    Build once, search many times.  All matching is performed on raw bytes
    so the automaton handles arbitrary binary payloads (network packets).

    Usage::

        ac = AhoCorasick()
        ac.add_pattern("SELECT")
        ac.add_pattern("UNION SELECT")
        ac.build()
        matches = ac.search("GET /?q=SELECT+*+FROM+users")
    """

    def __init__(self) -> None:
        self._root = TrieNode()
        self._built = False
        self._patterns: list[str] = []

    # ------------------------------------------------------------------
    # Phase 1 — trie construction
    # ------------------------------------------------------------------

    def add_pattern(self, pattern: str) -> None:
        """
        Insert a pattern into the trie.

        Must be called before :meth:`build`.  Patterns are matched
        case-insensitively by normalising to lowercase bytes.

        Args:
            pattern: The string pattern to register.

        Raises:
            RuntimeError: If called after :meth:`build`.
        """
        if self._built:
            raise RuntimeError("Cannot add patterns after build() has been called.")
        if not pattern:
            return

        self._patterns.append(pattern)
        node = self._root
        for ch in pattern.lower().encode():
            if ch not in node.children:
                node.children[ch] = TrieNode()
            node = node.children[ch]
        node.output.append(pattern)

    # ------------------------------------------------------------------
    # Phase 2 — failure function via BFS
    # ------------------------------------------------------------------

    def build(self) -> None:
        """
        Construct failure links and output links using BFS.

        Must be called once after all patterns are added.
        After build(), the automaton is ready for :meth:`search`.

        The failure link of a node v is the longest proper suffix of the
        string represented by v that is also a prefix of some pattern.
        This is identical to the KMP failure function generalised to a trie.
        """
        q: deque[TrieNode] = deque()

        # Depth-1 nodes: failure links point to root.
        for child in self._root.children.values():
            child.fail = self._root
            q.append(child)

        while q:
            current = q.popleft()

            for byte, child in current.children.items():
                # Walk failure links of *current* to find where child's
                # failure link should point.
                fail_node = current.fail
                while fail_node is not None and byte not in fail_node.children:
                    fail_node = fail_node.fail
                child.fail = fail_node.children[byte] if fail_node else self._root

                # A node must not link to itself.
                if child.fail is child:
                    child.fail = self._root

                # Merge output: everything the fail node matches, this node
                # also matches (output links compress the chain).
                child.output = child.output + child.fail.output

                q.append(child)

        self._built = True

    # ------------------------------------------------------------------
    # Phase 3 — search
    # ------------------------------------------------------------------

    def search(self, text: str | bytes) -> list[Match]:
        """
        Search text for all registered patterns in O(n) time.

        Args:
            text: The string or bytes to search.  Strings are UTF-8 encoded
                  and lowercased before matching so patterns are always
                  compared case-insensitively.

        Returns:
            List of :class:`Match` objects in order of their end position.

        Raises:
            RuntimeError: If called before :meth:`build`.
        """
        if not self._built:
            raise RuntimeError("Must call build() before search().")

        if isinstance(text, str):
            raw = text.lower().encode()
        else:
            raw = text.lower() if hasattr(text, "lower") else bytes(b.lower() if 32 <= b < 127 else b for b in text)

        matches: list[Match] = []
        node = self._root

        for i, byte in enumerate(raw):
            # Follow failure links until we find a valid transition or hit root.
            while node is not self._root and byte not in node.children:
                node = node.fail  # type: ignore[assignment]

            if byte in node.children:
                node = node.children[byte]

            # Collect all patterns that end at position i.
            for pattern in node.output:
                pat_bytes = len(pattern.encode())
                matches.append(Match(
                    pattern=pattern,
                    start=i - pat_bytes + 1,
                    end=i + 1,
                ))

        return matches

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def contains(self, text: str | bytes) -> bool:
        """Return True if any registered pattern appears in text."""
        return bool(self.search(text))

    def match_names(self, text: str | bytes) -> list[str]:
        """Return list of matched pattern strings (deduplicated, ordered)."""
        seen: set[str] = set()
        result: list[str] = []
        for m in self.search(text):
            if m.pattern not in seen:
                seen.add(m.pattern)
                result.append(m.pattern)
        return result

    @property
    def pattern_count(self) -> int:
        """Number of patterns registered."""
        return len(self._patterns)
