"""Parse a file once, so every rule queries the same tree."""

from dataclasses import dataclass
from functools import cache

import tree_sitter_python
import tree_sitter_typescript
from tree_sitter import Language, Node, Parser, Tree

# Which grammar reads which extension.
#
# The whole JavaScript family goes to `tsx` rather than `typescript`, which was
# measured rather than assumed: both grammars accept commonjs, esm and modern
# syntax, but the plain TypeScript grammar rejects JSX inside a `.js` file and
# tsx accepts it. `.ts` keeps the typescript grammar, because that is where the
# two genuinely differ: tsx reads `<T>x` as the start of a JSX element where
# typescript reads it as a type assertion.
#
# This is also why the dependency list stays at three packages. Covering
# JavaScript needs no fourth grammar, and JavaScript is 11% to 16% of the
# corpus.
LANGUAGE_BY_SUFFIX: dict[str, str] = {
    ".py": "python",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".jsx": "tsx",
    ".js": "tsx",
    ".mjs": "tsx",
    ".cjs": "tsx",
}

_GRAMMARS = {
    "python": tree_sitter_python.language,
    "typescript": tree_sitter_typescript.language_typescript,
    "tsx": tree_sitter_typescript.language_tsx,
}


@cache
def language_for(name: str) -> Language | None:
    """The grammar for a language name, built once and shared.

    Building a Language is the expensive part and the result is immutable, so
    it is cached and shared across threads. A Parser is not shared: see
    `parse_source`.
    """
    factory = _GRAMMARS.get(name)
    return Language(factory()) if factory else None


@dataclass(frozen=True)
class ParsedFile:
    """One file's syntax tree, with everything a rule needs to read it.

    `source` is bytes rather than str because nodes address the source by byte
    offset. Slicing decoded text with a byte offset silently cuts the wrong
    span in any file containing a non-ASCII character, which is precisely the
    kind of file the concealment rules exist to look at.
    """

    language: str
    grammar: Language
    tree: Tree
    source: bytes

    def text(self, node: Node) -> str:
        """The source behind a node, as text.

        Every rule needs this and every rule would otherwise write the slice
        and the decode by hand, which is where the byte-offset mistake gets
        made.
        """
        return self.source[node.start_byte : node.end_byte].decode("utf-8", "replace")


def parse_source(source: str, suffix: str) -> ParsedFile | None:
    """Parse one file, or return None if we have no grammar for it.

    None rather than an exception: a file with no grammar is the ordinary case,
    not a failure. Markdown and JSON are scanned by the codepoint rule and
    never parsed, and the caller stays a plain loop.

    A tree is returned even when the source does not parse cleanly. Grammars
    lag language features and a repository is under no obligation to compile,
    so a partial tree is worth more than nothing; a rule that cares can check
    `has_error` itself.

    A fresh Parser is built per call. Parsers hold mutable state and are not
    safe to share between threads, and the orchestrator runs eight of them at
    once, where a shared parser corrupts trees rather than raising: wrong
    findings instead of an error somebody would notice. The Language is shared,
    because it is immutable and is the expensive half.
    """
    name = LANGUAGE_BY_SUFFIX.get(suffix.lower())
    if name is None:
        return None

    grammar = language_for(name)
    if grammar is None:
        return None

    data = source.encode("utf-8")
    tree = Parser(grammar).parse(data)
    return ParsedFile(language=name, grammar=grammar, tree=tree, source=data)
