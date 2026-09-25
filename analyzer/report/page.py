"""The overview page: one self-contained file, generated from the site data."""

from html import escape
from pathlib import Path
from urllib.parse import urlparse

from analyzer.report.site import Decision, SiteData

# Author and source, on every page. A portfolio site a reviewer cannot trace
# back to a person or to the code is a dead end for both of them.
AUTHOR = "Manan Thakkar"
REPOSITORY = "https://github.com/ManankumarThakkar/mcp-observatory"

# Rendered as a single file with nothing fetched at runtime. A static dashboard
# that needs a server to assemble itself is not a static dashboard: this one
# opens from file://, from a static host, and with no network at all, which is
# also what makes it reviewable as a plain artifact.
#
# No framework, because there is no interaction to manage. The whole page is a
# handful of tables over numbers computed and tested elsewhere, and a build
# step would add a way for it to break without adding anything a reader sees.

_STYLE = """
:root {
  color-scheme: light dark;
  --bg: #fbfbfa; --panel: #fff; --ink: #16161a; --muted: #5c5f66;
  --line: #d4d4cf; --accent: #1f6feb; --warn: #9a3412; --ok: #166534;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0d0d0f; --panel: #16161a; --ink: #ececee; --muted: #9b9ba3;
    --line: #353540; --accent: #6aa8ff; --warn: #fdba74; --ok: #86efac;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--ink);
  font: 16px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
}
.wrap { max-width: 68rem; margin: 0 auto; padding: 0 16px 5rem; }
header { padding: 3.5rem 0 2rem; }
h1 { font-size: clamp(1.75rem, 4vw, 2.5rem); line-height: 1.15; margin: 0 0 .5rem; letter-spacing: -.02em; }
.lede { font-size: 1.125rem; color: var(--muted); max-width: 46rem; margin: 0; }
h2 { font-size: 1.0625rem; margin: 2.75rem 0 .75rem; letter-spacing: .01em; }
h2 .n { color: var(--muted); font-weight: 400; }
p { max-width: 46rem; }
.note { color: var(--muted); font-size: .9375rem; }
.chain { display: flex; flex-wrap: wrap; gap: .5rem; align-items: stretch; margin: 0; padding: 0; list-style: none; }
.chain li {
  flex: 1 1 8.5rem; background: var(--panel); border: 1px solid var(--line);
  border-radius: 10px; padding: .875rem 1rem;
}
.chain dt, .chain .k { font-size: .75rem; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); }
.chain .v { font-size: 1.5rem; font-variant-numeric: tabular-nums; font-weight: 600; letter-spacing: -.02em; }
.chain .sub { font-size: .8125rem; color: var(--muted); font-variant-numeric: tabular-nums; }
.callout {
  background: var(--panel); border: 1px solid var(--line); border-left: 3px solid var(--warn);
  border-radius: 8px; padding: 1rem 1.125rem; margin: 1rem 0 0; max-width: 46rem;
}
.callout strong { color: var(--warn); }
table { width: 100%; border-collapse: collapse; font-size: .9375rem; }
caption { text-align: left; color: var(--muted); font-size: .875rem; padding-bottom: .5rem; }
th, td { text-align: left; padding: .625rem .75rem; border-bottom: 1px solid var(--line); vertical-align: top; }
th { font-size: .75rem; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); font-weight: 600; }
td.n, th.n { text-align: right; font-variant-numeric: tabular-nums; }
tbody tr:hover { background: color-mix(in oklab, var(--panel) 70%, var(--accent) 6%); }
code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .875em; }
.zero { color: var(--muted); }
.scroll { overflow-x: auto; -webkit-overflow-scrolling: touch; }
.skip {
  position: absolute; left: -9999px; top: 0;
  background: var(--panel); color: var(--ink); padding: .75rem 1rem;
  border: 1px solid var(--line); border-radius: 0 0 8px 0; z-index: 10;
}
.skip:focus { left: 0; }
nav { margin: 0 0 1.5rem; font-size: .9375rem; }
nav a { font-weight: 500; }
.bar { width: 100%; height: 2.5rem; display: block; margin: .25rem 0 .5rem; }
.legend { display: flex; flex-wrap: wrap; gap: 1rem; margin: 0; padding: 0; list-style: none; font-size: .875rem; }
.legend li { display: flex; align-items: center; gap: .5rem; }
.swatch { width: .875rem; height: .875rem; border-radius: 3px; flex: 0 0 auto; }
a { color: var(--accent); }
a:focus-visible, :focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
footer { margin-top: 3.5rem; padding-top: 1.25rem; border-top: 1px solid var(--line); color: var(--muted); font-size: .875rem; }
"""


def _n(value: int) -> str:
    return f"{value:,}"


def _languages(languages: tuple[str, ...]) -> str:
    """Per-language coverage in words a reader does not have to decode.

    Success criterion 2a requires this beside every aggregate figure, so it is
    spelled out rather than shown as the grammar names the scanner uses
    internally: "tsx" is an implementation detail of which parser reads
    JavaScript, not a fact about coverage.
    """
    if "*" in languages:
        return "every language"
    if {"typescript", "tsx"} <= set(languages):
        return "TypeScript and JavaScript"
    return ", ".join(sorted(languages))


def _disclosure_bar(site: SiteData) -> str:
    """One bar: how much of what was found is published, and how much is not.

    The only chart on the page, because it is the only ratio a reader cannot
    reconstruct at a glance from the figures above it and the only one that
    changes how the rest of the page should be read. Four fifths of the
    findings are withheld, and a page of tables makes that a number rather than
    a shape.

    Inline SVG with no library. It is two rectangles; a charting dependency
    would add a way for the page to fail without adding anything a reader sees.

    `role="img"` and an accessible name, because an SVG without them is
    decoration to a screen reader - and a reader who cannot see it still gets
    every number from the text beside it, which is why the chart is a second
    presentation of the figures rather than the only one.
    """
    found = max(site.findings_found, 1)
    published = site.findings_published / found * 100
    label = (
        f"{_n(site.findings_published)} of {_n(site.findings_found)} findings published, "
        f"{_n(site.withheld)} withheld, none disclosed"
    )
    return f"""  <svg class="bar" viewBox="0 0 100 8" preserveAspectRatio="none"
       role="img" aria-label="{escape(label, quote=True)}">
    <rect x="0" y="0" width="100" height="8" rx="1" fill="var(--muted)"></rect>
    <rect x="0" y="0" width="{published:.2f}" height="8" rx="1" fill="var(--accent)"></rect>
  </svg>
  <ul class="legend">
    <li><span class="swatch" style="background: var(--accent)"></span>
        {_n(site.findings_published)} published ({published:.0f}%)</li>
    <li><span class="swatch" style="background: var(--muted)"></span>
        {_n(site.withheld)} withheld, none disclosed ({100 - published:.0f}%)</li>
  </ul>"""


def render_overview(site: SiteData) -> str:
    """The overview page, as one self-contained document.

    Ordered by what a reviewer asks, in the order they ask it: what this is,
    how much of the ecosystem was examined, what was found, what is being held
    back and why, and how often it is right. The last question has no answer
    yet, and the page says so rather than leaving the reader to assume the
    findings are all real - which is the claim this project exists not to make.
    """
    sampled = (
        f"{_n(site.sampled)} sampled"
        if site.sampled is not None
        else "whole corpus"
    )
    seed_note = (
        f" Sample drawn by ordering every repository by "
        f"<code>sha256(&quot;{site.sample_seed}:&lt;server&gt;&quot;)</code> and taking the first "
        f"{_n(site.sampled)}, so the same set can be regenerated."
        if site.sampled is not None
        else ""
    )
    share = site.scanned / site.corpus * 100 if site.corpus else 0.0

    rules = "\n".join(
        f"      <tr><td><strong>{escape(r.title)}</strong><br>"
        f'<span class="note"><code>{escape(r.rule_id)}</code> &middot; {_languages(r.languages)}</span></td>'
        f'<td class="n">{_n(r.found)}</td>'
        f'<td class="n{"" if r.findings else " zero"}">{_n(r.findings)}</td>'
        f'<td class="n{"" if r.found - r.findings else " zero"}">{_n(r.found - r.findings)}</td>'
        f'<td class="n{"" if r.servers else " zero"}">{_n(r.servers)}</td></tr>'
        for r in site.rules
    )
    coverage = "\n".join(
        f"      <tr><td><code>{escape(c.rule_id)}</code></td>"
        f"<td>{escape(c.title)}</td><td>{_languages(c.languages)}</td></tr>"
        for c in site.coverage
    )
    top = "\n".join(
        f'      <tr><td><a href="servers/{server_slug(g.server_id)}.html">'
        f"<code>{escape(g.server_id)}</code></a></td>"
        f"<td>{escape(g.evidence)}</td>"
        f'<td class="n">{_n(g.occurrences)}</td></tr>'
        for g in sorted(site.groups, key=lambda g: -g.occurrences)[:10]
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MCP Security Observatory</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3E%3Cpath fill='%231f6feb' d='M8 1 2 3.5v4.2c0 3.6 2.5 6.6 6 7.3 3.5-.7 6-3.7 6-7.3V3.5L8 1Z'/%3E%3C/svg%3E">
<meta name="description" content="A risk index for Model Context Protocol servers, published with its own measured accuracy.">
<style>{_STYLE}</style>
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<div class="wrap">
<header>
  <h1>MCP Security Observatory</h1>
  <p class="lede">A risk index for Model Context Protocol servers. Static analysis over
  published servers, with the scanner&rsquo;s own accuracy measured on a random sample of its
  output and published beside the results.</p>
</header>

<nav aria-label="Sections">
  <a href="findings.html">Browse all published findings &rarr;</a>
</nav>

<main id="main">
  <h2>What was examined</h2>
  <ul class="chain">
    <li><span class="k">Known repositories</span><div class="v">{_n(site.corpus)}</div>
        <div class="sub">collapsed from the public registry</div></li>
    <li><span class="k">Selected</span><div class="v">{_n(site.sampled) if site.sampled else _n(site.corpus)}</div>
        <div class="sub">{escape(sampled)}</div></li>
    <li><span class="k">Scanned</span><div class="v">{_n(site.scanned)}</div>
        <div class="sub">{share:.1f}% of known repositories</div></li>
    <li><span class="k">Skipped</span><div class="v">{_n(site.skipped)}</div>
        <div class="sub">not provably a server</div></li>
    <li><span class="k">Failed</span><div class="v">{_n(site.failed)}</div>
        <div class="sub">unreachable or over caps</div></li>
  </ul>
  <p class="note">Scanned on {escape(site.generated_at)}.{seed_note}</p>

  <h2>What was found</h2>
  <ul class="chain">
    <li><span class="k">Findings</span><div class="v">{_n(site.findings_found)}</div>
        <div class="sub">across {_n(site.scanned)} servers scanned</div></li>
    <li><span class="k">Published</span><div class="v">{_n(site.findings_published)}</div>
        <div class="sub">{_n(site.decisions_published)} distinct decisions</div></li>
    <li><span class="k">Withheld</span><div class="v">{_n(site.withheld)}</div>
        <div class="sub">high and critical, none disclosed</div></li>
    <li><span class="k">Servers affected</span><div class="v">{_n(site.servers_affected)}</div>
        <div class="sub">in the published set</div></li>
  </ul>

  <div class="callout">
    <p><strong>How often is this right? Not yet measured.</strong> 288 findings have been
    drawn at random from this output and are being labelled by hand; per-rule precision and
    recall will be published here with the threshold they were measured at, and the labelled
    set will ship as an open benchmark. Until then, treat every finding below as a candidate
    rather than a confirmed problem.</p>
  </div>

{_disclosure_bar(site)}

  <div class="callout">
    <p><strong>{_n(site.withheld)} of {_n(site.findings_found)} findings are not shown.</strong>
    Every high and critical finding is withheld, so the table below is the least severe part of
    what was found and is not a picture of the ecosystem&rsquo;s worst problems.
    <strong>No maintainer has been notified:</strong> notification is not implemented, a
    disclosure window opens only when a notification is recorded, and so nothing above medium
    severity has ever been published. The gate failing closed is the intended direction.
    Maintainer opt-out is honoured unconditionally.</p>
  </div>

  <h2>By rule <span class="n">&mdash; published</span></h2>
  <div class="scroll">
  <table>
    <caption>Found is every finding the rule produced. Published is what cleared the
    disclosure gate. A rule can find hundreds and publish none, which is what four of these
    five do.</caption>
    <thead><tr><th scope="col">Rule</th><th scope="col" class="n">Found</th><th scope="col" class="n">Published</th><th scope="col" class="n">Withheld</th><th scope="col" class="n">Servers</th></tr></thead>
    <tbody>
{rules}
    </tbody>
  </table>
  </div>
  <p class="note">A rule showing zero has published nothing, not found nothing: four of the
  five emit above medium severity and are withheld in full by the disclosure gate.</p>

  <h2>Language coverage</h2>
  <div class="scroll">
  <table>
    <caption>Every aggregate figure on this page is bounded by this table. A percentage
    derived from TypeScript is never presented as an ecosystem-wide one.</caption>
    <thead><tr><th scope="col">Rule</th><th scope="col">Detects</th><th scope="col">Examines</th></tr></thead>
    <tbody>
{coverage}
    </tbody>
  </table>
  </div>

  <h2>Most repeated decisions <span class="n">&mdash; published</span></h2>
  <div class="scroll">
  <table>
    <caption>One misconfiguration set on many response paths. Counting the rows instead of
    the decisions would overstate these servers roughly twofold.</caption>
    <thead><tr><th scope="col">Server</th><th scope="col">What the rule reported</th><th scope="col" class="n">Lines</th></tr></thead>
    <tbody>
{top}
    </tbody>
  </table>
  </div>
</main>

<footer>
  <p>Scanner version {escape(site.tool_version)}. Scanned {escape(site.generated_at)},
  published {escape(site.published_at)}. Findings, SARIF and the coverage summary are
  committed to the repository, so this page is reproducible from published data alone.</p>
  <p>Never runs the code it examines. Reads only public repositories.
  Every figure above is computed from the committed data and the method is
  published, so this page is reproducible rather than asserted.</p>
  <p>Built by {escape(AUTHOR)} &middot;
     <a href="{REPOSITORY}" rel="noopener">Source, decision log and disclosure policy</a></p>
</footer>
</div>
</body>
</html>
"""


def server_slug(server_id: str) -> str:
    """A path segment for one server.

    Server ids are registry names carrying dots and a slash -
    `io.github.Trusty-Squire/mcp` - and neither a slash nor mixed case belongs
    in a path that has to work on a case-insensitive filesystem and in a URL.
    The slash becomes a double dash, which cannot arise from a single dash in
    the original and so keeps the mapping injective for ordinary ids.
    """
    return server_id.replace("/", "--").lower()


def _slugs(site: SiteData) -> dict[str, str]:
    """Slug per affected server, refusing a collision.

    Two servers sharing a slug would silently overwrite one page with the
    other, and the maintainer of the first would read somebody else's findings.
    Lowercasing makes that possible, so it is checked rather than assumed.
    """
    slugs: dict[str, str] = {}
    seen: dict[str, str] = {}
    for server_id in sorted({group.server_id for group in site.groups}):
        slug = server_slug(server_id)
        if slug in seen:
            raise ValueError(
                f"slug collision: {server_id!r} and {seen[slug]!r} both become {slug!r}"
            )
        seen[slug] = server_id
        slugs[server_id] = slug
    return slugs


# The only schemes this page will put in an href. An allowlist, because the
# alternative is enumerating what a browser will execute and that list is not
# ours to keep current.
LINKABLE_SCHEMES = frozenset({"http", "https"})


def linkable(url: str) -> bool:
    """Whether this URL is safe to render as a link.

    Escaping is not sufficient and that is the point. `escape(url, quote=True)`
    prevents an attribute break-out, and `javascript:alert(1)` needs no quotes:
    it is a valid href value. A javascript: href in a published page is stored
    XSS on a public site.

    The URL arrives from `data/servers.json`, read into a plain dict, so
    `ServerRecord`'s https guarantee stops at the file boundary exactly as the
    index loader's did before it was fixed. This is the last check before public
    HTML, so it validates rather than trusting what wrote the file.

    Leading whitespace is stripped before the scheme is read, because a browser
    ignores it and `urlparse` does not - "  javascript:alert(1)" parses as a
    relative path with no scheme and would otherwise pass.
    """
    parsed = urlparse(url.strip())
    return parsed.scheme.lower() in LINKABLE_SCHEMES and bool(parsed.hostname)


def _repo_cell(server_id: str, repo_urls: dict[str, str]) -> str:
    url = repo_urls.get(server_id)
    if not url or not linkable(url):
        # Reads as unrecorded rather than rendering unlinked text: a blank cell
        # looks like a rendering fault, and echoing a rejected URL as plain text
        # puts an attacker's string on the page for no benefit.
        return '<span class="note">not recorded</span>'
    safe = escape(url, quote=True)
    return f'<a href="{safe}" rel="noopener nofollow">{escape(url)}</a>'


def _shell(title: str, body: str, *, depth: int = 0) -> str:
    """The page frame, shared so every page carries the same styles inline."""
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(title)}</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3E%3Cpath fill='%231f6feb' d='M8 1 2 3.5v4.2c0 3.6 2.5 6.6 6 7.3 3.5-.7 6-3.7 6-7.3V3.5L8 1Z'/%3E%3C/svg%3E">
<style>{_STYLE}</style>
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<div class="wrap">
{body}
<footer>
  <p><a href="{"../" * depth}index.html">Back to the overview</a></p>
  <p>Never runs the code it examines. Reads only public repositories.</p>
  <p>Built by {escape(AUTHOR)} &middot;
     <a href="{REPOSITORY}" rel="noopener">Source and engineering log</a></p>
</footer>
</div>
</body>
</html>
"""


def render_findings(site: SiteData, *, repo_urls: dict[str, str]) -> str:
    """Every published decision, grouped by the server it belongs to.

    This is how a maintainer finds their own server, so it lists all of them on
    one page rather than paginating: a browser's own find is the search, and it
    only works on what is present.
    """
    slugs = _slugs(site)
    by_server: dict[str, list[Decision]] = {}
    for group in site.groups:
        by_server.setdefault(group.server_id, []).append(group)

    rows = "\n".join(
        f"      <tr><td><a href=\"servers/{slugs[server_id]}.html\"><code>{escape(server_id)}</code></a><br>"
        f'<span class="note">{_repo_cell(server_id, repo_urls)}</span></td>'
        f'<td class="n">{len(groups)}</td>'
        f'<td class="n">{sum(g.occurrences for g in groups)}</td>'
        f"<td>{escape(', '.join(sorted({g.evidence for g in groups})))}</td></tr>"
        for server_id, groups in sorted(by_server.items())
    )

    body = f"""<header>
  <h1>Published findings</h1>
  <p class="lede">{_n(site.decisions_published)} decisions across
  {_n(site.servers_affected)} servers, from {_n(site.scanned)} scanned.
  {_n(site.withheld)} further findings are withheld pending private disclosure and do not
  appear here.</p>
</header>

<main id="main">
  <div class="callout">
    <p><strong>Looking for your own server and not finding it?</strong> A repository can be
    registered under more than one name, and findings are published under one of them, so the
    name you know may not be the name listed. The repository address beside each server is the
    reliable way to recognise your own. If your findings are high or critical they are withheld
    entirely and will not appear here at all.</p>
  </div>

  <h2>By server</h2>
  <div class="scroll">
  <table>
    <caption>A decision is one thing to fix. Lines counts how many places it appears.</caption>
    <thead><tr><th scope="col">Server</th><th scope="col" class="n">Decisions</th><th scope="col" class="n">Lines</th><th scope="col">Reported</th></tr></thead>
    <tbody>
{rows}
    </tbody>
  </table>
  </div>
</main>"""
    return _shell("Published findings", body)


def render_server(server_id: str, site: SiteData, *, repo_urls: dict[str, str]) -> str:
    """One server's published findings, and what is not shown about it."""
    groups = [g for g in site.groups if g.server_id == server_id]
    rows = "\n".join(
        f"      <tr><td>{escape(g.evidence)}</td>"
        f'<td class="n">{g.occurrences}</td>'
        f"<td><code>{escape(', '.join(g.locations))}</code></td>"
        f'<td class="note">{escape(g.first_seen[:10])}</td></tr>'
        for g in sorted(groups, key=lambda g: -g.occurrences)
    )

    body = f"""<header>
  <h1><code>{escape(server_id)}</code></h1>
  <p class="lede">{_repo_cell(server_id, repo_urls)}</p>
</header>

<main id="main">
  <div class="callout">
    <p><strong>This is not a clean bill of health.</strong> Only findings that cleared the
    disclosure gate appear below, and every high and critical finding is withheld - so this
    server may have findings that are not shown here. Notification is not implemented yet, so
    no disclosure window has opened and nothing above medium severity has been published at
    all. Accuracy has not been measured, so treat each finding below as a candidate rather
    than a confirmed problem.</p>
  </div>

  <h2>Published findings <span class="n">&mdash; {len(groups)} decision{"" if len(groups) == 1 else "s"}</span></h2>
  <div class="scroll">
  <table>
    <thead><tr><th scope="col">What the rule reported</th><th scope="col" class="n">Lines</th><th scope="col">Where</th><th scope="col">First seen</th></tr></thead>
    <tbody>
{rows}
    </tbody>
  </table>
  </div>

  <p class="note">To have findings about this server withheld from publication entirely, see
  the opt-out in <code>SECURITY.md</code>. Opt-out is honoured unconditionally.</p>
</main>"""
    return _shell(server_id, body, depth=1)


def write_site(site: SiteData, *, out_dir: Path, repo_urls: dict[str, str]) -> int:
    """Write every page, and return how many files were written.

    Per-server pages exist so a maintainer can be sent a link to their own
    findings, which is what a disclosure notice needs. That is also why the
    slug is checked for collisions rather than assumed unique: a link that
    quietly resolved to somebody else's server would send one maintainer
    another's findings.

    Stale server pages are removed. A server whose findings are all withheld
    after a rescan would otherwise keep a page nothing links to, still public
    and still naming it.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "index.html").write_text(render_overview(site), encoding="utf-8")
    (out_dir / "findings.html").write_text(
        render_findings(site, repo_urls=repo_urls), encoding="utf-8"
    )

    servers_dir = out_dir / "servers"
    servers_dir.mkdir(parents=True, exist_ok=True)
    slugs = _slugs(site)
    for server_id, slug in slugs.items():
        (servers_dir / f"{slug}.html").write_text(
            render_server(server_id, site, repo_urls=repo_urls), encoding="utf-8"
        )

    wanted = {f"{slug}.html" for slug in slugs.values()}
    for stale in servers_dir.glob("*.html"):
        if stale.name not in wanted:
            stale.unlink()

    return 2 + len(slugs)
