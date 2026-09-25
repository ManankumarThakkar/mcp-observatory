"""The overview page: one self-contained file, generated from the site data."""

from html import escape

from analyzer.report.site import SiteData

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
  --line: #e4e4e1; --accent: #1f6feb; --warn: #9a3412; --ok: #166534;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0d0d0f; --panel: #16161a; --ink: #ececee; --muted: #9b9ba3;
    --line: #26262c; --accent: #6aa8ff; --warn: #fdba74; --ok: #86efac;
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
        f'<td class="n{"" if r.decisions else " zero"}">{_n(r.decisions)}</td>'
        f'<td class="n{"" if r.servers else " zero"}">{_n(r.servers)}</td>'
        f'<td class="n{"" if r.findings else " zero"}">{_n(r.findings)}</td></tr>'
        for r in site.rules
    )
    coverage = "\n".join(
        f"      <tr><td><code>{escape(c.rule_id)}</code></td>"
        f"<td>{escape(c.title)}</td><td>{_languages(c.languages)}</td></tr>"
        for c in site.coverage
    )
    top = "\n".join(
        f"      <tr><td><code>{escape(g.server_id)}</code></td>"
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
<meta name="description" content="A risk index for Model Context Protocol servers, published with its own measured accuracy.">
<style>{_STYLE}</style>
</head>
<body>
<div class="wrap">
<header>
  <h1>MCP Security Observatory</h1>
  <p class="lede">A risk index for Model Context Protocol servers. Static analysis over
  published servers, with the scanner&rsquo;s own accuracy measured on a random sample of its
  output and published beside the results.</p>
</header>

<main>
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
        <div class="sub">pending private disclosure</div></li>
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

  <div class="callout">
    <p><strong>{_n(site.withheld)} of {_n(site.findings_found)} findings are not shown.</strong>
    Every high and critical finding is withheld pending private disclosure to its maintainer,
    so the table below is the least severe part of what was found and is not a picture of the
    ecosystem&rsquo;s worst problems. Maintainer opt-out is honoured unconditionally.</p>
  </div>

  <h2>By rule <span class="n">&mdash; published</span></h2>
  <div class="scroll">
  <table>
    <caption>A decision is one thing a maintainer would fix. One decision often appears on
    several lines, so rows are shown separately rather than counted as problems.</caption>
    <thead><tr><th>Rule</th><th class="n">Decisions</th><th class="n">Servers</th><th class="n">Rows</th></tr></thead>
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
    <thead><tr><th>Rule</th><th>Detects</th><th>Examines</th></tr></thead>
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
    <thead><tr><th>Server</th><th>What the rule reported</th><th class="n">Lines</th></tr></thead>
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
  <p>Never runs the code it examines. Reads only public repositories.</p>
</footer>
</div>
</body>
</html>
"""
