"""`secreview` command-line entry point.

Reviews either a GitHub PR (`secreview review owner/repo#42`) or a local
unified diff (`--diff <file>` / `--diff -` for stdin). Wiring only: obtain the
diff text, build a provider, run the reviewer, render the report.
"""

from __future__ import annotations

import sys
from pathlib import Path

import typer

from . import github_client
from . import report as report_mod
from .providers import AnthropicProvider, OpenAIProvider
from .providers.base import ReviewProvider
from .reviewer import review_diff

app = typer.Typer(help="LLM-assisted security code reviewer.", no_args_is_help=True)

_PROVIDERS: dict[str, type[ReviewProvider]] = {
    "anthropic": AnthropicProvider,
    "openai": OpenAIProvider,
}


def _load_diff(source: str) -> str:
    """Read a unified diff from a file path, or from stdin when source is '-'."""
    if source == "-":
        return sys.stdin.read()
    path = Path(source)
    if not path.is_file():
        raise typer.BadParameter(f"diff file not found: {source}")
    return path.read_text()


def _load_pr_diff(target: str) -> str:
    """Fetch a PR's diff from GitHub (auth via GITHUB_TOKEN), with clear errors."""
    try:
        return github_client.fetch_pr_diff(target)
    except github_client.GitHubError as e:
        raise typer.BadParameter(str(e)) from e


def _make_provider(name: str, model: str | None, thinking: bool) -> ReviewProvider:
    cls = _PROVIDERS[name]
    kwargs: dict[str, object] = {}
    if model:
        kwargs["model"] = model
    if name == "anthropic":
        kwargs["thinking"] = thinking
    return cls(**kwargs)


@app.callback()
def _main() -> None:
    """LLM-assisted security code reviewer."""
    # Present so Typer keeps the `review` subcommand name (PLAN: `secreview review`)
    # instead of collapsing the single-command app.


@app.command()
def review(
    target: str | None = typer.Argument(
        None, help="PR reference: 'owner/repo#N' or a GitHub PR URL."
    ),
    diff: str | None = typer.Option(
        None, "--diff", "-d", help="Path to a unified diff file, or '-' for stdin."
    ),
    provider: str = typer.Option(
        "anthropic", "--provider", "-p", help="LLM backend: anthropic | openai."
    ),
    model: str | None = typer.Option(
        None, "--model", "-m", help="Override the provider's default model."
    ),
    no_thinking: bool = typer.Option(
        False, "--no-thinking", help="Disable adaptive thinking (anthropic only)."
    ),
    json_out: bool = typer.Option(
        False, "--json", help="Emit machine-readable JSON instead of a table."
    ),
) -> None:
    """Review a GitHub PR or a unified diff and report security findings."""
    if provider not in _PROVIDERS:
        raise typer.BadParameter(
            f"unknown provider {provider!r}; choose from {sorted(_PROVIDERS)}"
        )
    if bool(target) == bool(diff):
        raise typer.BadParameter("provide exactly one of a PR reference or --diff.")

    diff_text = _load_pr_diff(target) if target else _load_diff(diff)
    prov = _make_provider(provider, model, thinking=not no_thinking)
    report = review_diff(diff_text, prov)

    if json_out:
        typer.echo(report_mod.to_json(report))
    else:
        report_mod.render_terminal(report)


if __name__ == "__main__":
    app()
