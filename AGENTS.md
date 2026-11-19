# Repository Guidelines

## Project Structure

`credentialthreat.py` is the Python CLI entry point. It coordinates discovery, resource scanning, and report generation. Keep shared processing in `credentialthreat/core/`, where `files.py` handles domain input and CSV output. The two active discovery providers are implemented in `credentialthreat/recon/crtsh.py` and `credentialthreat/recon/rapiddns.py`.

The CLI reads one domain per line from `credentialthreat/data/input/domains.txt` and writes dated CSV reports under `credentialthreat/data/output/`. Keep local target lists and generated findings out of contributions.

## Local Development

Use Python 3.12 or later and run commands from the repository root. The CLI runs directly from source.

- `python -m venv .venv` creates a virtual environment. Activate it with `.\.venv\Scripts\Activate.ps1` in PowerShell or `source .venv/bin/activate` in Bash.
- `python -m pip install -r requirements.txt` installs the pinned runtime dependencies.
- `python credentialthreat.py --help` checks that the CLI imports successfully and lists its options without starting a scan.
- `python -m compileall -q credentialthreat.py credentialthreat` checks Python syntax across the entry point and package.

## Coding Style

Use four-space indentation, `snake_case` for functions and variables, and `PascalCase` for classes such as `ManageFiles`. Follow the type hints in adjacent functions. The repository has no configured formatter or linter.

## Testing Guidelines

Run the offline suite with `python -m unittest discover -s tests`. Add standard-library `unittest` cases in `tests/test_<module>.py`. For changes to CSV output, use a temporary directory and assert the header and field order with synthetic records. Mock HTTP responses for provider tests. The worker termination test requires POSIX to exercise `fork`.

## Commits and Pull Requests

Recent commits use short summaries such as `Update Changelog`. Name the affected component and the change in the subject. In a pull request, describe the observable behavior, link any related issue, and list the checks you ran. For report-format changes, include a sanitized example row.
