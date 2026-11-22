"""Run from the checkout with python tests/measure_rules.py. Reads only the fixed corpus."""

from collections import Counter
from pathlib import Path
import re
import runpy
import sys

from credential_corpus import PAGES, RULES


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
Scanner = runpy.run_path(str(ROOT / "credentialthreat.py"))["ScanerCredentials"]


def observations(scanner, page):
    # Measure the production expressions before the worker redacts positions and
    # combines rule labels. An integration test checks parity with worker output.
    for match in re.finditer(scanner.credential_pattern, page.html, re.IGNORECASE | re.MULTILINE):
        yield "assignment", match.span("value"), match["label"].lower()
    for rule, pattern in scanner.additional_patterns.items():
        for match in re.finditer(pattern, page.html):
            yield rule, match.span(), rule


def measure():
    scanner = Scanner()
    if set(RULES) != {"assignment", *scanner.additional_patterns}:
        raise ValueError("Rule inventory and benchmark disagree")
    actual, shape, review = Counter(), Counter(), Counter()
    for page in PAGES:
        for rule, span, _ in observations(scanner, page):
            actual[rule, page.name, *span] += 1
        for start, end, target in page.annotations:
            for rule in target.rules:
                key = (rule, page.name, start, end)
                shape[key] += 1
                if not target.example:
                    review[key] += 1
    return actual, shape, review


def percentage(numerator, denominator):
    return f"{100 * numerator / denominator:.1f}%" if denominator else "n/a"


def locations(counts, rule):
    return ", ".join(f"{page}@{start}:{end}" for name, page, start, end in counts.elements()
                     if rule == name) or "-"


def print_score(title, actual, expected):
    tp = actual & expected
    fp = actual - expected
    fn = expected - actual
    print(f"\n{title}")
    print("Rule          TP  FP  FN  Precision   Recall")
    for rule in RULES:
        correct, extra, missed = [sum(n for key, n in counts.items() if key[0] == rule)
                                  for counts in (tp, fp, fn)]
        print(f"{rule:12} {correct:3} {extra:3} {missed:3} "
              f"{percentage(correct, correct + extra):>9} {percentage(correct, correct + missed):>8}")
        print(f"  FP: {locations(fp, rule)}  FN: {locations(fn, rule)}")


if __name__ == "__main__":
    actual, shape, review = measure()
    print(f"{len(PAGES)} HTML responses, {shape.total()} labeled rule occurrences, "
          f"{review.total()} requiring owner review.")
    print_score("Format recognition", actual, shape)
    print_score("Owner review", actual, review)
