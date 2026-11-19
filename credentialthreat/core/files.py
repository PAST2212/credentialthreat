#!/usr/bin/env python3

from pathlib import Path
import datetime
import csv
from credentialthreat.core.website import SUFFIXES, dns_name, report_origin

DATA_DIRECORY = Path(__file__).parents[1] / 'data'
INPUT_DIRECORY = DATA_DIRECORY / 'input'
OUTPUT_DIRECORY = DATA_DIRECORY / 'output'


def _daily_report() -> Path:
    OUTPUT_DIRECORY.mkdir(parents=True, exist_ok=True)
    report = OUTPUT_DIRECORY / f'Credential_Leak_Candidates_Redacted_{datetime.date.today()}.csv'
    try:
        stream = report.open('x', newline='', encoding='utf-8')
    except FileExistsError:
        return report
    with stream:
        header = ['Base URL', 'Affected Network Resource from Base URL', 'Registered Domain Base URL', 'Credential Leak Candidate']
        csv.writer(stream, delimiter=';').writerow(header)
    return report


class ManageFiles:
    @staticmethod
    def _user_data(file: str) -> list:
        try:
            lines = (INPUT_DIRECORY / file).read_text(encoding='utf-8-sig').splitlines()
        except FileNotFoundError:
            return []
        domains = []
        for line_number, line in enumerate(lines, 1):
            entry = line.strip()
            if not entry or entry.startswith("#"):
                continue
            host = dns_name(entry)
            if not host or not SUFFIXES(host).registered_domain:
                raise ValueError(f"Invalid domain in {file} on line {line_number}")
            domains.append(host)
        return domains

    def get_domains(self) -> list:
        return self._user_data('domains.txt')

    @staticmethod
    def create_csv_result_file() -> None:
        _daily_report()

    @staticmethod
    def write_csv_result_file(iterables: list[tuple]) -> None:
        with _daily_report().open(mode='a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f, delimiter=';')
            for origin, resource, matches in iterables:
                base = report_origin(origin)
                source = report_origin(resource)
                domain = SUFFIXES(base).registered_domain
                for label, _ in matches:
                    description = f"Unverified {label} [REDACTED]"
                    if not {"public_key", "certificate", "stripe_publishable_key"}.isdisjoint(label.split(" + ")):
                        description += " (label may identify public material)"
                    writer.writerow([base, source, domain, description])
