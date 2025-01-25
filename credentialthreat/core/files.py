#!/usr/bin/env python3

from pathlib import Path
import sys
import os
import datetime
import csv
import tldextract

DATA_DIRECORY = Path(__file__).parents[1] / 'data'
INPUT_DIRECORY = DATA_DIRECORY / 'input'
OUTPUT_DIRECORY = DATA_DIRECORY / 'output'


class ManageFiles:
    @staticmethod
    def _user_data(file: str) -> list:
        try:
            file_keywords = open(f'{INPUT_DIRECORY}/{file}', 'r', encoding='utf-8-sig')
            keywords = []
            for item in file_keywords:
                if item[0] != "#":
                    domain = item.replace("\n", "").lower().replace(",", "").replace(" ", "").strip()
                    if domain is not None and domain != '':
                        registered_domain = tldextract.extract(domain, include_psl_private_domains=True).registered_domain
                        keywords.append(registered_domain)
            file_keywords.close()

        except Exception as e:
            print(f'Something went wrong with reading User Data File. Please check file {INPUT_DIRECORY}/{file}', e)
            sys.exit()

        return keywords

    def get_domains(self) -> list:
        return self._user_data('domains.txt')

    @staticmethod
    def create_csv_result_file() -> None:
        console_file_path = f'{OUTPUT_DIRECORY}/Credential_Leak_Candidates_{datetime.date.today()}.csv'
        if not os.path.exists(console_file_path):
            header = ['Base URL', 'Affected Network Resource from Base URL', 'Registered Domain Base URL', 'Credential Leak Candidate']
            with open(console_file_path, 'w') as f:
                writer = csv.writer(f, delimiter=';')
                writer.writerow(header)

    @staticmethod
    def write_csv_result_file(iterables: list[tuple]) -> None:
        console_file_path = f'{OUTPUT_DIRECORY}/Credential_Leak_Candidates_{datetime.date.today()}.csv'
        with open(console_file_path, mode='a', newline='') as f:
            writer = csv.writer(f, delimiter=';')
            for leak_tuple in iterables:
                writer.writerow([leak_tuple[0], leak_tuple[1], tldextract.extract(leak_tuple[0], include_psl_private_domains=True).registered_domain, *leak_tuple[2]])
