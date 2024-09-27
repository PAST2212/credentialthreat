# credentialthreat

Find leaked credentials and sensitive data (e.g., tokens, API keys) based on URL, Subdomain & JavaScript File Permutations.

**Current Version:** 1.11

## Features

### Key Features
- Subdomain Scan
- (Internal) URL / JavaScript File / Network File Scan
- Multiprocessing based on CPU cores
- DDoS Prevention Instruments (e.g., time delays)
- Scan up to 100,000 URLs / Network Files based on a single domain

### CSV Output
The CSV file is created in the `credentialthreat/data/output` folder with the following columns:
- Base URL: URL with affected sensitive data candidate
- Affected Network Resource from Base URL
- Registered Domain of Base URL
- Credential Sensitive Data Candidate

### Example Output
![CSV Output Example](https://github.com/PAST2212/credentialthreat/assets/124390875/4c3dca5b-ff4b-4fbf-beef-7bf7f401e203)

## Installation

```bash
git clone https://github.com/PAST2212/credentialthreat.git
cd credentialthreat
pip install -r requirements.txt
```

## Usage

1. Add root domain(s) to scan in `credentialthreat/data/input/domains.txt` (one per line, including TLD).
2. Run the script:
   ```bash
   python3 credentialthreat.py
   ```

## Updating

```bash
cd credentialthreat
git pull
```

If you encounter a merge error, try:
```bash
git reset --hard
git pull
```

**Note:** Make a backup of your userdata folder before updating.

## Example Results

![Result Example 1](https://github.com/PAST2212/credentialthreat/assets/124390875/88201216-622a-475e-8162-22bd811eacbf)

![Result Example 2](https://github.com/PAST2212/credentialthreat/assets/124390875/c24536c5-c3ec-464f-a952-22a37aa89b4d)

![Result Example 3](https://github.com/PAST2212/credentialthreat/assets/124390875/b99da01b-227c-4f87-88e9-60ea2e057be6)

## Changelog

For updates, please see the [Changelog](https://github.com/PAST2212/credentialthreat/blob/master/Changelog).

## Notes

### Author
Patrick Steinhoff - [LinkedIn](https://www.linkedin.com/in/patrick-steinhoff-168892222/)

### To-Do
- Implement PEP 8 compliance
- Add new Regex patterns

### Additional Information
- URL scans are currently capped at 100,000 URLs due to performance and capacity considerations.
- GET requests may take considerable time due to the trade-off between speed performance and DDoS prevention.
- Credit goes to Bug Bounty Hunter h4x0r-dz and their project [Leaked-Credentials](https://github.com/h4x0r-dz/Leaked-Credentials), which this project's regex is based on.
