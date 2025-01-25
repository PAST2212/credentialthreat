# credentialthreat

Find leaked credentials and sensitive data (e.g., tokens, API keys) based on URL, Subdomain & JavaScript File Permutations.

**Current Version:** 2.00

## Features

### Key Features
- Subdomain Scan
- Internal URL Discovery
- Network Resource Detection (JavaScript, Configuration Files)
- Enhanced Credential Pattern Detection
- Smart URL Prioritization
- Multiprocessing based on CPU cores
- DDoS Prevention Instruments (e.g., time delays)
- Configurable URL Scan Limit (default: 100,000)

### Scanning Strategy
- **URL Prioritization**: URLs are prioritized based on their likelihood of containing sensitive data
- **Pattern Categories**:
  - High-Risk Patterns (API keys, tokens, passwords)
  - Cloud Service Credentials
  - Database Connection Strings
  - Authentication Tokens
  - Infrastructure Secrets

   
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
git clone https://github.com/PAST2212/credentialthreat
cd credentialthreat
pip install -r requirements.txt
```

## Usage

Basic usage (default setting):
```bash
python3 credentialthreat.py
```

Advanced usage (example command):
```bash
python3 credentialthreat.py --limit 200000
```

Options:
- `--limit`: Maximum number of URLs to be scanned (default: 100000)

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

## Configuration

1. Add domain name to `credentialthreat/data/input/domains.txt`

## Example Results

![Result Example 1](https://github.com/PAST2212/credentialthreat/assets/124390875/88201216-622a-475e-8162-22bd811eacbf)

![Result Example 2](https://github.com/PAST2212/credentialthreat/assets/124390875/c24536c5-c3ec-464f-a952-22a37aa89b4d)

![Result Example 3](https://github.com/PAST2212/credentialthreat/assets/124390875/b99da01b-227c-4f87-88e9-60ea2e057be6)

## Changelog

For updates, please see the [Changelog](https://github.com/PAST2212/credentialthreat/blob/master/Changelog).

## Notes

### Author
Patrick Steinhoff - [LinkedIn](https://www.linkedin.com/in/patrick-steinhoff-168892222/)

### Additional Information
- Part of credential patterns are based on Bug Bounty Hunter h4x0r-dz project: [Leaked-Credentials](https://github.com/h4x0r-dz/Leaked-Credentials)
