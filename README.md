# credentialthreat
**find leaked credentials and sensitive data (e.g. tokens, api keys, ...) on URLs / Host Names, Subdomains, Javascript Files based on a single Domain as input**

**Current Version 1.00**

# **Features**
**Key Features**
- Subdomain Scan
- (Internal) URL / Javascript File / Network File Scan
- Multiprocessing based on cpu cores
- DDOS Prevention Instruments (e.g. time delays)
- Scan up to 100.000 URLs / Network Files based on a single domain
- Making automatically get request retries (up to 3 times) in case of failing url get request

**CSV Output Columns**
- CSV File is created into data/output folder
- Base URL: URL with affected sensitive data candidate; e.g. https://www.agilecommunity.ottogroup.com/de/medien/newsroom/
- Affected Network Resource from Base URL: Network Resource File / URL that is (get) requested / connected with BASE URL; e.g. https://www.agilecommunity.ottogroup.com/wLayout22/wGlobal/layout/scripts/juicer.js
- Registered Domain Base URL: Registered Domain of Base URL; e.g. ottogroup.com
- Credential Leak Candidate: Predicted leaked data,  e.g. ('app_id', '731223346944897') <br>

**Example Screenshot: Illustration of csv file and scanned sensitive data candidates**

# **Instructions**

**How to install:**
- git clone https://github.com/PAST2212/credentialthreat.git
- cd credentialthreat
- pip install -r requirements.txt

**How to run:** <br>

- "python3 credentialthreat.py" <br>

**How to update:**
- cd credentialthreat
- git pull
- In case of a Merge Error: Try "git reset --hard" before "git pull"
  
  ==> Make sure to make a backup of your userdata folder before update

**Before the first run - How it Works:** 
- Put your root domain(s) you want to scan into this TXT file "credentialthreat/data/input/domains.txt" line per line for scanning operations (with the TLD). "hackerone.com" root domain is listed per default.

# **Changelog**
- Please see Changelog for Updates:
- https://github.com/PAST2212/credentialthreat/blob/main/Changelog

# **Notes**

**Author**
- Patrick Steinhoff (https://www.linkedin.com/in/patrick-steinhoff-168892222/)

**TO DO**
- PEP 8 Compliance
- Design Adjustments
- Add new Regex

**Additional**
- URL Scan for leaked candidates were capped to 100.000 URLs due to performance issues.
- Normalized URLS / Subdomains means typical preprocessing operations (e.g. deduplicating)
- Depending on the quantity of processed URLs, it can take a lot of time to make URL GET requests because of balancing general multiprocessing / asyncio limitations and DDOS Preventions.
