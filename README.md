# TheHarvester Automation Script Documentation

## Introduction
This script automates the use of **TheHarvester**, a tool for gathering emails, subdomains, IPs, and other information from various public sources. The script runs TheHarvester across multiple sources, collects the results, and summarizes the findings.

---

## Prerequisites
Before using this script, ensure you have TheHarvester installed. If not, install it using:
```bash
sudo apt update && sudo apt install theharvester
```

---

## Script Overview
The script:
1. Iterates through a list of sources.
2. Executes TheHarvester command for each source.
3. Captures and stores the output in a text file.
4. Extracts and counts **IPs, Emails, and Hosts** found.
5. Provides a summary of findings.

---

## Usage Instructions
Modify the script as needed:
- **Change the domain** to your target.
- **Adjust the limit** as required.
- **Update the sources** list if necessary.

Run the script with **sudo**:
```bash
python3 script.py
```
Results will be stored in `theharvester_output.txt`.

---

## Explanation of Parameters
- **`-d <domain>`** → Target domain for information gathering.
- **`-l <limit>`** → Number of results to fetch.
- **`-b <source>`** → Data source (e.g., Google, Bing, Censys, etc.).

---

## Useful TheHarvester Commands

### View Available Data Sources
To see all supported data sources, run:
```bash
theHarvester -h | grep "-b"
```

### Run TheHarvester for a Specific Domain
```bash
sudo theHarvester -d example.com -l 100 -b all
```

### Save Output to a File
```bash
sudo theHarvester -d example.com -l 100 -b google,bing -f output.txt
```

### Use TheHarvester with an API Key
If a source requires an API key (e.g., Censys, Hunter, etc.), configure it in TheHarvester's configuration files before running:
```bash
sudo theHarvester -d example.com -l 100 -b censys
```

---

## Output Format
```
Running: sudo theHarvester -d example.com -l 200 -b bing
...
Finished: bing
...
IPs Found: 10, Emails Found: 5, Hosts Found: 8
==================================================
Total IPs Found: 50
Total Emails Found: 20
Total Hosts Found: 35
```

---

## Notes
- Ensure you have proper permissions before running TheHarvester.
- Some sources may require API keys.
- Adjust parameters based on your target domain and use case.

---

## Disclaimer
This script is intended for ethical use only. Always obtain permission before scanning any domain.

---
