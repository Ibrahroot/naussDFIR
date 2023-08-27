
![Logo](imglogo.png)

[![Threat-Analyzer](https://img.shields.io/badge/nauss-DFIR-red)](https://github.com/Ibrahroot/naussDFIR/)
[![Version](https://img.shields.io/badge/version-1.0-blue.svg)](https://github.com/Ibrahroot/naussDFIR/)
[![License](https://img.shields.io/badge/license-GPL-blue.svg)](LICENSE).
[![Python Version](https://img.shields.io/badge/power-shell-green)](https://www.python.org)


# nauss DFIR tool lite

`nauss DFIR tool lite` is a PowerShell-based Digital Forensic and Incident Response (DFIR) tool designed to assist security analysts and enthusiasts with various DFIR-related tasks. The tool currently supports searching for hashes via VirusTotal, DNS/IP searches via SecurityTrails, and active network connections analysis using AbuseIPDB.

## Features

1. **Hash Search via VirusTotal**: Quickly retrieve a report from VirusTotal for a given hash.
2. **DNS/IP Search via SecurityTrails**: Get subdomains and historical data for specified domains using SecurityTrails API.
3. **Active Network Connections Analysis using AbuseIPDB**: Fetch active network connections and check their reputation against AbuseIPDB.

## Usage

1. Clone the repository to your local machine.
2. Navigate to the tool's directory and run the script using PowerShell.
3. Follow the on-screen prompts.

```powershell
powershell -ExecutionPolicy Bypass -File .\nauss.ps1
```

## Prerequisites

1. PowerShell (Pre-installed on Windows systems)
2. Internet connection to interact with the APIs.

## Configuration

API keys for VirusTotal, SecurityTrails, and AbuseIPDB are required for the respective functionalities. Ensure you have these keys and configure them in the script or in a separate configuration file.

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License

[MIT License](LICENSE)

## Disclaimer

This tool is for educational purposes only. Ensure you have the necessary permissions before scanning or fetching data from third-party sources.

---

### Connect with the Developer:
- [Twitter](https://twitter.com/ib_root)
- [LinkedIn](https://www.linkedin.com/in/iocs)

---
