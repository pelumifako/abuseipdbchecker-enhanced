# AbuseIPDB PowerShell Tool

PowerShell script to check or report IP addresses against AbuseIPDB.com, with support for single or bulk operations, IPv4 and IPv6, and exporting results to CSV.

---

## Features

- Check or report individual IPs or bulk IPs from a file
- Supports both IPv4 and IPv6 addresses
- Securely prompts for your AbuseIPDB API key at runtime (no hardcoding needed)
- Extracts detailed info per IP:
  - Abuse confidence score
  - ISP, ASN
  - Country, Usage type
  - Domain, Hostnames
- Graceful error handling with status reporting
- Optional CSV export for further analysis (use `-ExportCsv` switch)
- Automatically filters out invalid IP addresses from input files

---

## Requirements

- PowerShell 5.1 or higher
- An AbuseIPDB API key (create one at [AbuseIPDB](https://www.abuseipdb.com/account))

---

## Usage

### Single IP Check

```powershell
.\AbuseIPDBTool.ps1 -IP 8.8.8.8 -Action check
```

### Single IP Report

```powershell
.\AbuseIPDBTool.ps1 -IP 192.168.1.100 -Action report -Categories "14,20" -Comment "Port scanning detected"
```

### Bulk IP Check from File

```powershell
.\AbuseIPDBTool.ps1 -FilePath .\ips.txt -Action check
```

### Bulk IP Report from File

```powershell
.\AbuseIPDBTool.ps1 -FilePath .\suspicious_ips.txt -Action report -Categories "14,20"
```

### Export Results to CSV

```powershell
.\AbuseIPDBTool.ps1 -IP 1.1.1.1 -Action check -ExportCsv
```

### Custom Export Path

```powershell
.\AbuseIPDBTool.ps1 -IP 1.1.1.1 -Action check -ExportCsv -ExportCsvPath "MyResults.csv"
```

---

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-IP` | **Either this or `-FilePath`** | Single IP address to check/report |
| `-FilePath` | **Either this or `-IP`** | Path to text file containing IP addresses (one per line) |
| `-Action` | **Yes** | Either "check" or "report" |
| `-Categories` | **Yes** (for report only) | Comma-separated category IDs for reporting (e.g., "14,20") |
| `-Comment` | No | Comment to include with reports (default: empty) |
| `-ExportCsv` | No | Switch to enable CSV export |
| `-ExportCsvPath` | No | Custom path for CSV export (default: "AbuseIPDB_Results.csv") |

### Parameter Rules:
- You **must** specify either `-IP` or `-FilePath`, but **not both**
- When using `-Action report`, the `-Categories` parameter is **required**
- Use `-ExportCsv` switch to enable CSV export (optional)

---

## File Format

For bulk operations, create a text file with one IP address per line. Invalid IPs are automatically filtered out:

```
8.8.8.8
1.1.1.1
192.168.1.1
2001:4860:4860::8888
invalid-ip-here
10.0.0.1
```

---

## AbuseIPDB Category IDs

Common categories for reporting (use comma-separated for multiple):

- **3** - Fraud Orders
- **4** - DDoS Attack  
- **9** - Malware
- **10** - Botnet
- **14** - Port Scan
- **15** - Hacking
- **18** - Brute Force
- **19** - Bad Web Bot
- **20** - Exploited Host
- **21** - Web App Attack

---

## Output

- **Console**: Enhanced real-time status updates showing IP, Status, Confidence, Country, and ISP
- **CSV Export**: Optional detailed results exported to specified path (use `-ExportCsv` switch)

### CSV Columns:
- IP, Status, Confidence, ISP, ASN, Country, UsageType, Domain, Hostnames

---

## Error Handling

The script includes comprehensive error handling:

- **Invalid IP validation**: Single IPs are validated before processing
- **File existence check**: Verifies file exists before reading
- **Empty file handling**: Exits gracefully if no valid IPs found in file
- **Parameter validation**: Ensures correct parameter combinations
- **API errors**: Failed requests are logged as "Error" status in CSV output

---

## Important Notes

- **API Key Security**: The script prompts for your API key securely at runtime - never hardcode it
- **Mutually Exclusive Parameters**: Use either `-IP` OR `-FilePath`, never both
- **Categories Required for Reporting**: When using `-Action report`, you must specify `-Categories`
- **UTF-8 CSV Export**: Results are exported with UTF-8 encoding for international character support
