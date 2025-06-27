param(
    [Parameter(Mandatory = $false)]
    [string]$IP,

    [Parameter(Mandatory = $false)]
    [string]$FilePath,

    [Parameter(Mandatory = $true)]
    [ValidateSet("check", "report")]
    [string]$Action,

    [Parameter(Mandatory = $false)]
    [string]$Categories,

    [Parameter(Mandatory = $false)]
    [string]$Comment = "",

    [Parameter(Mandatory = $false)]
    [switch]$ExportCsv,

    [Parameter(Mandatory = $false)]
    [string]$ExportCsvPath = "AbuseIPDB_Results.csv"
)

function IsValidIP($ip) {
    return [System.Net.IPAddress]::TryParse($ip, [ref]$null)
}

if (($null -eq $IP) -and ($null -eq $FilePath)) {
    Write-Error "You must specify either -IP or -FilePath."
    exit 1
}

if (($null -ne $IP) -and ($null -ne $FilePath)) {
    Write-Error "Specify only one of -IP or -FilePath, not both."
    exit 1
}

if ($Action -eq "report" -and [string]::IsNullOrWhiteSpace($Categories)) {
    Write-Error "Reporting requires -Categories parameter."
    exit 1
}

if ($FilePath) {
    if (!(Test-Path $FilePath)) {
        Write-Error "File not found: $FilePath"
        exit 1
    }
    $IPList = Get-Content -Path $FilePath | Where-Object { IsValidIP $_ }
} else {
    if (-not (IsValidIP $IP)) {
        Write-Error "Invalid IP address specified."
        exit 1
    }
    $IPList = @($IP)
}

# Prompt securely for API key
$SecureKey = Read-Host -Prompt "Enter your AbuseIPDB API key" -AsSecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureKey)
$ApiKey = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($BSTR)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

$Headers = @{ "Key" = $ApiKey; "Accept" = "application/json" }
$Output = @()

foreach ($IPAddr in $IPList) {
    try {
        if ($Action -eq "check") {
            $params = @{
                Uri         = "https://api.abuseipdb.com/api/v2/check?ipAddress=$IPAddr&maxAgeInDays=90&verbose"
                Method      = "GET"
                Headers     = $Headers
                ContentType = "application/json"
            }
        } elseif ($Action -eq "report") {
            $Body = @{
                ip         = $IPAddr
                categories = $Categories
                comment    = $Comment
            } | ConvertTo-Json

            $params = @{
                Uri         = "https://api.abuseipdb.com/api/v2/report"
                Method      = "POST"
                Headers     = $Headers
                ContentType = "application/json"
                Body        = $Body
            }
        }

        $response = Invoke-RestMethod @params
        $data = $response.data

        $obj = [PSCustomObject]@{
            IP         = $data.ipAddress
            Status     = "200"
            Confidence = $data.abuseConfidenceScore
            ISP        = $data.isp
            ASN        = $data.asn
            Country    = $data.countryName
            UsageType  = $data.usageType
            Domain     = $data.domain
            Hostnames  = ($data.hostnames -join ", ")
        }

        $Output += $obj

        Write-Host "$($obj.IP) => Status: $($obj.Status), Confidence: $($obj.Confidence)%, Country: $($obj.Country), ISP: $($obj.ISP)" -ForegroundColor Green
    }
    catch {
        Write-Warning "$IPAddr => Error: $_"
        $Output += [PSCustomObject]@{
            IP         = $IPAddr
            Status     = "Error"
            Confidence = ""
            ISP        = ""
            ASN        = ""
            Country    = ""
            UsageType  = ""
            Domain     = ""
            Hostnames  = ""
        }
    }
}

if ($ExportCsv) {
    $Output | Export-Csv -Path $ExportCsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "Results exported to $ExportCsvPath" -ForegroundColor Cyan
} else {
    Write-Host "ExportCsv flag not specified; results not saved to CSV." -ForegroundColor Yellow
}

