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
    [string]$ExportCsvPath = "AbuseIPDB_Results.csv",
    
    [Parameter(Mandatory = $false)]
    [int]$MaxAgeInDays = 90,
    
    [Parameter(Mandatory = $false)]
    [int]$ThrottleMs = 1000
)

function IsValidIP($ip) {
    return [System.Net.IPAddress]::TryParse($ip, [ref]$null)
}

function Get-ApiKeySecurely {
    try {
        $SecureKey = Read-Host -Prompt "Enter your AbuseIPDB API key" -AsSecureString
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureKey)
        $ApiKey = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($BSTR)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
        return $ApiKey
    }
    catch {
        Write-Error "Failed to securely retrieve API key: $($_.Exception.Message)"
        exit 1
    }
}

function Test-Prerequisites {
    # Validate input parameters
    $IPProvided = -not [string]::IsNullOrWhiteSpace($IP)
    $FilePathProvided = -not [string]::IsNullOrWhiteSpace($FilePath)
    
    if (-not $IPProvided -and -not $FilePathProvided) {
        Write-Error "You must specify either -IP or -FilePath."
        exit 1
    }
    
    if ($IPProvided -and $FilePathProvided) {
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
    }
}

function Get-IPList {
    if (-not [string]::IsNullOrWhiteSpace($FilePath)) {
        $IPs = Get-Content -Path $FilePath | Where-Object { 
            $_.Trim() -ne "" -and -not $_.StartsWith("#")
        }
        $ValidIPs = $IPs | Where-Object { IsValidIP $_ }
        $InvalidCount = $IPs.Count - $ValidIPs.Count
        
        if ($InvalidCount -gt 0) {
            Write-Warning "Found $InvalidCount invalid IP addresses in file. Skipping them."
        }
        
        Write-Host "Processing $($ValidIPs.Count) valid IP addresses from file." -ForegroundColor Cyan
        return $ValidIPs
    } else {
        if (-not (IsValidIP $IP)) {
            Write-Error "Invalid IP address specified: $IP"
            exit 1
        }
        return @($IP)
    }
}

function Invoke-AbuseIPDBCheck($IPAddr, $Headers) {
    $Uri = "https://api.abuseipdb.com/api/v2/check?ipAddress=$IPAddr&maxAgeInDays=$MaxAgeInDays&verbose"
    
    $params = @{
        Uri         = $Uri
        Method      = "GET"
        Headers     = $Headers
        ContentType = "application/json"
        TimeoutSec  = 30
    }
    
    return Invoke-RestMethod @params
}

function Invoke-AbuseIPDBReport($IPAddr, $Headers) {
    $Body = @{
        ip         = $IPAddr
        categories = $Categories
        comment    = $Comment
    } | ConvertTo-Json -Depth 3
    
    $params = @{
        Uri         = "https://api.abuseipdb.com/api/v2/report"
        Method      = "POST"
        Headers     = $Headers
        ContentType = "application/json"
        Body        = $Body
        TimeoutSec  = 30
    }
    
    return Invoke-RestMethod @params
}

function Format-OutputObject($data, $IPAddr, $Action) {
    if ($Action -eq "check") {
        return [PSCustomObject]@{
            IP              = $data.ipAddress
            Status          = "Success"
            Confidence      = $data.abuseConfidenceScore
            ISP             = $data.isp
            ASN             = $data.asn
            Country         = $data.countryName
            CountryCode     = $data.countryCode
            UsageType       = $data.usageType
            Domain          = $data.domain
            Hostnames       = ($data.hostnames -join ", ")
            TotalReports    = $data.totalReports
            NumDistinctUsers = $data.numDistinctUsers
            LastReportedAt  = $data.lastReportedAt
            IsPublic        = $data.isPublic
            IsWhitelisted   = $data.isWhitelisted
        }
    } else {
        return [PSCustomObject]@{
            IP              = $IPAddr
            Status          = "Reported"
            AbuseConfidence = $data.abuseConfidenceScore
            Message         = "Successfully reported to AbuseIPDB"
        }
    }
}

function Write-ResultSummary($Output, $Action) {
    $SuccessCount = ($Output | Where-Object { $_.Status -ne "Error" }).Count
    $ErrorCount = ($Output | Where-Object { $_.Status -eq "Error" }).Count
    
    Write-Host "`n=== SUMMARY ===" -ForegroundColor Magenta
    Write-Host "Total IPs processed: $($Output.Count)" -ForegroundColor White
    Write-Host "Successful $Action operations: $SuccessCount" -ForegroundColor Green
    Write-Host "Failed operations: $ErrorCount" -ForegroundColor Red
    
    if ($Action -eq "check") {
        $HighRisk = ($Output | Where-Object { 
            $_.Status -ne "Error" -and [int]$_.Confidence -ge 75 
        }).Count
        $MediumRisk = ($Output | Where-Object { 
            $_.Status -ne "Error" -and [int]$_.Confidence -ge 25 -and [int]$_.Confidence -lt 75 
        }).Count
        
        Write-Host "High risk IPs (75%+ confidence): $HighRisk" -ForegroundColor Red
        Write-Host "Medium risk IPs (25-74% confidence): $MediumRisk" -ForegroundColor Yellow
    }
}

# Main execution
try {
    Write-Host "AbuseIPDB PowerShell Script v2.0" -ForegroundColor Cyan
    Write-Host "Action: $Action" -ForegroundColor White
    
    # Run prerequisite checks
    Test-Prerequisites
    
    # Get IP list
    $IPList = Get-IPList
    
    # Get API key securely
    $ApiKey = Get-ApiKeySecurely
    $Headers = @{ 
        "Key" = $ApiKey
        "Accept" = "application/json"
        "User-Agent" = "PowerShell-AbuseIPDB-Script/2.0"
    }
    
    # Process IPs
    $Output = @()
    $ProcessedCount = 0
    
    foreach ($IPAddr in $IPList) {
        $ProcessedCount++
        Write-Progress -Activity "Processing IPs" -Status "Processing $IPAddr ($ProcessedCount of $($IPList.Count))" -PercentComplete (($ProcessedCount / $IPList.Count) * 100)
        
        try {
            if ($Action -eq "check") {
                $response = Invoke-AbuseIPDBCheck -IPAddr $IPAddr -Headers $Headers
            } elseif ($Action -eq "report") {
                $response = Invoke-AbuseIPDBReport -IPAddr $IPAddr -Headers $Headers
            }
            
            $obj = Format-OutputObject -data $response.data -IPAddr $IPAddr -Action $Action
            $Output += $obj
            
            # Display result
            if ($Action -eq "check") {
                $Color = switch ([int]$obj.Confidence) {
                    { $_ -ge 75 } { 'Red' }
                    { $_ -ge 25 } { 'Yellow' }
                    default { 'Green' }
                }
                Write-Host "$($obj.IP) => Confidence: $($obj.Confidence)%, Country: $($obj.Country), ISP: $($obj.ISP), Reports: $($obj.TotalReports)" -ForegroundColor $Color
            } else {
                Write-Host "$($obj.IP) => Successfully reported" -ForegroundColor Green
            }
        }
        catch {
            $ErrorMsg = $_.Exception.Message
            if ($_.Exception.Response.StatusCode) {
                $StatusCode = $_.Exception.Response.StatusCode
                $ErrorMsg = "HTTP $StatusCode - $ErrorMsg"
            }
            
            Write-Warning "$IPAddr => Error: $ErrorMsg"
            $Output += [PSCustomObject]@{
                IP     = $IPAddr
                Status = "Error"
                Error  = $ErrorMsg
            }
        }
        
        # Rate limiting
        if ($ProcessedCount -lt $IPList.Count) {
            Start-Sleep -Milliseconds $ThrottleMs
        }
    }
    
    Write-Progress -Activity "Processing IPs" -Completed
    
    # Export results if requested
    if ($ExportCsv) {
        try {
            $Output | Export-Csv -Path $ExportCsvPath -NoTypeInformation -Encoding UTF8
            Write-Host "`nResults exported to: $ExportCsvPath" -ForegroundColor Cyan
        }
        catch {
            Write-Error "Failed to export CSV: $($_.Exception.Message)"
        }
    }
    
    # Display summary
    Write-ResultSummary -Output $Output -Action $Action
}
catch {
    Write-Error "Script execution failed: $($_.Exception.Message)"
    exit 1
}
finally {
    # Clear sensitive variables
    if ($ApiKey) {
        $ApiKey = $null
        [System.GC]::Collect()
    }
}
