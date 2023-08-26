
$banner = @"


╔╗╔╔═╗╦ ╦╔═╗╔═╗  ╔╦╗╔═╗╦╦═╗  ╔╦╗┌─┐┌─┐┬  ┌─┐
║║║╠═╣║ ║╚═╗╚═╗   ║║╠╣ ║╠╦╝   ║ │ ││ ││  └─┐
╝╚╝╩ ╩╚═╝╚═╝╚═╝  ═╩╝╚  ╩╩╚═   ╩ └─┘└─┘┴─┘└─┘
        |    GitHub: https://github.com/Ibrahroot
        |   Twitter: https://twitter.com/ib_root
        |  LinkedIn: https://www.linkedin.com/in/iocs

"@ 

# Define a function to "type" each character of the banner with a delay 
function TypeEffect($text) { 
    foreach ($char in $text.ToCharArray()) { 
        Write-Host -NoNewline $char -ForegroundColor Cyan 
        Start-Sleep -Milliseconds 0.001 
    } 
} 

# Call the function with our banner 
TypeEffect $banner 

function Typing-Effect { 
    param ( 
        [string]$Text, 
        [ConsoleColor]$Color = "White", 
        [int]$Delay = 0.3 
    ) 
    for ($i = 0; $i -lt $Text.Length; $i++) { 
        Write-Host -NoNewline -ForegroundColor $Color $Text[$i] 
        Start-Sleep -Milliseconds $Delay 
    } 
    Write-Host "" 
} 

Typing-Effect "[-----------------------------------------[Choose Option]-----------------------------------------]" -Color Cyan 

$chosenOption = $null 
while ($null -eq $chosenOption) { 
    Typing-Effect "1. Hash Search via VirusTotal 
2. DNS/IP Search via SecurityTrails 
3. Active Network Connections Analysis using AbuseIPDB" -Color Yellow 
    $chosenOption = Read-Host "Choose your option (1, 2, or 3)" 
    if ("1", "2", "3" -notcontains $chosenOption) { 
        Typing-Effect "[!] Invalid option. Please select 1, 2, or 3." -Color Red 
        $chosenOption = $null 
    } 
} 

# Option 1: Hash Search via VirusTotal 
if ($chosenOption -eq "1") {
    Typing-Effect "Enter the hash value you want to search for:" -Color Yellow
    $hashToSearch = Read-Host

    # Define VirusTotal API Key
    $VTApiKey = "VirusTotal API Key"

    try {
        # Get Report from VirusTotal
        $VTReport = Invoke-RestMethod -Method "GET" -Uri "https://www.virustotal.com/api/v3/files/$hashToSearch" -Headers @{"x-apikey" = $VTApiKey}

        $results = @()

        if ($VTReport.data.attributes.last_analysis_stats) {
            $malicious = $VTReport.data.attributes.last_analysis_stats.malicious
            $undetected = $VTReport.data.attributes.last_analysis_stats.undetected

            # Create a custom object with the desired properties
            $result = [PSCustomObject]@{
                'MD5' = $VTReport.data.attributes.md5
                'SHA1' = $VTReport.data.attributes.sha1
                'SHA256' = $VTReport.data.attributes.sha256
                'VHash' = $VTReport.data.attributes.vhash
                'SSDeep' = $VTReport.data.attributes.ssdeep
                'Type Description' = $VTReport.data.attributes.type_description
                'Size' = $VTReport.data.attributes.size
                'Names' = ($VTReport.data.attributes.names -join ', ')
                'PE Info' = $VTReport.data.attributes.pe_info
                'Malicious Detections' = $malicious
                'Undetected' = $undetected
            }

            $results += $result

            # Display the results in GUI
            Add-Type -AssemblyName System.Windows.Forms
            [System.Windows.Forms.MessageBox]::Show(($result | Format-List | Out-String), "VirusTotal Report", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)

            # Save the results to a CSV file in the script directory
            $currentDate = Get-Date -Format "yyyy-MM-dd_HH_mm_ss"
            $csvFileName = "${PSScriptRoot}\${hashToSearch}_${currentDate}_.csv"
            $results | Export-Csv -Path $csvFileName -NoTypeInformation

            Typing-Effect "Results saved to $csvFileName" -Color Green
        } else {
            Typing-Effect "[!] No report found for the hash ${hashToSearch}." -Color Red
        }

    } catch [System.Net.WebException] {
        # This captures HTTP errors and connectivity issues
        if ($_.Exception.Message -like "*Unable to connect to the remote server*") {
            Typing-Effect "[!] Unable to connect to VirusTotal. Please check your internet connection." -Color Red
        } else {
            Typing-Effect "[!] Hash not found or there was an issue with the request." -Color Red
        }
    } catch {
        # This captures any other general errors
        Typing-Effect "[!] An unexpected error occurred: $($_.Exception.Message)" -Color Red
    }

    Typing-Effect "[-] Press Enter to return to the main menu..." -Color Black
    Read-Host
}
 

# Option 2: DNS/IP Search via PassiveDNS 
if ($chosenOption -eq "2") { 
    # Option 2: DNS/IP Search via SecurityTrails
function Typing-Effect {
    param (
        [string]$Text,
        [string]$Color = "White"
    )
    $Text.ToCharArray() | ForEach-Object {
        Write-Host $_ -NoNewline -ForegroundColor $Color
        Start-Sleep -Milliseconds 0.1
    }
    Write-Host ""
}

function FetchSubDomainsFromSecurityTrails {
    param (
        [string]$Domain
    )
    $headers = @{
        "accept" = "application/json"
        "APIKEY" = "SecurityTrails API"
    }
    $url = "https://api.securitytrails.com/v1/domain/$Domain/subdomains"
    $response = Invoke-RestMethod -Uri $url -Headers $headers -Method GET
    return $response.subdomains
}

function FetchHistoricalDataFromSecurityTrails {
    param (
        [string]$Domain
    )
    $headers = @{
        "accept" = "application/json"
        "APIKEY" = "SecurityTrails API"
    }
    $url = "https://api.securitytrails.com/v1/history/$Domain/dns/a"
    $response = Invoke-RestMethod -Uri $url -Headers $headers -Method GET
    return $response.records
}

Typing-Effect "[----------------------------------------------[Options]----------------------------------------------]" -Color Cyan

$validPath = $false
$Domains = @() # Initialize an empty array to store the domains

Typing-Effect "[-] Enter domains one by one. Press Enter without typing anything to finish." -Color DarkBlue

do {
    $DomainInput = Read-Host "Enter a domain"
    if (-not [string]::IsNullOrWhiteSpace($DomainInput)) {
        $Domains += $DomainInput
    }
} while (-not [string]::IsNullOrWhiteSpace($DomainInput))

foreach ($Domain in $Domains) {
    Typing-Effect "[-] Querying SecurityTrails for $Domain..." -Color Yellow

    # Fetch Subdomains
    $subDomains = FetchSubDomainsFromSecurityTrails -Domain $Domain
    Typing-Effect "[--Subdomains for $Domain--]" -Color Cyan
    foreach ($subDomain in $subDomains) {
        Typing-Effect "$subDomain.$Domain" -Color Green
    }

    # Fetch Historical Data
    Typing-Effect "[--Historical Data for $Domain--]" -Color Cyan
    try {
        $historicalData = FetchHistoricalDataFromSecurityTrails -Domain $Domain
        foreach ($data in $historicalData) {
            $firstSeen = $data.first_seen
            $lastSeen = $data.last_seen
            $organizations = $data.organizations -join ', '
            $values = $data.values | ForEach-Object { $_.ip }
            $ipValues = $values -join ', '
            Typing-Effect "First Seen: $firstSeen, Last Seen: $lastSeen, Organizations: $organizations, IPs: $ipValues" -Color Green
        }
    } catch {
        Typing-Effect "[!] Error fetching historical data for ${Domain}: $($_.Exception.Message)" -Color Red
    }

    Typing-Effect "[-------------------------------------------------------------]" -Color Cyan
}


Typing-Effect "[-----------------------------------------------[Exit]------------------------------------------------]" -Color Cyan
Typing-Effect "[-] Press Enter to close this script..." -Color Red
Read-Host 
} 

# Option 3: Active Network Connections Analysis using AbuseIPDB 

if ($chosenOption -eq "3") { 
    Typing-Effect "[-] Fetching active network connections and checking against AbuseIPDB..." -Color Yellow 

    $connections = netstat -an | Where-Object { $_ -match "\d+\.\d+\.\d+\.\d+:\d+" } 

    # Define AbuseIPDB API Key 
    $AbuseIPDBApiKey = "AbuseIPDB API" 

    Typing-Effect "[--Active Network Connections with AbuseIPDB Check--]" -Color Cyan 
    foreach ($connection in $connections) { 
        if ($connection -match "(\d+\.\d+\.\d+\.\d+):\d+\s+(\d+\.\d+\.\d+\.\d+):\d+") { 
            $destinationIP = $matches[2]

            # Exclude local and private IP ranges for the destination IP
            if ($destinationIP -match "^127\." -or $destinationIP -match "^0\.0\.0\.0" -or $destinationIP -match "^10\." -or $destinationIP -match "^172\.(1[6-9]|2[0-9]|3[0-1])\." -or $destinationIP -match "^192\.168\.") {
                continue
            }

            # Check IP on AbuseIPDB 
            $headers = @{ 
                "Key" = $AbuseIPDBApiKey 
                "Accept" = "application/json" 
            } 

            try {
                $response = Invoke-RestMethod -Uri "https://api.abuseipdb.com/api/v2/check?ipAddress=$destinationIP" -Headers $headers 
                Typing-Effect "$destinationIP - Abuse Confidence Score: $($response.data.abuseConfidenceScore)%" -Color Green
            } catch {
                if ($_.Exception.Response.StatusCode.Value__ -eq 401) {
                    Typing-Effect "Error: Unauthorized access to AbuseIPDB. Please check your API key." -Color Red
                    break
                } else {
                    Typing-Effect "Error querying AbuseIPDB: $($_.Exception.Message)" -Color Red
                }
            }
        } 
    } 

    Typing-Effect "[-------------------------------------------------------------]" -Color Cyan 
} 
 
 
 

Typing-Effect "[-----------------------------------------------[Exit]------------------------------------------------]" -Color Cyan 
Typing-Effect "[-] Press Enter to close this script..." -Color Red 
Read-Host 
