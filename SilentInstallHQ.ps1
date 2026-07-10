#requires -Version 5.1
<#
.SYNOPSIS
    Analyze Windows installer files or public installer URLs using SilentInstallHQ.

.DESCRIPTION
    Supports:
    - Public HTTPS installer URL
    - Local installer file
    - Local files over 50 MB using SilentInstallHQ async large-file flow
    - API key from parameter or environment variables
    - Null-safe output: shows "Not returned" instead of blank values
    - Optional VirusTotal lookup by SHA256 using VirusTotal API

.NOTES
    This script does NOT upload files to VirusTotal.
    VirusTotal check only queries an existing VT report by SHA256.

.EXAMPLES
    .\SilentInstallHQ.ps1 `
        -Source "https://github.com/ip7z/7zip/releases/download/26.02/7z2602-x64.msi" `
        -OutFile "C:\Temp\7zip-profile.json"

    .\SilentInstallHQ.ps1 `
        -Source "C:\Temp\GoogleChromeStandaloneEnterprise_Arm64.msi" `
        -OutFile "C:\Temp\chrome-profile.json"

    .\SilentInstallHQ.ps1 `
        -Source "C:\Temp\GoogleChromeStandaloneEnterprise_Arm64.msi" `
        -OutFile "C:\Temp\chrome-profile.json" `
        -CheckVirusTotal
#>

param(
    [Parameter(Mandatory)]
    [string]$Source,

    [string]$ApiKey,

    [string[]]$ApiKeyEnvVarNames = @(
        "SIHQ_API_KEY",
        "SILENTINSTALLHQ_API_KEY",
        "SILENTINSTALLHQ_TOKEN"
    ),

    [string]$BaseUrl = "https://app.silentinstallhq.com",

    [string]$OutFile,

    [switch]$AllowDownloadLargeUrl,

    [switch]$SkipUrlPreCheck,

    [int]$PollIntervalSeconds = 7,

    [int]$PollTimeoutMinutes = 15,

    [switch]$CheckVirusTotal,

    [string]$VirusTotalApiKey,

    [string[]]$VirusTotalApiKeyEnvVarNames = @(
        "VT_API_KEY",
        "VIRUSTOTAL_API_KEY",
        "VIRUSTOTAL_TOKEN"
    )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$MaxSyncBytes = 50MB

function Get-ValueFromEnvironment {
    param(
        [Parameter(Mandatory)]
        [string[]]$Names,

        [string]$Label = "API key"
    )

    foreach ($name in $Names) {
        foreach ($scope in @("Process", "User", "Machine")) {
            $value = [Environment]::GetEnvironmentVariable($name, $scope)

            if (-not [string]::IsNullOrWhiteSpace($value)) {
                Write-Host "Using $Label from $scope environment variable: $name"
                return $value
            }
        }
    }

    return $null
}

function Get-SIHQApiKey {
    param(
        [string]$ExplicitApiKey,
        [string[]]$EnvVarNames
    )

    if (-not [string]::IsNullOrWhiteSpace($ExplicitApiKey)) {
        Write-Host "Using SilentInstallHQ API key from -ApiKey parameter."
        return $ExplicitApiKey
    }

    return Get-ValueFromEnvironment `
        -Names $EnvVarNames `
        -Label "SilentInstallHQ API key"
}

function Get-VirusTotalResolvedApiKey {
    param(
        [string]$ExplicitApiKey,
        [string[]]$EnvVarNames
    )

    if (-not [string]::IsNullOrWhiteSpace($ExplicitApiKey)) {
        Write-Host "Using VirusTotal API key from -VirusTotalApiKey parameter."
        return $ExplicitApiKey
    }

    return Get-ValueFromEnvironment `
        -Names $EnvVarNames `
        -Label "VirusTotal API key"
}

function New-SIHQHeaders {
    param([string]$Key)

    $headers = @{}

    if (-not [string]::IsNullOrWhiteSpace($Key)) {
        $headers["X-API-Key"] = $Key
    }
    else {
        Write-Warning "No SilentInstallHQ API key found. Request may use anonymous shared quota or fail depending on API policy."
    }

    return $headers
}

function Test-IsHttpsUrl {
    param([string]$Value)

    $uri = $null

    if ([System.Uri]::TryCreate($Value, [System.UriKind]::Absolute, [ref]$uri)) {
        return $uri.Scheme -eq "https"
    }

    return $false
}

function Get-WebErrorDetail {
    param([object]$ErrorRecord)

    try {
        if ($null -ne $ErrorRecord.ErrorDetails -and
            -not [string]::IsNullOrWhiteSpace($ErrorRecord.ErrorDetails.Message)) {
            return $ErrorRecord.ErrorDetails.Message
        }
    }
    catch {
    }

    try {
        $response = $ErrorRecord.Exception.Response

        if ($null -ne $response) {
            if ($response -is [System.Net.Http.HttpResponseMessage]) {
                $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()

                if (-not [string]::IsNullOrWhiteSpace($body)) {
                    return $body
                }
            }

            if ($response.GetType().GetMethod("GetResponseStream")) {
                $stream = $response.GetResponseStream()

                if ($null -ne $stream) {
                    $reader = [System.IO.StreamReader]::new($stream)
                    $body = $reader.ReadToEnd()

                    if (-not [string]::IsNullOrWhiteSpace($body)) {
                        return $body
                    }
                }
            }
        }
    }
    catch {
    }

    return $ErrorRecord.Exception.Message
}

function Get-UrlMetadata {
    param([string]$Url)

    Write-Host "Checking URL accessibility: $Url"

    try {
        $response = Invoke-WebRequest `
            -Uri $Url `
            -Method Head `
            -MaximumRedirection 5 `
            -TimeoutSec 30 `
            -UseBasicParsing

        $contentLength = 0
        $contentType = $null

        if ($response.Headers.ContainsKey("Content-Length")) {
            $rawLength = $response.Headers["Content-Length"] | Select-Object -First 1
            [void][int64]::TryParse([string]$rawLength, [ref]$contentLength)
        }

        if ($response.Headers.ContainsKey("Content-Type")) {
            $contentType = $response.Headers["Content-Type"] | Select-Object -First 1
        }

        return [pscustomobject]@{
            Url           = $Url
            StatusCode    = [int]$response.StatusCode
            ContentType   = $contentType
            ContentLength = $contentLength
        }
    }
    catch {
        Write-Warning "URL HEAD pre-check failed. SilentInstallHQ API call may still work. Details: $($_.Exception.Message)"

        return [pscustomobject]@{
            Url           = $Url
            StatusCode    = $null
            ContentType   = $null
            ContentLength = 0
        }
    }
}

function Invoke-SIHQUrlIdentify {
    param(
        [Parameter(Mandatory)]
        [string]$Url,

        [Parameter(Mandatory)]
        [hashtable]$Headers
    )

    Write-Host "Submitting public download URL to SilentInstallHQ..."

    $body = @{
        url = $Url
    } | ConvertTo-Json -Depth 10

    try {
        return Invoke-RestMethod `
            -Uri "$BaseUrl/identify/url" `
            -Method Post `
            -Headers $Headers `
            -ContentType "application/json" `
            -Body $body
    }
    catch {
        $detail = Get-WebErrorDetail -ErrorRecord $_
        throw "SilentInstallHQ URL analysis failed. $detail"
    }
}

function Invoke-SIHQLocalSyncIdentify {
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,

        [Parameter(Mandatory)]
        [hashtable]$Headers
    )

    Write-Host "Uploading local file to SilentInstallHQ sync endpoint..."

    $file = Get-Item -LiteralPath $FilePath

    try {
        return Invoke-RestMethod `
            -Uri "$BaseUrl/identify" `
            -Method Post `
            -Headers $Headers `
            -Form @{
                file = $file
            }
    }
    catch {
        $detail = Get-WebErrorDetail -ErrorRecord $_
        throw "SilentInstallHQ local file analysis failed. $detail"
    }
}

function Invoke-SIHQLocalLargeIdentify {
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,

        [Parameter(Mandatory)]
        [hashtable]$Headers
    )

    $file = Get-Item -LiteralPath $FilePath

    Write-Host "File is larger than 50 MB. Using SilentInstallHQ async large-file flow..."

    try {
        $reserveBody = @{
            filename = $file.Name
        } | ConvertTo-Json -Depth 10

        $reserve = Invoke-RestMethod `
            -Uri "$BaseUrl/identify/upload-url" `
            -Method Post `
            -Headers $Headers `
            -ContentType "application/json" `
            -Body $reserveBody

        if ($null -eq $reserve.PSObject.Properties["upload_url"] -or
            $null -eq $reserve.PSObject.Properties["job_id"]) {
            throw "SilentInstallHQ response did not contain upload_url or job_id."
        }

        $uploadUrl = $reserve.upload_url
        $jobId = $reserve.job_id

        Write-Host "Upload job ID: $jobId"
        Write-Host "Uploading binary to pre-signed upload URL..."

        Invoke-RestMethod `
            -Uri $uploadUrl `
            -Method Put `
            -ContentType "application/octet-stream" `
            -InFile $file.FullName | Out-Null

        Write-Host "Submitting analysis job..."

        $submitBody = @{
            job_id = $jobId
        } | ConvertTo-Json -Depth 10

        Invoke-RestMethod `
            -Uri "$BaseUrl/identify/submit" `
            -Method Post `
            -Headers $Headers `
            -ContentType "application/json" `
            -Body $submitBody | Out-Null

        $deadline = (Get-Date).AddMinutes($PollTimeoutMinutes)

        do {
            Start-Sleep -Seconds $PollIntervalSeconds

            $job = Invoke-RestMethod `
                -Uri "$BaseUrl/jobs/$jobId" `
                -Method Get `
                -Headers $Headers

            $status = [string]$job.status
            Write-Host "Job status: $status"

            switch ($status.ToLowerInvariant()) {
                "complete" {
                    if ($null -ne $job.PSObject.Properties["profile"]) {
                        return $job.profile
                    }

                    throw "Job completed, but no profile object was returned."
                }

                "failed" {
                    $errorMessage = "Unknown error"

                    if ($null -ne $job.PSObject.Properties["error"] -and
                        -not [string]::IsNullOrWhiteSpace([string]$job.error)) {
                        $errorMessage = [string]$job.error
                    }

                    throw "SilentInstallHQ analysis job failed. $errorMessage"
                }
            }

        } while ((Get-Date) -lt $deadline)

        throw "Timed out waiting for SilentInstallHQ job to complete. Job ID: $jobId"
    }
    catch {
        $detail = Get-WebErrorDetail -ErrorRecord $_
        throw "SilentInstallHQ large-file analysis failed. $detail"
    }
}

function Save-SIHQProfile {
    param(
        [Parameter(Mandatory)]
        [object]$Profile,

        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return
    }

    $folder = Split-Path -Path $Path -Parent

    if (-not [string]::IsNullOrWhiteSpace($folder)) {
        if (-not (Test-Path -LiteralPath $folder)) {
            New-Item -Path $folder -ItemType Directory -Force | Out-Null
        }
    }

    $Profile |
        ConvertTo-Json -Depth 50 |
        Out-File -FilePath $Path -Encoding UTF8

    Write-Host "Full JSON profile saved to: $Path"
}

function Get-SIHQProperty {
    param(
        [Parameter(Mandatory)]
        [object]$InputObject,

        [Parameter(Mandatory)]
        [string[]]$Names
    )

    foreach ($name in $Names) {
        $property = $InputObject.PSObject.Properties |
            Where-Object { $_.Name -ieq $name } |
            Select-Object -First 1

        if ($null -ne $property) {
            return $property.Value
        }
    }

    return $null
}

function Format-SIHQValue {
    param(
        [object]$Value,

        [string]$Default = "Not returned"
    )

    if ($null -eq $Value) {
        return $Default
    }

    if ($Value -is [string] -and [string]::IsNullOrWhiteSpace($Value)) {
        return $Default
    }

    return $Value
}

function Get-SIHQArrayDisplay {
    param([object]$Value)

    if ($null -eq $Value) {
        return "Not returned"
    }

    $items = @($Value)

    if ($items.Count -eq 0) {
        return "None"
    }

    return ($items -join ", ")
}

function Show-SIHQProfileSummary {
    param(
        [Parameter(Mandatory)]
        [object]$Profile
    )

    $fileSize = Get-SIHQProperty -InputObject $Profile -Names @("file_size", "FileSize")
    $fileSizeMB = $null

    if ($null -ne $fileSize) {
        $fileSizeMB = [math]::Round(([double]$fileSize / 1MB), 2)
    }

    $summary = [pscustomobject]@{
        SHA256                    = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("sha256", "SHA256"))
        FileName                  = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("filename", "FileName"))
        FileSizeMB                = Format-SIHQValue $fileSizeMB
        ProductName               = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("product_name", "ProductName"))
        Publisher                 = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("publisher", "Publisher"))
        ProductVersion            = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("product_version", "ProductVersion"))
        InstallerType             = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("installer_type", "InstallerType"))
        DetectedEngine            = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("detected_engine", "DetectedEngine"))
        EngineSource              = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("engine_source", "EngineSource"))
        Architecture              = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("architecture", "Architecture"))
        ArchitectureSource        = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("architecture_source", "ArchitectureSource"))
        IsSigned                  = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("is_signed", "DigitallySigned"))
        Signer                    = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("signer", "Signer"))
        Issuer                    = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("issuer", "Issuer"))
        Confidence                = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("confidence", "ReadinessScore"))
        SilentInstall             = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("silent_install", "SilentInstall"))
        SilentInstallSource       = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("silent_install_source", "SilentInstallSource"))
        SilentInstallVerifiedAt   = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("silent_install_verified_at", "SilentInstallVerifiedAt"))
        SilentInstallVerifiedVer  = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("silent_install_verified_version", "SilentInstallVerifiedVersion"))
        SilentUninstall           = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("silent_uninstall", "SilentUninstall"))
        RepairCommand             = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("repair_command", "RepairCommand"))
        LoggingCommand            = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("logging_command", "LoggingCommand"))
        ProductCode               = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("product_code", "ProductCode"))
        UpgradeCode               = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("upgrade_code", "UpgradeCode"))
        IntuneRuleSource          = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("intune_rule_source", "IntuneRuleSource"))
        WingetPackageId           = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("winget_package_id", "WingetPackageId"))
        WingetVersion             = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("winget_version", "WingetVersion"))
        WingetEnrichedAt          = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("winget_enriched_at", "WingetEnrichedAt"))
        InstallScope              = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("install_scope", "InstallScope"))
        ElevationRequirement      = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("elevation_requirement", "ElevationRequirement"))
        UpgradeBehavior           = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("upgrade_behavior", "UpgradeBehavior"))
        MinimumOSVersion          = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("minimum_os_version", "MinimumOSVersion"))
        InstallerLocale           = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("installer_locale", "InstallerLocale"))
        SupportedLocales          = Get-SIHQArrayDisplay (Get-SIHQProperty -InputObject $Profile -Names @("supported_locales", "SupportedLocales"))
        LocaleBehavior            = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("locale_behavior", "LocaleBehavior"))
        LocaleSource              = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("locale_source", "LocaleSource"))
        Description               = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("description", "Description"))
        HomePageUrl               = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("homepage_url", "HomepageUrl"))
        License                   = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("license", "License"))
        LicenseUrl                = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("license_url", "LicenseUrl"))
        PrivacyUrl                = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("privacy_url", "PrivacyUrl"))
        SupportUrl                = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("support_url", "SupportUrl"))
        ReleaseNotes              = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("release_notes", "ReleaseNotes"))
        ReleaseNotesUrl           = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("release_notes_url", "ReleaseNotesUrl"))
        VirusTotal                = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("vt_permalink", "VirusTotal"))
        RecordSource              = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("record_source", "RecordSource"))
        SubmittedAt               = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("submitted_at", "SubmittedAt"))
        SubmissionCount           = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("submission_count", "SubmissionCount"))
        LastSeen                  = Format-SIHQValue (Get-SIHQProperty -InputObject $Profile -Names @("last_seen", "LastSeen"))
    }

    Write-Host ""
    Write-Host "SilentInstallHQ validation completed successfully."
    Write-Host ""

    $summary | Format-List

    $intuneRule = Get-SIHQProperty -InputObject $Profile -Names @(
        "intune_rule",
        "IntuneRule",
        "detection_rule",
        "DetectionRule"
    )

    if ($null -ne $intuneRule) {
        Write-Host ""
        Write-Host "Intune Detection Rule:"
        $intuneRule | ConvertTo-Json -Depth 30
    }

    $warnings = Get-SIHQProperty -InputObject $Profile -Names @(
        "warnings",
        "Warnings"
    )

    if ($null -ne $warnings) {
        $warningItems = @($warnings)

        if ($warningItems.Count -gt 0) {
            Write-Host ""
            Write-Warning "Warnings returned by SilentInstallHQ:"

            foreach ($warning in $warningItems) {
                Write-Warning $warning
            }
        }
    }

    $sourceUrls = Get-SIHQProperty -InputObject $Profile -Names @(
        "source_urls",
        "SourceUrls"
    )

    if ($null -ne $sourceUrls -and @($sourceUrls).Count -gt 0) {
        Write-Host ""
        Write-Host "Source URLs:"
        foreach ($sourceUrl in @($sourceUrls)) {
            Write-Host "- $sourceUrl"
        }
    }
}

function Get-VirusTotalFileReport {
    param(
        [Parameter(Mandatory)]
        [string]$Sha256,

        [Parameter(Mandatory)]
        [string]$ApiKey
    )

    $headers = @{
        "x-apikey" = $ApiKey
    }

    try {
        return Invoke-RestMethod `
            -Uri "https://www.virustotal.com/api/v3/files/$Sha256" `
            -Method Get `
            -Headers $headers
    }
    catch {
        $detail = Get-WebErrorDetail -ErrorRecord $_
        throw "VirusTotal file report lookup failed. $detail"
    }
}

function Show-VirusTotalSummary {
    param(
        [Parameter(Mandatory)]
        [object]$VirusTotalReport
    )

    if ($null -eq $VirusTotalReport.PSObject.Properties["data"]) {
        Write-Warning "VirusTotal response does not contain data object."
        return
    }

    $attributes = $VirusTotalReport.data.attributes

    if ($null -eq $attributes.PSObject.Properties["last_analysis_stats"]) {
        Write-Warning "VirusTotal response does not contain last_analysis_stats."
        return
    }

    $stats = $attributes.last_analysis_stats

    $malicious = if ($null -ne $stats.PSObject.Properties["malicious"]) { [int]$stats.malicious } else { 0 }
    $suspicious = if ($null -ne $stats.PSObject.Properties["suspicious"]) { [int]$stats.suspicious } else { 0 }
    $harmless = if ($null -ne $stats.PSObject.Properties["harmless"]) { [int]$stats.harmless } else { 0 }
    $undetected = if ($null -ne $stats.PSObject.Properties["undetected"]) { [int]$stats.undetected } else { 0 }
    $timeout = if ($null -ne $stats.PSObject.Properties["timeout"]) { [int]$stats.timeout } else { 0 }
    $confirmedTimeout = if ($null -ne $stats.PSObject.Properties["confirmed-timeout"]) { [int]$stats."confirmed-timeout" } else { 0 }
    $failure = if ($null -ne $stats.PSObject.Properties["failure"]) { [int]$stats.failure } else { 0 }
    $typeUnsupported = if ($null -ne $stats.PSObject.Properties["type-unsupported"]) { [int]$stats."type-unsupported" } else { 0 }

    $passed = $harmless + $undetected
    $detections = $malicious + $suspicious
    $scanIssues = $timeout + $confirmedTimeout + $failure + $typeUnsupported
    $total = $passed + $detections + $scanIssues

    Write-Host ""
    Write-Host "VirusTotal Summary:"
    Write-Host ""

    [pscustomobject]@{
        TotalEngines       = $total
        PassedClean        = $passed
        Malicious          = $malicious
        Suspicious         = $suspicious
        DetectionFailed    = $detections
        ScanIssueOrSkipped = $scanIssues
        Harmless           = $harmless
        Undetected         = $undetected
        Timeout            = $timeout
        ConfirmedTimeout   = $confirmedTimeout
        Failure            = $failure
        TypeUnsupported    = $typeUnsupported
    } | Format-List

    if ($null -eq $attributes.PSObject.Properties["last_analysis_results"]) {
        Write-Warning "VirusTotal response does not contain last_analysis_results."
        return
    }

    $engineResults = foreach ($engineProperty in $attributes.last_analysis_results.PSObject.Properties) {
        $engineName = $engineProperty.Name
        $engineData = $engineProperty.Value

        [pscustomobject]@{
            Engine     = $engineName
            Category   = $engineData.category
            Result     = $engineData.result
            Method     = $engineData.method
            EngineName = $engineData.engine_name
            Version    = $engineData.engine_version
            Update     = $engineData.engine_update
        }
    }

    $failedEngines = $engineResults |
        Where-Object { $_.Category -in @("malicious", "suspicious") } |
        Sort-Object Category, Engine

    if (@($failedEngines).Count -gt 0) {
        Write-Host ""
        Write-Warning "VirusTotal detections found. Engines reporting malicious/suspicious:"
        $failedEngines | Format-Table Engine, Category, Result, Version, Update -AutoSize
    }
    else {
        Write-Host ""
        Write-Host "VirusTotal detections: none. No engine reported malicious or suspicious."
    }

    $issueEngines = $engineResults |
        Where-Object { $_.Category -in @("timeout", "confirmed-timeout", "failure") } |
        Sort-Object Category, Engine

    if (@($issueEngines).Count -gt 0) {
        Write-Host ""
        Write-Warning "VirusTotal scan issues. Engines that failed/timed out:"
        $issueEngines | Format-Table Engine, Category, Result, Version, Update -AutoSize
    }
}

try {
    $resolvedApiKey = Get-SIHQApiKey `
        -ExplicitApiKey $ApiKey `
        -EnvVarNames $ApiKeyEnvVarNames

    $headers = New-SIHQHeaders -Key $resolvedApiKey

    $profile = $null

    if (Test-IsHttpsUrl -Value $Source) {

        if ($SkipUrlPreCheck) {
            $profile = Invoke-SIHQUrlIdentify `
                -Url $Source `
                -Headers $headers
        }
        else {
            $urlInfo = Get-UrlMetadata -Url $Source

            Write-Host "URL status code : $($urlInfo.StatusCode)"
            Write-Host "Content-Type    : $($urlInfo.ContentType)"
            Write-Host "Content-Length  : $($urlInfo.ContentLength) bytes"

            if ($urlInfo.ContentLength -gt $MaxSyncBytes) {
                if (-not $AllowDownloadLargeUrl) {
                    throw "URL file appears larger than 50 MB. Re-run with -AllowDownloadLargeUrl to download locally and use async upload flow."
                }

                $uri = [System.Uri]$Source
                $fileName = [System.IO.Path]::GetFileName($uri.AbsolutePath)

                if ([string]::IsNullOrWhiteSpace($fileName)) {
                    $fileName = "sihq-download.bin"
                }

                $tempFile = Join-Path $env:TEMP $fileName

                Write-Host "Downloading large URL to local temp file: $tempFile"

                Invoke-WebRequest `
                    -Uri $Source `
                    -OutFile $tempFile `
                    -MaximumRedirection 5 `
                    -TimeoutSec 900 `
                    -UseBasicParsing

                $profile = Invoke-SIHQLocalLargeIdentify `
                    -FilePath $tempFile `
                    -Headers $headers
            }
            else {
                $profile = Invoke-SIHQUrlIdentify `
                    -Url $Source `
                    -Headers $headers
            }
        }
    }
    else {
        if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
            throw "Source is not a valid HTTPS URL or local file path: $Source"
        }

        $file = Get-Item -LiteralPath $Source

        Write-Host "Local file : $($file.FullName)"
        Write-Host "File size  : $($file.Length) bytes"

        if ($file.Length -le $MaxSyncBytes) {
            $profile = Invoke-SIHQLocalSyncIdentify `
                -FilePath $file.FullName `
                -Headers $headers
        }
        else {
            $profile = Invoke-SIHQLocalLargeIdentify `
                -FilePath $file.FullName `
                -Headers $headers
        }
    }

    Save-SIHQProfile `
        -Profile $profile `
        -Path $OutFile

    Show-SIHQProfileSummary -Profile $profile

    if ($CheckVirusTotal) {
        $sha256 = Get-SIHQProperty -InputObject $profile -Names @("sha256", "SHA256")

        if ([string]::IsNullOrWhiteSpace($sha256)) {
            Write-Warning "Skipping VirusTotal check because SHA256 was not found in SilentInstallHQ profile."
        }
        else {
            $resolvedVirusTotalApiKey = Get-VirusTotalResolvedApiKey `
                -ExplicitApiKey $VirusTotalApiKey `
                -EnvVarNames $VirusTotalApiKeyEnvVarNames

            if ([string]::IsNullOrWhiteSpace($resolvedVirusTotalApiKey)) {
                Write-Warning "Skipping VirusTotal check because no VirusTotal API key was found."
                Write-Warning "Set VT_API_KEY or pass -VirusTotalApiKey."
            }
            else {
                $vtReport = Get-VirusTotalFileReport `
                    -Sha256 $sha256 `
                    -ApiKey $resolvedVirusTotalApiKey

                Show-VirusTotalSummary -VirusTotalReport $vtReport
            }
        }
    }

    exit 0
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}