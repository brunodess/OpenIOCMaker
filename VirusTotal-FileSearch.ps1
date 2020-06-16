##########################################################################################################################################################
### Calls VirusTotal API to search File from hash and returns CSV with multiple hashes and Trend Micro Results and a list of SHA 1 hashes in TXT
### Input List must be only the hash values, can be any hash supported by VirusTotal
### 
### INSTRUCTIONS
### Input the hash list file path below, on the Set file Parameters section, inputFilePath String Variable
### Set the outputFilePath to the directory in which to save the results
### Set the apikey to your API Key on Virus Total
### If using a free apikey, leave the isFreeKey to true, to enable the throtle every 4 calls a minute and 1000 calls a day.
#### VirusTotal limits free keys to 4 calls every minute and 1000 calls every day, this script has Sleeping periods for these limitations
#### while running this I noticed the limitation seems to be 240 every hour, either way, the script sleeps for $sleepTime seconds when Quota is exceeded
##########################################################################################################################################################
$sleepTime = 600

#Set file Parameters
$inputFilePath = ""
$outputFilePath = ""

#Set VirusTotal Parameters
$apikey = ''
$VTapiURL = 'https://www.virustotal.com/api/v3/files'
##########################################################################################################################################################

$outputFileName = "$(New-Guid)"
$hashList = Get-Content $inputFilePath

$outputCSV = @()
$outputSHA1 = @()
$counter = 0

foreach ($hash in $hashList){ #hash List Iteration BEGIN
    #if($counter -gt 0 -and $counter % 4 -eq 0 ){Start-Sleep 60; echo 'Sleeping'}
    $Response = ''
    $RepeatQuery = $false
    $handler = @{}
    #$Response = Invoke-WebRequest -URI "$VTapiURL/$hash" -Headers @{"x-apikey"=$apikey} -UseBasicParsing
    Do {
        try {
            $Response = Invoke-WebRequest -URI "$VTapiURL/$hash" -Headers @{"x-apikey"=$apikey} -UseBasicParsing
            If ($Response.StatusCode -eq 200) {
                $json = ConvertFrom-Json( $Response.Content)
                $handler = [ordered]@{MD5 = $json.data.attributes.md5; SHA1 = $json.data.attributes.sha1; SHA256 = $json.data.attributes.sha256;Classification = $json.data.attributes.last_analysis_results.TrendMicro.category;Detection = $json.data.attributes.last_analysis_results.TrendMicro.result}
                $outputCSV+= $handler
                $outputSHA1+= $json.data.attributes.sha1        
            } else {$Response.StatusCode}
            $RepeatQuery = $false
            $counter++
        } catch {
            if ($_.Exception.Response.StatusCode.Value__ -eq 429) {
                $RepeatQuery = $true
                echo "Quota exceeded - Sleeping for $sleepTime seconds"
                Start-Sleep $sleepTime
            } else {
                $_.Exception.Response.StatusCode.Value__
            }
        }
    } While ($RepeatQuery)
}
$outputSHA1 | Out-File -FilePath "$($outputFilePath)SHA1-$($outputFileName).txt"
$outputCSV| ForEach-Object { 
    New-Object PSObject -Property $_ 
} | Export-Csv -Path "$($outputFilePath)CSV-$($outputFileName).csv" -NoTypeInformation