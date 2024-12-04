function Get-AccessToken {
    param (
        [String]$tenant,
        [String]$clientID,
        [String]$clientSecret,
        [String]$domain = "identitynow"
    )
    $params = @{
        uri    = "https://$tenant.api.$domain.com/oauth/token?grant_type=client_credentials&client_id=$($clientID)&client_secret=$($clientSecret)"
        method = "POST"
    }
    return (Invoke-RestMethod @params).access_token
}

function Search-IDN {
    param (
        [String]$query = "*",
        [String]$indices = "identities",
        [int]$limit = 250,
        [int]$offset = 0,
        [String]$tenant = "",
        [boolean]$progress = $true,
        [String]$searchAfter = "",
        [String]$token = "",
        [String]$domain = "identitynow"
    )
    
    $results = @()
    $response = $null

    $body = @{
        indices     = @($indices)
        query       = @{
            query = $query
        }
        sort        = @("id")
        searchAfter = @($searchAfter)
    }
    $params = @{
        method                  = "POST"
        uri                     = "https://$($tenant).api.$domain.com/v3/search?limit=1&count=true"
        body                    = (ConvertTo-Json $body)
        headers                 = @{Authorization = "Bearer $token" }
        ContentType             = "application/json"
        ResponseHeadersVariable = "responseHeader"
    }
    $response = Invoke-RestMethod @params
    if ($progress) {
        $total = [int]($responseHeader."X-Total-Count")[0]
        if ($total -eq 0) {
            return $results
        }
    }

    do {
        if ($progress) {
            Write-Progress -Activity "Getting $indices for $query" -Status "$($results.count) / $total" -PercentComplete ($results.count / $total * 100)
        }
        $body = @{
            indices     = @($indices)
            query       = @{
                query = $query
            }
            sort        = @("id")
            searchAfter = @($searchAfter)
        }
        $params = @{
            method                  = "POST"
            uri                     = "https://$($tenant).api.$domain.com/v3/search?limit=$limit"
            body                    = (ConvertTo-Json $body)
            headers                 = @{Authorization = "Bearer $token" }
            ContentType             = "application/json"
            ResponseHeadersVariable = "responseHeader"
        }
        
        $offset += $limit
        $response = Invoke-RestMethod @params
        $results += $response
        if ($response.count -gt 1) {
            $searchAfter = $response[$response.count - 1].id
        }
    } until ($response.count -lt $limit)
    if ($progress) {
        Write-Progress -Activity "Getting $indices for $query" -Completed
    }
        
    return $results
}

function Get-IDNAccounts {
    param (
        [String]$tenant,
        [Int]$offset = 0,
        [String]$filters = "",
        [string]$token,
        [String]$domain = "identitynow"
    )

    $uri = "https://$($tenant).api.$domain.com/v3/accounts?offset=$offset&filters=$filters"
    return Invoke-RestMethod -Method GET -Uri $uri -Headers @{Authorization = "Bearer $($token)" }
}

function Get-AttributeSyncReport {
    param (
        [Parameter(Mandatory)]
        [string]$tenant,
        [string]$sourceId,
        [string]$sourceName,
        [string[]]$accountAttributes,
        [string[]]$identityAttributes,
        [string]$token = "",
        [string]$clientId = "",
        [string]$clientSecret = "",
        [string]$query = "@accounts(source.name:""$sourceName"")",
        [boolean]$progress = $true,
        [String]$domain = "identitynow",
        [String]$outputDir = (Get-Location).path
    )
    # If user does not provide token check for clientId/clientSecret
    if ($token -eq "") {
        if ([string]::IsNullOrEmpty($clientId) -or [string]::IsNullOrEmpty($clientSecret)) {
            Write-Error "Supply token or clientId/clientSecret"
            return $null
        }
        Write-Host "Getting token for $tenant"
        $oAuthURI = "https://$($tenant).api.$domain.com/oauth/token"
        $token = (Invoke-RestMethod -Method Post -Uri "$($oAuthURI)?grant_type=client_credentials&client_id=$($clientID)&client_secret=$($clientSecret)").access_token
    }

    # If user supplies sourceName, get the id
    if ($sourceName) {
        Write-Host "Getting sourceId for $sourceName"
        $params = @{
            method  = "GET"
            uri     = "https://$tenant.api.$domain.com/v3/sources?filters=name eq ""$sourceName"""
            headers = @{
                Authorization = "Bearer $token"
            }
        }
        $response = Invoke-RestMethod @params
        $sourceId = $response.id
        # $sourceId = (Invoke-RestMethod @params)[0].id
        if ($null -eq $sourceId) {
            Write-Host "Null sourceId for $sourceName"
            return $null
        }
    }

    Write-Host $sourceId

    # Get the createPolicy for the source
    $params = @{
        method  = "GET"
        uri     = "https://$tenant.api.$domain.com/v3/sources/$sourceId/provisioning-policies/CREATE"
        headers = @{
            Authorization = "Bearer $token"
        }
    }
    $createPolicy = Invoke-RestMethod @params

    # Get Identity Attribute -> Account Attribute Mapping
    # Get only attributes from $accountAttributes list otherwise get all that are identityAttribute type
    $mapping = @{}
    foreach ($field in $createPolicy.fields) {
        if ($null -eq $accountAttributes -or $accountAttributes.contains($field.name)) {
            if ($field.transform.type -eq "identityAttribute") {
                $mapping[$field.name] = $field.transform.attributes.name
            }
        }
    }
    Write-Host "Create Profile Mapping:" -ForegroundColor Yellow
    Write-Host ($mapping | Out-String) -ForegroundColor Green
    
    $output = @()
    # Get Users
    $users = Search-IDN -query $query -tenant $tenant -token $token -progress $progress -domain $domain
    $usersLookup = @{}
    foreach ($user in $users) {
        $usersLookup[$user.id] = $user
    }
    $counter = 0
    $total = $users.count
    $offset = 0
    $limit = 250
    do {
        Write-Progress -Activity "Getting Accounts Offset:$offset"
        $response = Get-IDNAccounts -tenant $tenant -token $token -filters "sourceId eq ""$sourceId"" and uncorrelated eq false" -offset $offset -domain $domain
        $offset += $limit
        foreach ($account in $response) {
            try {
                if ($counter -gt $total) {
                    $counter = $total
                }
                
                $counter++
            
                $user = $usersLookup[$account.identityId]
                $object = New-Object -TypeName PSObject
                foreach ($identityAttribute in $identityAttributes) {
                    $object | Add-Member -MemberType NoteProperty -Name $identityAttribute -Value $user.attributes.$identityAttribute
                }

                $object | Add-Member -MemberType NoteProperty -Name "accountName" -Value $account.name
    
                foreach ($map in $mapping.GetEnumerator()) {
                    $accountAttribute = $map.Name
                    $identityAttribute = $map.Value
                    $identityAttributeValue = $user.attributes.$identityAttribute
                    $accountAttributeValue = $account.attributes.$accountAttribute
                    $name = "$identityAttribute|$accountAttribute"
    
                    if ($identityAttributeValue -ceq $accountAttributeValue) {
                        $object | Add-Member -MemberType NoteProperty -Name $name -Value "Synced"
                    }
                    else {
                        $object | Add-Member -MemberType NoteProperty -Name $name -Value "$identityAttributeValue|$accountAttributeValue"
                    }
                }
            
                $output += $object
            }
            catch {
                Write-Host "Could not get $($account.identityId)"
                $ErrorMessage = $_.Exception.Message
                $ErrorItem = $_.Exception.ItemName
                Write-Error "Error: Item = $ErrorItem -> Message = $ErrorMessage"
            }
        }
    } until ($response.count -lt $limit)
    
    Write-Progress -Activity "Getting Accounts Offset:$offset" -Completed

    $date = Get-Date -Format "yyyy-MM-dd HH_mm_ss"
    $rootDir = "$outputDir/$tenant/$sourceName"
    if (!(Test-Path $rootDir)) {
        New-Item -ItemType Directory $rootDir
    }
    $path = "$outputDir/$tenant/$sourceName/AttributeSyncReport $date.csv"
    $output | Export-Csv $path -NoTypeInformation
    Write-Host "Success! Look for files here:`n$path"
    return $path
}

# Enter all parameters here
$tenant = 'devrel-ga-5699'
$domain = 'identitynow-demo'
$token = ''
$clientID = (op read op://Personal/IDN-$tenant/username)
$clientSecret = (op read op://Personal/IDN-$tenant/password)
$sourceName = "Network"

# Destination for CSV files
$outputDirectory = '/Users/edwatho/Dev Days'

# [Optional] Use this list to provide context for each user. This will just be the direct Identity Attribute value
$identityAttributes = @(
    "uid"
    "cloudLifecycleState"
    "displayName"
)

if (!($token -or ($clientID -and $clientSecret))) {
    Write-Host "Please provide either a token or PAT details in the script"
}
    
if (!$token) {
    $token = Get-AccessToken -tenant $tenant -clientID $clientID -clientSecret $clientSecret -domain $domain
}

$path = Get-AttributeSyncReport -tenant $tenant -token $token -sourceName $sourceName -identityAttributes $identityAttributes -domain $domain -outputDir $outputDirectory