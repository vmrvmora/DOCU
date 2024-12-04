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
        [boolean]$countOnly = $false,
        [boolean]$firstSet = $false,
        [String]$domain = "identitynow",
        $token = $null
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
    if ($countOnly) {
        return [int]($responseHeader."X-Total-Count")[0]
    }
    if ($progress) {
        $total = [int]($responseHeader."X-Total-Count")[0]
        if ($total -eq 0) {
            return $results
        }
    }
    $response = $null

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
            uri                     = "https://$($tenant).api.$domain.com/v3/search?limit=$limit&count=true"
            body                    = (ConvertTo-Json $body)
            headers                 = @{Authorization = "Bearer $token" }
            ContentType             = "application/json"
            ResponseHeadersVariable = "responseHeader"
        }

        $offset += $limit
        $response = Invoke-RestMethod @params
        if ($firstSet) {
            return $response
        }
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

function Get-Roles {
    param (
        [String]$tenant,
        [Int]$limit = 50,
        [Int]$offset = 0,
        [String]$filters = "",
        [bool]$list = $false,
        [String]$domain = "identitynow",
        [String]$token
    )

    # Get Total Roles
    $uri = "https://$($tenant).api.$domain.com/beta/roles?limit=1&count=true&filters=$filters"
    $result = Invoke-WebRequest -Method GET -Uri $uri -Headers @{Authorization = "Bearer $token" }
    $totalRoles = [int]($result.headers."X-Total-Count")[0]

    $rolesMapping = [ordered]@{}
    $rolesList = @()
    # Get All Roles
    if ($totalRoles -gt 0) {
        do {
            Write-Progress -Activity "Getting Roles" -PercentComplete ($rolesMapping.count / $totalRoles * 100) -Status "$($rolesMapping.count) / $totalRoles"
            $uri = "https://$($tenant).api.$domain.com/beta/roles?offset=$offset&filters=$filters"
            $roles = Invoke-RestMethod -Method GET -Uri $uri -Headers @{Authorization = "Bearer $($token)" }
            foreach ($role in $roles) {
                $rolesMapping[$role.name] = $role
            }
            $rolesList += $roles

            $offset += $limit
        } until ($roles.count -lt $limit)
    }

    Write-Progress -Activity "Getting Roles" -Completed
    if ($list) {
        return $rolesList
    }
    return $rolesMapping
}

function Get-AccessProfiles {
    param (
        [String]$tenant,
        [Int]$limit = 50,
        [Int]$offset = 0,
        [String]$filters = "",
        [bool]$list = $false,
        [String]$domain = "identitynow",
        [String]$token
    )

    # Get Total
    $uri = "https://$($tenant).api.$domain.com/beta/access-profiles?limit=1&count=true&filters=$filters"
    $result = Invoke-WebRequest -Method GET -Uri $uri -Headers @{Authorization = "Bearer $token" }
    $total = [int]($result.headers."X-Total-Count")[0]
    if ($total -eq 0) {
        return $null
    }

    $mapping = [ordered]@{}
    $array = @()
    # Get All
    do {
        Write-Progress -Activity "Getting Access Profiles" -PercentComplete ($mapping.count / $total * 100) -Status "$($mapping.count) / $total"
        $uri = "https://$($tenant).api.$domain.com/beta/access-profiles?offset=$offset&filters=$filters"
        $response = Invoke-RestMethod -Method GET -Uri $uri -Headers @{Authorization = "Bearer $($token)" }
        foreach ($item in $response) {
            $mapping[$item.name] = $item
        }
        $array += $response
        $offset += $limit
    } until ($response.count -lt $limit)

    Write-Progress -Activity "Getting Access Profiles" -Completed
    if ($list) {
        return $array
    }
    return $mapping
}

function Get-RoleMembershipPreview {
    param (
        $tenant,
        $filter,
        $apFilter,
        $skipEnabled = $false,
        $countOnly = $false,
        $outputDir = (Get-Location).path,
        $token = '',
        [String]$domain = "identitynow"
    )
    $roles = Get-Roles -tenant $tenant -domain $domain -list $true -filters $filter -token $token
    Write-Host "Role count: $($roles.count)" -ForegroundColor Yellow
    $apMapping = Get-AccessProfiles -tenant $tenant -domain $domain -filters $apFilter -token $token
    Write-Host "Access Profile count: $($apMapping.count)" -ForegroundColor Yellow
    
    $missingAccess = @()
    $missingTotals = @()
    foreach ($role in $roles) {
        $roleName = $role.name
        $roleId = $role.id
        Write-Host "Processing $roleName" -ForegroundColor Green
        $accessProfiles = $role.accessProfiles

        $entitlements = @()
        foreach ($ap in $accessProfiles) {
            $entitlements = @()
            if ($skipEnabled -and $apMapping[$ap.name].enabled -eq "false") {
                Continue
            }
            foreach ($entitlement in $apMapping[$ap.name].entitlements) {
                $entitlements += $entitlement.name
            }
            foreach ($entitlement in $apMapping[$ap.name].entitlements) {
                Write-Host $entitlement.name -ForegroundColor Blue
                $query = "@access(id:$roleId) AND NOT @access(id:$($entitlement.id))"
                $results = Search-IDN -tenant $tenant -query $query -countOnly $countOnly -domain $domain -token $token
                if ($countOnly) {
                    Write-Host "$results users have the $roleName Role, but are missing $($entitlement.name)"
                }

                $totalQuery = "@access(id:$($entitlement.id))"
                $total = Search-IDN -tenant $tenant -query $totalQuery -countOnly $countOnly -domain $domain -token $token
                if ($countOnly) {
                    $missingTotals += [PSCustomObject]@{
                        'Missing Entitlement'                   = $entitlement.name
                        Count                                   = $results
                        'Number of users with this Entitlement' = $total
                        'Role Name'                             = $roleName
                        'AP Name'                               = $ap.name
                        Query                                   = $query
                        'Total Query'                           = $totalQuery
                    }
                }
                else {
                    foreach ($result in $results) {
                        $missingAccess += [PSCustomObject]@{
                            uid                   = $result.attributes.uid
                            RoleName              = $roleName
                            APName                = $ap.name
                            'Missing Entitlement' = $entitlement
                            'AP Entitlements'     = ($entitlements -join ";")
                            cloudLifecycleState   = $result.attributes.cloudLifecycleState
                        }
                    }
                }
            }
        }
    }
    $date = Get-Date -Format "yyyy-MM-dd HHmmss"
    $rootDir = "$outputDir/$tenant/Missing Access/"
    if (!(Test-Path $rootDir)) {
        New-Item -ItemType Directory $rootDir
    }
    $path = ''
    if ($countOnly) {
        $path = "$rootDir/Missing Access Totals_$date.csv"
        $missingTotals | Export-Csv $path
    }
    else {
        $path = "$rootDir/Missing Access_$date.csv"
        $missingAccess | Export-Csv $path
    }
    Write-Host "Success! Look for files here:`n$path" -ForegroundColor Magenta
    return $path
}

# Enter all parameters here
$tenant = 'devrel-ga-5699'
$domain = 'identitynow-demo'
$token = ''
$clientID = (op read op://Personal/IDN-$tenant/username)
$clientSecret = (op read op://Personal/IDN-$tenant/password)

# Destination for CSV files
$outputDirectory = '/Users/edwatho/Dev Days'

# Add this filter to limit which roles are previewed
# Default will return all roles
# Ex. 'name sw "AD"'
$roleFilter = ''

# Warning! All Access Profiles need to be included that are on the roles
# Add this filter to limit which access profiles are previewed
$apFilter = ''

if (!($token -or ($clientID -and $clientSecret))) {
    Write-Host "Please provide either a token or PAT details in the script"
}

if (!$token) {
    $token = Get-AccessToken -tenant $tenant -clientID $clientID -clientSecret $clientSecret -domain $domain
}

$path = Get-RoleMembershipPreview -tenant $tenant -domain $domain -token $token -outputDir $outputDirectory -countOnly $true -filter $roleFilter -apFilter $apFilter