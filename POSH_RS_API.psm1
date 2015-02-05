Function Get-RSServiceCatalog {
    param(
        [Parameter()][string]$Username,
        [Parameter()][string]$APIKey,
        [Parameter()][string]$region        
    )

    if ($username -ne "") { 
        write-verbose "Username $username passed."
        $script:RS_Username = $username
    }

    if ($APIKey -ne "") { 
        write-verbose "API Key $apikey passed."
        $script:RS_apikey = $APIKey
    }

    if ($region -ne "") { 
        write-verbose "Region $region passed."
        $script:RS_region = $region
    }

    if ($script:RS_username -eq $null) { 
        write-verbose "Rackspace Username not set.  Prompting"
        $script:RS_Username = read-host "Enter Racksace username" 
    } 
    write-Debug "Using Rackspace Username: $RS_Username"
    
    if ($script:RS_apikey -eq $null) { 
        write-verbose "Rackspace API Key not set.  Prompting"
        $script:RS_apikey = read-host "Enter Racksace API key" 
    }
    write-Debug "Using Rackspace APIKey: $rs_apikey"

    if ($script:RS_catalog -ne $null) {
       write-verbose "Existing catalog found"
       if ([datetime]$RS_catalog.access.token.expires -lt (get-date)){
            write-verbose "Existing Catalog has expired and needs to be refreshed."
            $script:RS_catalog = $null
        } elseif($RS_catalog.access.user.name -ne $RS_Username){
            write-verbose "Existing Catalog does not match username.  Purging."
            $script:RS_catalog = $null
        }
    }

    if ($script:RS_catalog -eq $null){
        write-verbose "Requesting new catalog."
        $script:RS_Catalog = (Invoke-RestMethod -Uri $("https://identity.api.rackspacecloud.com/v2.0/tokens") -Method POST -Body $(@{"auth" = @{"RAX-KSKEY:apiKeyCredentials" = @{"username" = $RS_Username; "apiKey" = $RS_APIKey}}} | convertTo-Json) -ContentType application/json)
    } 

    if ($script:RS_region -eq $null) { 
        write-verbose "Rackspace DC not set.  Setting to account default"
        Set-RSRegion -region $rs_catalog.access.user.'RAX-AUTH:defaultRegion' 
    } 
    return $script:RS_catalog
}

Function Get-RSRegion { return $script:RS_region }
Function Get-RSRegions { return $script:RS_catalog.access.serviceCatalog.endpoints.region | Sort-Object |  Get-Unique }
Function Get-RSProducts { return $script:RS_catalog.access.serviceCatalog.name }

Function Set-RSRegion { 
Param (
    [Parameter(Mandatory=$True)]
    [string]$region

)

    $script:RS_region = $region
}

Function GetAuthToken {
   return @{"X-Auth-Token"=($RS_catalog.access.token.id)}
}

Function GetEndpoint {
Param (
    [Parameter(Mandatory=$True)]
    [string]$product

)
    write-verbose "Getting Endpoint"
    $endpoints = ((Get-RSServiceCatalog).access.serviceCatalog | where {$_.name -eq "$product"}).endpoints 
    if ($endpoints.count -eq 1 ){
        write-verbose "$product only has a single endpoint: $($endpoints.publicURL)"
        $endpoints.publicURL
    } else {
        write-verbose "$product endpoint in ${RS_region}: $(($endpoints | where {$_.region -eq $RS_region}).publicURL)"
        ($endpoints | where {$_.region -eq $RS_region}).publicURL
    }
}

function Invoke-RSAPIGET(){
    param( 
        [Parameter()][string]$uri
    ) 
    PROCESS {
        write-verbose "Invoke-RestMethod -Uri $uri -Method GET -Headers $(GetAuthToken) -ContentType application/json)"
        Invoke-RestMethod -Uri $uri -Method GET -Headers (GetAuthToken) -ContentType application/json
    } 
    END {

    }   
}

function Invoke-RSAPIPOST(){
    param( 
        [Parameter()][string]$uri,
        [Parameter()][string]$body
    ) 
    PROCESS {
        write-verbose "Invoke-RestMethod -Uri $uri -Method GET -Headers $(GetAuthToken) -ContentType application/json)"
        Invoke-RestMethod -Uri $uri -Method POST -Headers (GetAuthToken) -body $body   -ContentType application/json
    } 
    END {

    }   
}

function Invoke-RSAPIPUT(){
    param( 
        [Parameter()][string]$uri,
        [Parameter()][string]$body
    ) 
    PROCESS {
        write-verbose "Invoke-RestMethod -Uri $uri -Method PUT -Headers (GetAuthToken) -body $body   -ContentType application/json"
        Invoke-RestMethod -Uri $uri -Method PUT -Headers (GetAuthToken) -body $body   -ContentType application/json
    } 
    END {

    }   
}