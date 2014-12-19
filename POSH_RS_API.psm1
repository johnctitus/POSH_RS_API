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

#list Server(s)
function Get-RSNextGenServer(){
   #[CmdletBinding(DefaultParametersetName="RSServerSearch")] 
    param( 
        [Parameter()][string[]]$ServerID,
        [Parameter()][string[]]$Image,
        [Parameter()][string[]]$Flavor,
        [Parameter()][string[]]$Name,
        [Parameter()][string[]]$Status
    ) 
    BEGIN {
        $product = "cloudServersOpenStack"        
    }
    PROCESS {
        write-verbose "Getting Next Gen Server List"
        write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

        $uri = GetEndpoint -product $product
        if ($serverID.count -eq 1) {
            $uri += "/servers/$($serverID[0])"
            $apiResult = "server" 
        } else {
            $uri = $uri + "/servers/detail" 
            $apiResult="servers"
        }

        $continue = $true
        write-verbose $uri
        write-verbose "Invoke-RestMethod -Uri $uri -Method GET -Headers $(GetAuthToken) -ContentType application/json).($apiResult))"
        $result = (Invoke-RestMethod -Uri $uri -Method GET -Headers (GetAuthToken) -ContentType application/json).($apiResult)

        if ($continue) {
            if ($name.count -gt 1) {
                Write-verbose "Filtering list by name"
                $result = $result | where-object {$name -contains $_.name }
            }
            if ($name.count -eq 1) {
                Write-verbose "Filtering list by name"
                $result = $result | where-object {$_.name -like $name}
            }
            if ($serverID.count -ne 0) {
                Write-verbose "Filtering list by ServerID"
                $result = $result | where-object {$serverID -contains $_.id }
            }
            if ($image.count -ne 0) {
                Write-verbose "Filtering list by image"
                Write-Debug "$image"
                $result = $result | where-object { $image -contains $_.image.id }
            }
            if ($flavor.count -ne 0) {
                Write-verbose "Filtering list by flavor"
                $result = $result | where-object {$flavor -contains $_.flavor.id }
            }
            if ($status.count -ne 0) {
                Write-verbose "Filtering list by status"
                $result = $result | where-object { $status -contains $_."OS-EXT-STS:vm_state" }
            }
            $result
        }          
    } 
    END {

    }   
}

#create Server
function New-RSNextGenServer(){
[CmdletBinding(DefaultParametersetName="AutoDisk")] 
param( 
        [Parameter(Mandatory=$True)][string]$Flavor,
        [Parameter(Mandatory=$True)][string]$Name,
        [Parameter(Mandatory=$True)][string]$Image,
        [Parameter()][ValidateSet("AUTO","MANUAL")][string]$diskConfig,
        [Parameter()][hashtable]$Metadata, 
        [Parameter()][hashtable]$Personality,
        [Parameter()][string[]]$Networks, 
        [Parameter()][string]$KeyPair,
        [Parameter()][string]$AutoNATIP 
    )
    BEGIN {
        $product = "cloudServersOpenStack"
        $apiResult="server"
    }
    PROCESS {
        write-verbose "Creating new Next Gen Server"
        write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

        $uri = (GetEndpoint -product $product) + "/servers"
        $body = @{"server" =  @{"name" = "$Name";"imageRef" = "$image";"flavorRef" = "$Flavor"}}

        if ($diskConfig -ne "") { 
            $body.server.add("config_drive", $true) 
            $body.server.add("OS-DCF:diskConfig", "$diskConfig")
        }
        if ($Metadata.count -gt 0) { 
            $body.server.add("metadata", $metaData) 
        }
        if ($personality.count -gt 0) { 
            $body.server.add("personality", $personality) 
            foreach ($key in $Personality.keys){
                        
                $body.server.personality += @(@{"path"="$key";"contents"="$([System.Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($personality[$key])))"})
            }
        }
        if ($networks.count -gt 0) { 
            $body.server.add("networks", @()) 
            foreach ($network in $networks){
                        
                $body.server.networks += @{"uuid"="$network"}
            }
        }
        if ($KeyPair -ne "") { 
            $body.server.add("key_name", "$keyPair")  
        }
        if ($AutoNATIP -ne "") { 
            if ($body.server.metadata -eq $null){
                $body.server.add("metadata", @{"RackConnectPublicIP"="$AutoNATIP"}) 
            } else {
                $body.server.metadata.add("RackConnectPublicIP", "$AutoNATIP")
            }
        }

        $body = $body | ConvertTo-Json -Compress -depth 10
        write-debug $body

        $continue = $true
                
        (Invoke-RestMethod -Uri $uri -Method POST -body $body -Headers (GetAuthToken) -ContentType application/json).($apiResult)
    }
                
        
}
#Update Server
function Update-RSNextGenServer(){
param( 
        [Parameter(Mandatory=$True)]$ServerID,
        [Parameter()][string]$Name,
        [Parameter()][string]$AccessIPv4,
        [Parameter()][string]$AccessIPv6
    )
    $product = "cloudServersOpenStack"
    $apiResult="server"

    write-verbose "Updating Next Gen Server $serverID"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"
    $body = @{"server" =  @{}} 
    
    if ($name -ne "") { $body.server.add("name", $name) }
    if ($AccessIPv4 -ne "") { $body.server.add("AccessIPv4", $AccessIPv4) }
    if ($AccessIPv6 -ne "") { $body.server.add("AccessIPv6", $AccessIPv6) }
    
    $body = $body | ConvertTo-Json -Compress -depth 10
    write-debug $body

    $uri = (GetEndpoint -product $product ) + "/servers/$serverID"
    $continue = $true

    (Invoke-RestMethod -Uri $uri -Method PUT -body $body  -Headers (GetAuthToken) -ContentType application/json).($apiResult)
}
#Delete Server
function Delete-RSNextGenServer(){
param( 
        [Parameter(Mandatory=$True)][string]$ServerID
    )

    $product = "cloudServersOpenStack"
    $apiResult="server"

    write-verbose "Deleting Next Gen Server $serverID"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

    $uri = (GetEndpoint -product $product ) + "/servers/$s"

    (Invoke-RestMethod -Uri $uri -Method DELETE -Headers (GetAuthToken) -ContentType application/json).($apiResult) 
}

#Create\Update Keypair

#List Key Pairs

#Delete Key Pairs

#Change Password
function Set-RSNextGenServerPassword(){
Param (
    [Parameter(Mandatory=$True)][string[]]$serverID,
    [Parameter(Mandatory=$True)][string]$password
)

    $product = "cloudServersOpenStack"

    write-verbose "Set Password for Next Gen Server $serverID"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"
    
    $uri = (Get-endpoint -product $product) + "/servers"
    $body = @{"changePassword" = @{"adminPass" = "$password"}} | convertTo-json -depth 10
    foreach ($s in $serverID) {
        write-verbose "Setting Password for Next Gen Server $serverID"
        Invoke-RestMethod -Uri "$uri/$s/action" -Method POST -Body $body -Headers (Get-AuthToken) -ContentType application/json
    }
} 
 
#Reboot Server
function Reboot-RSNextGenServer(){
param( 
        [Parameter(Mandatory=$True)][string]$serverID,
        [Parameter()][switch]$HardReboot
    )

    $product = "cloudServersOpenStack"

    write-verbose "Reboot Next Gen Server $serverID"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"
    
    $uri = (Get-endpoint -product $product) + "/servers/$serverID/action"
    
    if ($HardReboot.IsPresent) { 
        $body = @{"reboot" =  @{"type" = "HARD"}} | convertTo-Json  -Compress
    } else {
        $body = @{"reboot" =  @{"type" = "SOFT"}} | convertTo-Json  -Compress
    }

    Invoke-RestMethod -Uri "$uri" -Method POST -Body $body -Headers (Get-AuthToken) -ContentType application/json
}
#Rebuild Server

#Resize Server

#Confirm Resize

#Revert Resize

#Rescue Server

#Unrescue server

#Create Image

#Attach Volume

#List Volume Attachment(s)

#Detach Volume

#set Metadata

#Update Metadata

#Set Metadata Item

#Delete Metadata Item

#list Flavors
#Get Flavor Details
function Get-RSFlavor(){
    param( 
        [Parameter()][string[]]$FlavorID,
        [Parameter()][string[]]$Name,
        [Parameter()][int]$MinDisk=0,
        [Parameter()][int]$MinDataDisk=0,
        [Parameter()][int]$MinRam=0,
        [Parameter()][int]$MinSwap=0,
        [Parameter()][int]$MinCPU=0
    ) 
    BEGIN {
        $product = "cloudServersOpenStack" 
        
    }
    PROCESS {
        write-verbose "Getting Next Gen Server List"
        write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

        $uri = GetEndpoint -product $product
        if ($serverID.count -eq 1) {
            $uri += "/flavors/$($flavorID[0])"
            $apiResult = "flavor" 
        } else {
            $uri = $uri + "/flavors/detail" 
            $apiResult="flavors"
        }


        $continue = $true
        write-verbose $uri
        $result = (Invoke-RestMethod -Uri $uri -Method GET  -Headers (GetAuthToken) -ContentType application/json).($apiResult)

        if ($continue) {
        if ($MinDisk -gt 0) {$result = $result | where-object -property disk -ge "$MinDisk"}
                        if ($MinDataDisk -gt 0) {$result = $result | where-object -property "OS-FLV-EXT-DATA:ephemeral" -ge "$MinDataDisk"}
                        if ($MinSwap -gt 0) {$result = $result | where-object -property swap -ge "$MinSwap"}
                        if ($MinRam -gt 0) {$result = $result | where-object -property ram -ge "$MinRam"}
                        if ($MinRam -gt 0) {$result = $result | where-object -property vcpus -ge "$MinCPU"}
                        if ($FlavorID.count -gt 1) {$result = $result | where-object -property id -in $FlavorID}
            if ($name.count -gt 1) {
                Write-verbose "Filtering list by name"
                $result = $result | where-object {$name -contains $_.name }
            }
            if ($name.count -eq 1) {
                Write-verbose "Filtering list by name"
                $result = $result | where-object {$_.name -like $name}
            }
            if ($flavorID.count -ne 0) {
                Write-verbose "Filtering list by FlavorID"
                $result = $result | where-object {$flavorID -contains $_.id }
            }
            if ($MinDisk -gt 0) {
                Write-verbose "Filtering list by MinDisk"
                where-object -property disk -ge "$MinDisk"
            }
            if ($MinDataDisk -gt 0) {
                Write-verbose "Filtering list by MinDataDisk"
                $result = $result | where-object -property "OS-FLV-EXT-DATA:ephemeral" -ge "$MinDataDisk"
            }
            if ($MinSwap -gt 0) {
                Write-verbose "Filtering list by MinSwap"
                $result = $result | where-object -property swap -ge "$MinSwap"
            }
            if ($MinRam -gt 0) {
                Write-verbose "Filtering list by MinRam"
                $result = $result | where-object -property ram -ge "$MinRam"
            }
            if ($MinCPU -gt 0) {
                Write-verbose "Filtering list by MinCPU"
                $result = $result | where-object -property vcpus -ge "$MinCPU"
            }

            $result
        }          

    } 
    END {

    }   
}


#List Images
#Get Image Details
function Get-RSImage(){
param( 
        [Parameter()][string[]]$ImageID,
        [Parameter()][string[]]$Name,
        [Parameter()][string[]]$ServerID,
        [Parameter()][string[]]$Status,
        [Parameter()][DateTime]$ChangeDate
    )
    BEGIN {
        $product = "cloudImages" 
        
    }
    PROCESS {
        write-verbose "Getting Next Gen Server List"
        write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

        $baseuri = GetEndpoint -product $product
        if ($serverID.count -eq 1) {
            $uri = $baseuri + "/images/$($imageID[0])"
            $apiResult = "image" 
        } else {
            $uri = $baseuri + "/images" 
            $apiResult="images"
        }


        $continue = $true
        do {
            write-verbose $uri
        
            $result_json = (Invoke-RestMethod -Uri $uri -Method GET  -Headers (GetAuthToken) -ContentType application/json)

            if ($continue) {
             
            
                $result = $result_json.($apiResult)
                if ($ImageID.count -gt 1) {
                    Write-verbose "Filtering list by ImageID"
                    $result = $result | where-object {$ImageID -contains $_.id }
                }
                if ($name.count -gt 1) {
                    Write-verbose "Filtering list by exact name"
                    $result = $result | where-object {$name -contains $_.name }
                }
                if ($name.count -eq 1) {
                    Write-verbose "Filtering list by name"
                    $result = $result | where-object {$_.name -like $name}
                }
                if ($status.count -ne 0) {
                    Write-verbose "Filtering list by status"
                    $result = $result | where-object -property status -in $status
                }
                if ($changeDate -gt 0) {
                    Write-verbose "Filtering list by Change Date"
                    $result = $result | where-object { [dateTime]$_.updated_at -ge $changeDate} 
                }
                                                                                                                                                        <#
        if ($continue) {
        
            if ($name.count -gt 1) {
                Write-verbose "Filtering list by name"
                $result = $result | where-object {$name -contains $_.name }
            }
            if ($name.count -eq 1) {
                Write-verbose "Filtering list by name"
                $result = $result | where-object {$_.name -like $name}
            }
            if ($flavorID.count -ne 0) {
                Write-verbose "Filtering list by FlavorID"
                $result = $result | where-object {$flavorID -contains $_.id }
            }
            if ($MinDisk -gt 0) {
                Write-verbose "Filtering list by MinDisk"
                where-object -property disk -ge "$MinDisk"
            }
            if ($MinDataDisk -gt 0) {
                Write-verbose "Filtering list by MinDataDisk"
                $result = $result | where-object -property "OS-FLV-EXT-DATA:ephemeral" -ge "$MinDataDisk"
            }
            if ($MinSwap -gt 0) {
                Write-verbose "Filtering list by MinSwap"
                $result = $result | where-object -property swap -ge "$MinSwap"
            }
            if ($MinRam -gt 0) {
                Write-verbose "Filtering list by MinRam"
                $result = $result | where-object -property ram -ge "$MinRam"
            }
            if ($MinCPU -gt 0) {
                Write-verbose "Filtering list by MinCPU"
                $result = $result | where-object -property vcpus -ge "$MinCPU"
            }
            #>
                $result
                if ($result_json.next -ne $null) { $uri = $baseURI + $result_json.next.subString(3)}
            }          
        } while ($result_json.next -ne $null)
    } 
    END {

    }   
}

#Delete Image

