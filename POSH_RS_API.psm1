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
            $body.server.add("personality", @()) 
            foreach ($key in $Personality.keys){
                        
                $body.server.personality += @{"path"="$key";"contents"="$([System.Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($personality[$key])))"}
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

    $uri = (GetEndpoint -product $product ) + "/servers/$serverID"

    (Invoke-RestMethod -Uri $uri -Method DELETE -Headers (GetAuthToken) -ContentType application/json)
}

#Change Password
function Set-RSNextGenServerPassword(){
Param (
    [Parameter(Mandatory=$True)][string[]]$serverID,
    [Parameter(Mandatory=$True)][string]$password
)

    $product = "cloudServersOpenStack"

    write-verbose "Set Password for Next Gen Server $serverID"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"
    
    $uri = (GetEndpoint -product $product) + "/servers"
    $body = @{"changePassword" = @{"adminPass" = "$password"}} | convertTo-json -depth 10
    foreach ($s in $serverID) {
        write-verbose "Setting Password for Next Gen Server $serverID"
        Invoke-RestMethod -Uri "$uri/$s/action" -Method POST -Body $body -Headers (GetAuthToken) -ContentType application/json
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
    
    $uri = (GetEndpoint -product $product) + "/servers/$serverID/action"
    
    if ($HardReboot.IsPresent) { 
        $body = @{"reboot" =  @{"type" = "HARD"}} | convertTo-Json  -Compress
    } else {
        $body = @{"reboot" =  @{"type" = "SOFT"}} | convertTo-Json  -Compress
    }

    Invoke-RestMethod -Uri "$uri" -Method POST -Body $body -Headers (GetAuthToken) -ContentType application/json
}

#Rebuild Server
function Rebuild-RSNextGenServer(){
param( 
        [Parameter(Mandatory=$True)][string]$serverID,
        [Parameter(Mandatory=$True)][string]$Image,
        [Parameter()][string]$Name,
        [Parameter()][string]$password,
        [Parameter()][hashtable]$Metadata, 
        [Parameter()][hashtable]$Personality,
        [Parameter()][ValidateSet("AUTO","MANUAL")][string]$diskConfig
    )
    BEGIN {
        $product = "cloudServersOpenStack"
        $apiResult="server"
    }
    PROCESS {
        write-verbose "Rebuilding Next Gen Server"
        write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

        $uri = (GetEndpoint -product $product) + "/servers/$serverID/action"
        #$body = @{"rebuild" =  @{"imageRef" = "$image";"flavorRef" = "$Flavor"}}
        $body = @{"rebuild" =  @{"imageRef" = "$image"}}
        
        if ($name -ne "") { 
            $body.rebuild.add("name", $name)
        }
        if ($password -ne "") { 
            $body.rebuild.add("adminPass", $password)
        }
        if ($diskConfig -ne "") { 
            $body.rebuild.add("config_drive", $true) 
            $body.rebuild.add("OS-DCF:diskConfig", "$diskConfig")
        }
        if ($Metadata.count -gt 0) { 
            $body.rebuild.add("metadata", $metaData) 
        }
        if ($personality.count -gt 0) { 
            $body.rebuild.add("personality", @()) 
            foreach ($key in $Personality.keys){
                $body.rebuild.personality += @{"path"="$key";"contents"="$([System.Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($personality[$key])))"}
            }
        }

        $body = $body | ConvertTo-Json -Compress -depth 10
        write-debug $body

        $continue = $true
                
        (Invoke-RestMethod -Uri $uri -Method POST -body $body -Headers (GetAuthToken) -ContentType application/json).($apiResult)
    }
                
        
}
#Resize Server
function Resize-RSNextGenServer(){
Param (
    [Parameter(Mandatory=$True)][string]$serverID,
    [Parameter(Mandatory=$True)][string]$Flavor
)

    $product = "cloudServersOpenStack"

    write-verbose "Resize Next Gen Server $serverID"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"
    
    $uri = (GetEndpoint -product $product) + "/servers/$serverID/action"
    $body = @{"resize" = @{"flavorRef" = "$Flavor"}} | convertTo-json -depth 10

    Invoke-RestMethod -Uri $uri -Method POST -Body $body -Headers (GetAuthToken) -ContentType application/json
} 

#Confirm Resize
function Confirm-RSNextGenServerResize(){
Param (
    [Parameter(Mandatory=$True)][string]$serverID
)

    $product = "cloudServersOpenStack"

    write-verbose "Confirm Resize Next Gen Server $serverID"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"
    
    $uri = (GetEndpoint -product $product) + "/servers/$serverID/action"
    $body = @{"confirmResize" = $null} | convertTo-json -depth 10

    Invoke-RestMethod -Uri $uri -Method POST -Body $body -Headers (GetAuthToken) -ContentType application/json
} 
#Revert Resize
function Revert-RSNextGenServerResize(){
Param (
    [Parameter(Mandatory=$True)][string]$serverID
)

    $product = "cloudServersOpenStack"

    write-verbose "Confirm Resize Next Gen Server $serverID"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"
    
    $uri = (GetEndpoint -product $product) + "/servers/$serverID/action"
    $body = @{"revertResize" = $null} | convertTo-json -depth 10

    Invoke-RestMethod -Uri $uri -Method POST -Body $body -Headers (GetAuthToken) -ContentType application/json
} 

#Create Image
function Create-RSNextGenServerImage {
Param (
    [Parameter(Mandatory=$True)][string]$serverID,
    [Parameter(Mandatory=$True)][string]$name
)

    $product = "cloudServersOpenStack"

    write-verbose "Create Image from Next Gen Server $serverID"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

    $uri = (GetEndpoint -product $product) + "/servers/$serverID/action"
    $body = @{"createImage" = @{"name" = "$name"}} | convertTo-json -depth 10

    Invoke-RestMethod -Uri $uri -Method POST -Body $body -Headers (GetAuthToken) -ContentType application/json
}

#set Metadata
#Update Metadata
function Set-RSNextGenServerMetadata(){
param( 
        [Parameter(Mandatory=$True)][string]$serverID,
        [Parameter()][hashtable]$Metadata,
        [Parameter()][switch]$Reset
    )

    $product = "cloudServersOpenStack"
    $apiResult="metadata"

    write-verbose "Setting Metadata for Next Gen Server $serverID"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"
    
    $uri = (GetEndpoint -product $product) + "/servers/$serverID/metadata"
    
    if ($Reset.IsPresent) { 
        $Action = "PUT"
    } else {
        $Action = "POST"
    }
    
    $body = @{"metadata" =  $metadata} | convertTo-Json  -Compress
    
    (Invoke-RestMethod -Uri "$uri" -Method $Action -Body $body -Headers (GetAuthToken) -ContentType application/json).($apiResult)
}
#Delete Metadata Item
function Delete-RSNextGenServerMetadata(){
param( 
        [Parameter(Mandatory=$True)][string]$serverID,
        [Parameter()][string[]]$MetadataKey
    )
    $product = "cloudServersOpenStack"

    
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"
    
    foreach ($m in $metadataKey) {
        write-verbose "Deleting Metadata Key $m for Next Gen Server $serverID"
        $uri = (GetEndpoint -product $product) + "/servers/$serverID/metadata/$m"
        Invoke-RestMethod -Uri "$uri" -Method DELETE -Headers (GetAuthToken) -ContentType application/json
    }
}


#Create\Update Keypair

#List Key Pairs

#Delete Key Pairs

#Rescue Server

#Unrescue server

#Attach Volume

#List Volume Attachment(s)

#Detach Volume

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
                $result = $result | where-object -property disk -ge "$MinDisk"
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
        if ($ImageID.count -eq 1) {
            $uri = $baseuri + "/images/$($imageID[0])"

            (Invoke-RestMethod -Uri $uri -Method GET  -Headers (GetAuthToken) -ContentType application/json)

        } else {
            $uri = $baseuri + "/images" 
            $apiResult="images"

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
                    $result
                    if ($result_json.next -ne $null) { $uri = $baseURI + $result_json.next.subString(3)}
                }          
            } while ($result_json.next -ne $null)
        }


        
    } 
    END {

    }   
}

#Delete Image
function Delete-RSImage(){
param( 
        [Parameter(Mandatory=$True)][string]$imageID
    )

    $product = "cloudImages"

    write-verbose "Deleting Image $imageID"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

    $uri = (GetEndpoint -product $product ) + "/images/$image_id"

    (Invoke-RestMethod -Uri $uri -Method DELETE -Headers (GetAuthToken) -ContentType application/json)
}

#Update Image

#List Image Members
function Get-RSImageMembers(){
param( 
        [Parameter()][string[]]$ImageID,
        [Parameter()][string[]]$Member,
       # [Parameter()][ValidateSet("shared","private","public")][string]$visibility,
        [Parameter()][ValidateSet("pending","accepted","rejected")][string]$Status
    )
    BEGIN {
        $product = "cloudImages" 
        $apiResult = "members"
    }
    PROCESS {
        write-verbose "Getting Next Gen Server List"
        write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

        $baseuri = GetEndpoint -product $product
        $result = @()
        foreach ($image in $imageID) {
            $uri =$baseuri + "/images/$image/members"
            $result+=(Invoke-RestMethod -Uri ($uri) -Method GET  -Headers (GetAuthToken) -ContentType application/json).($apiResult)
        }

        if ($status -ne "" ) {
            Write-verbose "Filtering list by status $status"
            $result = $result | where-object -property status -eq $status
        }
        if ($Member.count -ne 0) {
            Write-verbose "Filtering list by member $member"
            $result = $result | where-object -property member_id -in $Member
        }                                                                                                                                                        
        $result
    } 
    END {

    }   
}
#Add Image Member
function Add-RSImageMembers(){
param( 
        [Parameter()][string[]]$ImageID,
        [Parameter()][string[]]$Member
    )
    BEGIN {
        $product = "cloudImages" 
        $apiResult = "members"
    }
    PROCESS {
        write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

        $baseuri = GetEndpoint -product $product

        foreach ($image in $imageID) {
            $uri =$baseuri + "/images/$image/members"

            foreach ($M in $Member) {
                $body = @{"member" = $m} | convertTo-Json  -Compress 
                write-verbose "Adding $m to image member list for image $image"
                Invoke-RestMethod -Uri $uri -Method POST -Body $body -Headers (GetAuthToken) -ContentType application/json
            }
        }
    } 
    END {

    }   
}

#Remove Image Member
function Remove-RSImageMembers(){
param( 
        [Parameter()][string[]]$ImageID,
        [Parameter()][string[]]$Member
    )
    BEGIN {
        $product = "cloudImages" 
        $apiResult = "members"
    }
    PROCESS {
        write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

        $baseuri = GetEndpoint -product $product

        foreach ($image in $imageID) {
            foreach ($M in $Member) {
                $uri =$baseuri + "/images/$image/members/$m"
                write-verbose "Removing $m to image member list for image $image"
                (Invoke-RestMethod -Uri ($uri) -Method DELETE -Headers (GetAuthToken) -ContentType application/json)
            }
        }
    } 
    END {

    }   
}

#Update Image Member
function Update-RSImageMembers(){
param( 
        [Parameter()][string[]]$ImageID,
        [Parameter()][ValidateSet("pending","accepted","rejected")][string]$Status
    )
    BEGIN {
        $product = "cloudImages" 
        $apiResult = "members"
    }
    PROCESS {
        write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

        $baseuri = GetEndpoint -product $product
        $member = $RS_catalog.access.token.tenant.id
        foreach ($image in $imageID) {
            $uri = $baseuri + "/images/$image/members/$member"
            $body = @{"status" = $status} | convertTo-Json  -Compress
            write-verbose "Updating status for $m to image member list for image $image to $status"
            (Invoke-RestMethod -Uri ($uri) -Method PUT -body $body -Headers (GetAuthToken) -ContentType application/json)
            
        }
    } 
    END {

    }   
}

#Add Image Tag

#Remove Image Tag

#List Image tasks

#Import Image

#Export Image

#List Load Balancers
function Get-RSLoadBalancer(){
   #[CmdletBinding(DefaultParametersetName="RSServerSearch")] 
    param( 
        [Parameter()][string[]]$LoadBalancerID,
        [Parameter()][string[]]$Name,
        [Parameter()][string[]]$Status,
        [Parameter()][string[]]$Protocol,
        [Parameter()][int[]]$port
    ) 
    BEGIN {
        $product = "cloudLoadBalancers"        
    }
    PROCESS {
        write-verbose "Getting Loadbalancer List"
        write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"
#Set initial values    
        $offset=0
        $continue = $true
        $result = @()
        $baseuri = GetEndpoint -product $product
#Gather full list    
        if ($LoadBalancerID.count -gt 0) {
            
            $apiResult = "loadbalancer" 

            foreach ($lb in $LoadBalancerID) {
                $uri =$baseuri + "/loadbalancers/$lb"
                $result += (Invoke-RestMethod -Uri ($uri) -Method GET  -Headers (GetAuthToken) -ContentType application/json).($apiResult)
            }
        } else {
            $uri = $baseuri + "/loadbalancers" 
            $apiResult="loadbalancers"

            do {
                write-verbose ($uri + '?offset=' +$offset)
        
                $r = (Invoke-RestMethod -Uri ($uri + '?offset=' +$offset) -Method GET  -Headers (GetAuthToken) -ContentType application/json).($apiResult)
                $result += $r
                $offset += $r.count
                      
            } while ($r.count -gt 0) 

        }
#Filter list based.
        if ($continue) {
            if ($name.count -gt 1) {
                Write-verbose "Filtering list by name"
                $result = $result | where-object {$name -contains $_.name }
            }
            if ($name.count -eq 1) {
                Write-verbose "Filtering list by name"
                $result = $result | where-object {$_.name -like $name}
            }
            if ($LoadBalancerID.count -ne 0) {
                Write-verbose "Filtering list by LoadBalancerID"
                $result = $result | where-object {$LoadBalancerID -contains $_.id }
            }
            if ($image.count -ne 0) {
                Write-verbose "Filtering list by port"
                $result = $result | where-object { $port -contains $_.port }
            }
            if ($Protocol.count -ne 0) {
                Write-verbose "Filtering list by Protocol"
                $result = $result | where-object {$Protocol -contains $_.protocol }
            }
            if ($status.count -ne 0) {
                Write-verbose "Filtering list by status"
                $result = $result | where-object { $status -contains $_.status }
            }                                                                                                                                                        
            $result
        }   
    } 
    END {

    }   
}
#Create Load Balancer

#Update Load Balancer

#Delete Load Balancer

#Show LoadBalancer Error Page

#Set LoadBalancer Error Page

#Delete LoadBalancer Error Page

#Show Load Balancer Stats
function Get-RSLoadBalancerStats {
Param (
    [Parameter(Mandatory=$True)][string]$LoadBalancerID
)
    $product = "cloudLoadBalancers"

    write-verbose "Getting status for Load Balancer $LoadBalancerID"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

    $uri = (GetEndpoint -product $product) + "/loadbalancers/$LoadBalancerID/stats"
    
    Invoke-RestMethod -Uri $uri -Method GET -Headers (GetAuthToken) -ContentType application/json
}

#Show Load Balancer Nodes
function Get-RSLoadBalancerNodes {
Param (
    [Parameter(Mandatory=$True)][string]$LoadBalancerID
)
    $product = "cloudLoadBalancers"

    write-verbose "Getting nodes for Load Balancer $LoadBalancerID"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

    $uri = (GetEndpoint -product $product) + "/loadbalancers/$LoadBalancerID/nodes"
    
    (Invoke-RestMethod -Uri $uri -Method GET -Headers (GetAuthToken) -ContentType application/json).nodes
}
#Add Load Balancer Nodes

#Update Load Balancer Node

#Delete Load Balancer Nodes

#Show Load Balancer Node events
function Get-RSLoadBalancerNodeEvents {
Param (
    [Parameter(Mandatory=$True)][string]$LoadBalancerID
)
    $product = "cloudLoadBalancers"

    write-verbose "Getting node events for Load Balancer $LoadBalancerID"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

    $uri = (GetEndpoint -product $product) + "/loadbalancers/$LoadBalancerID/nodes/events"
    
    (Invoke-RestMethod -Uri $uri -Method GET -Headers (GetAuthToken) -ContentType application/json).nodeServiceEvents
}
#Add Virtual IP

#Delete Virtual IP

#Show Historical LB Usage\Current Usage
function Get-RSLoadBalancerUsage {
Param (
    [Parameter(Mandatory=$True)][string]$LoadBalancerID,
    [Parameter()][switch]$current
)
    $product = "cloudLoadBalancers"

    write-verbose "Getting usage for Load Balancer $LoadBalancerID"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

    $uri = (GetEndpoint -product $product) + "/loadbalancers/$LoadBalancerID/usage"
    if ($current.IsPresent){ $uri = "$uri/current" }
    write-verbose "URI: $uri"
    (Invoke-RestMethod -Uri $uri -Method GET -Headers (GetAuthToken) -ContentType application/json).loadBalancerUsageRecords
}
#Show Account Level Usage

#Show Load Balancer Access Lists

#Create Load Balancer Access List

#Delete Cloud Load Balancer access list

#Delete Load Blancer Access List entries.

#Show Load Balancer Health monitor

#Update Load Balancer Health monitor

#Delete Load Balancer Health monitor

#Enable LB Session Persistance

#Disable LB Session Persistance

#Enable\Disable Connection Logging

#Update connection throttle

#Delete connection throttle

#Show content caching

#Enable\Disable content caching

#Show SSL Config

#Update SSL Config

#Delete SSL Config

#List Certificate mappings

#Add certificate mappings

#Update certificate mapping

#Delete certificate mapping

#Add LB metadata

#Show LB Metadata

#Add Monitoring Entity

#List Monitoring Entities
function Get-RSEntity(){
    param( 
        [Parameter()][string[]]$entityID,
        [Parameter()][string[]]$ServerName,
        [Parameter()][string[]]$ServerID,
        [Parameter()][string[]]$ServerIP
    ) 
    BEGIN {
        $product = "cloudMonitoring"        
    }
    PROCESS {
        write-verbose "Getting Entity List"
        write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

        $uri = GetEndpoint -product $product
        if ($entityID.count -eq 1) {
            $uri += "/entities/$($entityID[0])"
        } else {
            $uri = $uri + "/entities" 
        }

        $continue = $true
        write-verbose $uri
        write-verbose "Invoke-RestMethod -Uri $uri -Method GET -Headers $(GetAuthToken) -ContentType application/json)"
        $result = Invoke-RestMethod -Uri $uri -Method GET -Headers (GetAuthToken) -ContentType application/json

        if ($continue) {
   <#
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
            #>
            $result.values
        }          
    } 
    END {

    }   
}

#Update monitoring entity

#delete monitoring entity

#Create a check

#test a check/test a check with debug

#test an existing check

#list checks/get check
function Get-RSCheck(){
    param( 
        [Parameter()][string[]]$entityID,
        [Parameter()][string[]]$checkID
    ) 
    BEGIN {
        $product = "cloudMonitoring"        
    }
    PROCESS {
        write-verbose "Getting Check List"
        write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

        $uri = GetEndpoint -product $product
       <# if ($entityID.count -eq 1) {
            $uri += "/entities/$($entityID[0])/checks"
        } else {
            $uri = $uri + "/entities" 
        }#>
        $uri += "/entities/$($entityID[0])/checks"

        $continue = $true
        write-verbose $uri
        write-verbose "Invoke-RestMethod -Uri $uri -Method GET -Headers $(GetAuthToken) -ContentType application/json)"
        $result = Invoke-RestMethod -Uri $uri -Method GET -Headers (GetAuthToken) -ContentType application/json

        if ($continue) {
   <#
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
            #>
            $result.values
        }          
    } 
    END {

    }   
}

#update check

#delete check

#Create alarm

#Test Alarm

#List Alarms\Get Alarm
function Get-RSAlarm(){
    param( 
        [Parameter()][string[]]$entityID,
        [Parameter()][string[]]$alarmID
    ) 
    BEGIN {
        $product = "cloudMonitoring"        
    }
    PROCESS {
        write-verbose "Getting Alarm List"
        write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

        $uri = GetEndpoint -product $product
       <# if ($entityID.count -eq 1) {
            $uri += "/entities/$($entityID[0])/checks"
        } else {
            $uri = $uri + "/entities" 
        }#>
        $uri += "/entities/$($entityID[0])/alarms"

        $continue = $true
        write-verbose $uri
        write-verbose "Invoke-RestMethod -Uri $uri -Method GET -Headers $(GetAuthToken) -ContentType application/json)"
        $result = Invoke-RestMethod -Uri $uri -Method GET -Headers (GetAuthToken) -ContentType application/json

        if ($continue) {
   <#
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
            #>
            $result.values
        }          
    } 
    END {

    }   
}
#Update alarm
function Update-RSAlarm(){
    param( 
        [Parameter()][string]$entityID,
        [Parameter()][string]$alarmID,
        [Parameter()][boolean]$disabled = $false,
        [Parameter()][string]$criteria
    ) 
    $product = "cloudMonitoring"

    write-verbose "Updating Alarm $alarmID"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"
    $body = @{"disabled" = $disabled} 
    
    if ($criteria -ne "") { $body.add("criteria", $criteria) }
    
    $body = $body | ConvertTo-Json -Compress -depth 10
    write-debug $body

    $uri = (GetEndpoint -product $product ) + "/entities/$entityID/alarms/$alarmID"
    $continue = $true

    (Invoke-RestMethod -Uri $uri -Method PUT -body $body  -Headers (GetAuthToken) -ContentType application/json).($apiResult)
}

#Delete alarm