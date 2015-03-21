<#

Still Need to complete CBS Attachment functions

#>

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

#Create\Update Keypair
function New-RSKeyPair(){
    param( 
        [Parameter()][string]$Name,
        [Parameter()][string]$PublicKey
    ) 
    BEGIN {
        $product = "cloudServersOpenStack" 
        $apiResult = "keypair"
    }
    PROCESS {
        write-verbose "Creating new KeyPair"
        write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

        $uri = (GetEndpoint -product $product) +"/os-keypairs"

        write-verbose $uri
        $body = @{"keypair" = @{"name" = "$name"}} 
        if ($PublicKey -ne "") { 
            $body.keypair.add("public_key", $PublicKey) 
        }

        $body = $body | convertTo-json -depth 10

        (Invoke-RestMethod -Uri $uri -Method POST -Body $body -Headers (GetAuthToken) -ContentType application/json).($apiResult)
    } 
    END {

    }   
}

#List Key Pairs
function Get-RSKeyPair(){
    param( 
        [Parameter()][string[]]$Name
    ) 
    BEGIN {
        $product = "cloudServersOpenStack" 
    }
    PROCESS {
        write-verbose "Getting Key pairs"
        write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

        $uri = (GetEndpoint -product $product) +"/os-keypairs"

        write-verbose $uri
        $result = (Invoke-RestMethod -Uri $uri -Method GET  -Headers (GetAuthToken) -ContentType application/json).keypairs.keypair
        #$result = Invoke-RestMethod -Uri $uri -Method GET  -Headers (GetAuthToken) -ContentType application/json
            
        if ($name.count -gt 1) {
            Write-verbose "Filtering list by name"
            $result = $result | where-object {$name -contains $_.name }
        }
        if ($name.count -eq 1) {
            Write-verbose "Filtering list by name"
            $result = $result | where-object {$_.name -like $name}
        }    
        $result
    } 
    END {

    }   
}

#Delete Key Pairs
function Delete-RSKeyPair(){
    param( 
        [Parameter()][string]$Name
    ) 
    BEGIN {
        $product = "cloudServersOpenStack" 
        $apiResult = "keypair"
    }
    PROCESS {
        write-verbose "Deleting Keypairs"
        write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

        $uri = (GetEndpoint -product $product) +"/os-keypairs/$name"

        write-verbose $uri
        Invoke-RestMethod -Uri $uri -Method DELETE -Headers (GetAuthToken) -ContentType application/json
    } 
    END {

    }   
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

#Rescue Server
function Rescue-RSNextGenServer(){
Param (
    [Parameter(Mandatory=$True)][string]$serverID
)

    $product = "cloudServersOpenStack"

    write-verbose "Confirm Resize Next Gen Server $serverID"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"
    
    $uri = (GetEndpoint -product $product) + "/servers/$serverID/action"
    $body = @{"rescue" = "none"} | convertTo-json -depth 10

    Invoke-RestMethod -Uri $uri -Method POST -Body $body -Headers (GetAuthToken) -ContentType application/json
} 

#Unrescue server
function Unrescue-RSNextGenServer(){
Param (
    [Parameter(Mandatory=$True)][string]$serverID
)

    $product = "cloudServersOpenStack"

    write-verbose "Confirm Resize Next Gen Server $serverID"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"
    
    $uri = (GetEndpoint -product $product) + "/servers/$serverID/action"
    $body = @{"unrescue" = $null} | convertTo-json -depth 10

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

#Attach Volume

#List Volume Attachment(s)
function Get-RSNextGenServerCBS(){
Param (
    [Parameter(Mandatory=$True)][string]$serverID
)
    BEGIN {
        $product = "cloudServersOpenStack" 
    }
    PROCESS {
        write-verbose "Getting Key pairs"
        write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

        $uri = (GetEndpoint -product $product) +"/servers/$serverID/os-volume_attachments"

        write-verbose $uri
        $result = (Invoke-RestMethod -Uri $uri -Method GET  -Headers (GetAuthToken) -ContentType application/json).volumeAttachments
        #$result = Invoke-RestMethod -Uri $uri -Method GET  -Headers (GetAuthToken) -ContentType application/json
            
        if ($name.count -gt 1) {
            Write-verbose "Filtering list by name"
            $result = $result | where-object {$name -contains $_.name }
        }
        if ($name.count -eq 1) {
            Write-verbose "Filtering list by name"
            $result = $result | where-object {$_.name -like $name}
        }    
        $result
    } 
    END {

    }   
}

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

#Image functions included in POSH_RS_API_IMAGES

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

function Get-RSNextGenServerQuota {
Param (
    [Parameter()][switch]$rateLimit
)
    $product = "cloudServersOpenStack"

    write-verbose "Getting Next Gen Server Quota"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"
    
    if ($rateLimit.IsPresent) { 
        $apiResult = "rate"
    } else {
        $apiResult = "absolute"
    }

    $uri = (GetEndpoint -product $product) + "/limits"

    (Invoke-RestMethod -Uri $uri -Method GET -Headers (GetAuthToken) -ContentType application/json).limits.($apiResult)
}