Function Set-RSFilesAccountMetadata(){
param( 
        [Parameter()][string]$TempURLKey,
        [Parameter()][string]$TempURLKey2,
        [Parameter()][hashtable]$Metadata

    )  

    $product = "cloudFiles"
    $headers = GetAuthToken
    write-verbose "Set Cloud Files Account Metadata $containerID"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"
    
    if ($TempURLKey -ne "") { 
       $headers.add("X-Account-Meta-Temp-URL-Key", $TempURLKey) 
    }
    if ($TempURLKey2 -ne "") { 
       $headers.add("X-Account-Meta-Temp-URL-Key-2", $TempURLKey2) 
    }
    if ($Metadata.count -gt 0) {         
        foreach ($key in $Metadata.keys){
            if ($metadata[$key] -eq "") {
                $headers.add("X-Account-Meta-$key", $metadata[$key])
            }else {
                $headers.add("X-Remove-Account-Meta-$key", $metadata[$key]) 
            }
        }
    }

    $uri = (GetEndpoint -product $product) 
    write-verbose $uri
        
    (Invoke-WebRequest -Uri $uri -Method POST -Headers $headers ).headers  
}

function Get-RSFilesContainerMetadata(){
    param( 
        [Parameter()][string]$ContainerID
    ) 

    $product = "cloudFiles"

    write-verbose "Get Cloud Files Container Metadata $containerID"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"
    
        
    $uri = (GetEndpoint -product $product) + "/$ContainerId"
    write-verbose $uri
        
    (Invoke-WebRequest -Uri $uri -Method HEAD -Headers (GetAuthToken)).headers  
}

function Set-RSFilesContainerMetadata(){
    param( 
        [Parameter(Mandatory=$True)][string]$ContainerID,
        [Parameter()][switch]$ClearReadUsers,
        [Parameter()][string[]]$ReadUsers,
        [Parameter()][switch]$ClearWriteUsers,
        [Parameter()][string[]]$WriteUsers,
        [Parameter()][switch]$ClearVersioning,
        [Parameter()][string]$VersionContainer,
        [Parameter()][hashtable]$Metadata
    )  

    $product = "cloudFiles"
    $headers = GetAuthToken
    write-verbose "Set Cloud Files Account Metadata $containerID"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"
    
    if ($ClearReadUsers.IsPresent) { 
        $headers.add("X-Remove-Container-Read", "")
    } elseif ($ReadUsers.count -gt 0) { 
       $headers.add("X-Container-Read", ($readUsers -join ",")) 
    }

    if ($ClearWriteUsers.IsPresent) { 
        $headers.add("X-Remove-Container-Write", "")
    } elseif ($WriteUsers.count -gt 0) { 
       $headers.add("X-Container-Write", ($WriteUsers -join ",")) 
    }

    if ($ClearVersioning.IsPresent) { 
        $headers.add("X-Remove-Versions-Location", "")
    } elseif ($VersionContainer.count -gt 0) { 
       $headers.add("X-Versions-Location", $VersionContainer) 
    }

    if ($Metadata.count -gt 0) {         
        foreach ($key in $Metadata.keys){
            if ($metadata[$key] -eq "") {
                $headers.add("X-Container-Meta-$key", $metadata[$key])
            }else {
                $headers.add("X-Remove-Container-Meta-$key", $metadata[$key]) 
            }
        }
    }

    $uri = (GetEndpoint -product $product) 
    write-verbose $uri
        
    (Invoke-WebRequest -Uri $uri -Method POST -Headers $headers ).headers  
}

function Get-RSFilesObjectMetadata(){
   [CmdletBinding(DefaultParametersetName="RSServerSearch")] 
    param( 
        [Parameter(Mandatory=$True)][string]$ContainerID,
        [Parameter(Mandatory=$True)][string[]]$objectID
    )  

    $product = "cloudFiles"

    write-verbose "Listing Cloud Files Object Metadata $containerID"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"
    
    foreach ($object in $objectID) {    
        $uri = (GetEndpoint -product $product) + "/$ContainerId/$object"
        write-verbose $uri
        
        (Invoke-WebRequest -Uri $uri -Method HEAD -Headers (GetAuthToken)).headers  
    }
}

function Set-RSFilesObjectMetadata(){
    param( 
        [Parameter(Mandatory=$True)][string]$ContainerID,
        [Parameter(Mandatory=$True)][string]$ObjectID,
        [Parameter()][date]$DeleteAt,
        [Parameter()][string]$DeleteAfter,
        [Parameter()][switch]$DetectContentType,
        [Parameter()][string]$ContentType,
        [Parameter()][string]$ContentDisposition,
        [Parameter()][string]$ContentEncoding,
        [Parameter()][hashtable]$Metadata

    )  

    $product = "cloudFiles"
    $headers = GetAuthToken
    write-verbose "Set Cloud Files Account Metadata $containerID"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"
    
    if ($DeleteAt.count -ne $null) { 
       $headers.add("X-Delete-At", ([Math]::Floor([decimal](Get-Date($DeleteAt).ToUniversalTime()-uformat "%s")))) 
    }

    if ($DeleteAt.count -ne "") { 
       $headers.add("X-Delete-After", $DeleteAfter) 
    }

    if ($DetectContentType.IsPresent) { 
        $headers.add("X-Detect-Content-Type", "True")
    } elseif ($ContentType -ne "") { 
       $headers.add("Content-Type", $ContentType ) 
    }

    if ($ContentDisposition -ne "") { 
       $headers.add("Content-Disposition", $ContentDisposition ) 
    }

    if ($ContentEncoding -ne "") { 
       $headers.add("Content-Encoding", $ContentEncoding ) 
    }

    if ($Metadata.count -gt 0) {         
        foreach ($key in $Metadata.keys){
            if ($metadata[$key] -eq "") {
                $headers.add("X-Object-Meta-$key", $metadata[$key])
            }else {
                $headers.add("X-Remove-Object-Meta-$key", $metadata[$key]) 
            }
        }
    }

    $uri = (GetEndpoint -product $product) 
    write-verbose $uri
        
    (Invoke-WebRequest -Uri $uri -Method POST -Headers $headers ).headers  
}

function List-RSFilesContainer(){
   [CmdletBinding(DefaultParametersetName="RSServerSearch")] 
    param( 
        [Parameter()][string]$ContainerID,
        [Parameter()][string[]]$name,
        [Parameter()][int]$minBytes,
        [Parameter()][int]$maxBytes,
        [Parameter()][int]$minFiles,
        [Parameter()][int]$maxFiles,
        [Parameter()][string[]]$contentType

    ) 

    $product = "cloudFiles"

    write-verbose "Listing Cloud Files Container $containerID"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"
    
    $marker = ""
    $results =@()
    do {
        $uri = (GetEndpoint -product $product) + "/$ContainerId"+"?format=json&marker=$marker"
        write-verbose $uri
        $result = Invoke-RestMethod -Uri $uri -Method GET -Headers (GetAuthToken) -ContentType application/json -OutFile $objectID
        $marker = ($result | Select-Object -Last 1).name
        write-verbose "Marker: |$marker|"
        $results += $result
    } while ($result.count -gt 0)

    #Filter results
    if ($name.count -gt 1) {
        Write-verbose "Filtering list by name"
        $results = $results | where-object {$name -contains $_.name }
    }
    if ($name.count -eq 1) {
        Write-verbose "Filtering list by name"
        $results = $results | where-object {$_.name -like $name}
    }
    if ($flavorID.count -ne 0) {
        Write-verbose "Filtering list by FlavorID"
        $results = $results | where-object {$flavorID -contains $_.id }
    }
            
    if ($MinBytes -gt 0) {
        Write-verbose "Filtering list by MinBytes"
        $results = $results | where-object -property bytes -ge "$MinBytes"
    }
    if ($MaxBytes -gt 0) {
        Write-verbose "Filtering list by MaxBytes"
        $results = $results | where-object -property bytes -le "$MaxBytes"
    }
            
    if ($MinFiles -gt 0) {
        Write-verbose "Filtering list by MinFiles"
        $results = $results | where-object {$_.count -eq $null -or $_.count -ge $minFiles}
    }
    if ($MaxFiles -gt 0) {
        Write-verbose "Filtering list by MaxFiles"
        $results = $results | where-object {$_.count -eq $null -or $_.count -le $maxFiles}
    }     
    if ($contentType.count -gt 1) {
        Write-verbose "Filtering list by contentType"
        $results = $results | where-object {$_.content_type -eq $null -or $contentType -contains $_.content_type }
    }
    if ($contentType.count -eq 1) {
        Write-verbose "Filtering list by contentType"
        $results = $results | where-object {$_.content_type -eq $null -or $_.content_type -like $contentType}
    }

    $results
}

function New-RSFilesContainer() {
    param( 
        [Parameter()]$ContainerID,
        [Parameter()][string[]]$ReadUsers,
        [Parameter()][string[]]$WriteUsers,
        [Parameter()][string]$VersionContainer,
        [Parameter()][hashtable]$Metadata
    ) 

    $product = "cloudFiles"

    write-verbose "Create Cloud Files Container $containerID"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"
    
    $headers = GetAuthToken
    
    if ($ReadUsers.count -gt 0) { 
       $headers.add("X-Container-Read", ($readUsers -join ",")) 
    }

    if ($WriteUsers.count -gt 0) { 
       $headers.add("X-Container-Write", ($WriteUsers -join ",")) 
    }

    if ($VersionContainer.count -gt 0) { 
       $headers.add("X-Versions-Location", $VersionContainer) 
    }

    if ($Metadata.count -gt 0) {         
        foreach ($key in $Metadata.keys){
            $headers.add("X-Container-Meta-$key", $metadata[$key])
        }
    }
        
    $uri = (GetEndpoint -product $product) + "/$ContainerId"
    write-verbose $uri
        
    Invoke-RestMethod -Uri $uri -Method PUT -Headers (GetAuthToken)
}
  
function Delete-RSFilesContainer() {
    param( 
        [Parameter()]$ContainerID
    ) 

    $product = "cloudFiles"

    write-verbose "Create Cloud Files Container $containerID"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"
    
        
    $uri = (GetEndpoint -product $product) + "/$ContainerId"
    write-verbose $uri
        
    Invoke-RestMethod -Uri $uri -Method DELETE -Headers (GetAuthToken)
}


function Upload-RSFilesObject(){
    param( 
        [Parameter(Mandatory=$True)][string]$ContainerID,
        [Parameter(Mandatory=$True)][string]$ObjectID,
        [Parameter()][date]$DeleteAt,
        [Parameter()][string]$DeleteAfter,
        [Parameter()][switch]$DetectContentType,
        [Parameter()][string]$ContentType,
        [Parameter()][string]$ContentDisposition,
        [Parameter()][string]$ContentEncoding,
        [Parameter()][hashtable]$Metadata

    )  

    $product = "cloudFiles"
    $headers = GetAuthToken
    write-verbose "Set Cloud Files Account Metadata $containerID"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"
    
    if ($DeleteAt.count -ne $null) { 
       $headers.add("X-Delete-At", ([Math]::Floor([decimal](Get-Date($DeleteAt).ToUniversalTime()-uformat "%s")))) 
    }

    if ($DeleteAt.count -ne "") { 
       $headers.add("X-Delete-After", $DeleteAfter) 
    }

    if ($DetectContentType.IsPresent) { 
        $headers.add("X-Detect-Content-Type", "True")
    } elseif ($ContentType -ne "") { 
       $headers.add("Content-Type", $ContentType ) 
    }

    if ($ContentDisposition -ne "") { 
       $headers.add("Content-Disposition", $ContentDisposition ) 
    }

    if ($ContentEncoding -ne "") { 
       $headers.add("Content-Encoding", $ContentEncoding ) 
    }

    if ($Metadata.count -gt 0) {         
        foreach ($key in $Metadata.keys){
            if ($metadata[$key] -eq "") {
                $headers.add("X-Object-Meta-$key", $metadata[$key])
            }else {
                $headers.add("X-Remove-Object-Meta-$key", $metadata[$key]) 
            }
        }
    }

}

function Download-RSFilesObject() {
    param( 
        [Parameter(Mandatory=$True)][string]$ContainerID,
        [Parameter(Mandatory=$True)][string[]]$objectID

    )  
    
    $product = "cloudFiles"

    write-verbose "Downloading file $objectID"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"
    foreach ($object in $objectID) {
                
        $uri = (GetEndpoint -product $product) + "/$ContainerId/$object"
        
        $savefile = $object.replace(":","")
        $path = split-path $savefile
        if ($path -ne "" -and -not (Test-Path $path)) {New-Item $path -Type directory}
        
        Invoke-RestMethod -Uri $uri -Method GET -Headers (GetAuthToken) -ContentType application/json -OutFile "$savefile"
    }

}

Function Copy-RSFilesObject(){

}

Function Delete-RSFilesObject(){

}