function Get-RSCBSQuota {
Param (
)
    $product = "cloudBlockStorage"

    write-verbose "Getting CBS Quota"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

    $uri = (GetEndpoint -product $product) + "/os-quota-sets/"+(Get-RSDDI)+"?usage=True"
    (Invoke-RestMethod -Uri $uri -Method GET -Headers (GetAuthToken) -ContentType application/json).quota_set
}

function Get-RSCBSVolume{
    param( 
        [Parameter()][string[]]$VolumeID,
        [Parameter()][ValidateSet("SATA","SSD")][string]$VolumeType,
        [Parameter()][ValidateRange(50,1024)][int]$MinSize,
        [Parameter()][ValidateRange(50,1024)][int]$MaxSize,
        [Parameter()][string]$name,
        [Parameter()][string]$description,
        [Parameter()][string]$SnapshotID,
        [Parameter()][string]$SourceVolumeID,
        [Parameter()][string]$ImageID
    )

    $product = "cloudBlockStorage"
    $apiResult="volumes"
    $uri = "/volumes"
    $method = "GET"

    write-verbose "Listing CBS Volumes"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

    (Invoke-RSAPICall -product $product -Uri $uri -Method $method -body $body).($apiResult)
}

function New-RSCBSVolume{
    param( 
        [Parameter(Mandatory=$True)][ValidateSet("SATA","SSD")][string]$VolumeType,
        [Parameter(Mandatory=$True)][ValidateRange(50,1024)][int]$Size,
        [Parameter(Mandatory=$True)][string]$name,
        [Parameter()][string]$description,
        [Parameter()][string]$SnapshotID,
        [Parameter()][string]$VolumeID,
        [Parameter()][string]$ImageID
    )

    $product = "cloudBlockStorage"
    $apiResult="volume"
    $uri = "/volumes"
    $method = "POST"

    if ($volumeType -eq "SATA" -and $size -lt 75) { $size = 75}

    $body = @{"volume" = @{"volume_type" = "$VolumeType";"size" = $size;"display_name" = "$name"}} 
    
    if ($description -ne "") { $body.volume.add("display_description", $Description) }

    if ($SnapshotID -ne "") { $body.volume.add("snapshot_id", $SnapshotID) }
    elseif ($VolumeID -ne "") { $body.volume.add("source_volid", $VolumeID) }
    elseif ($ImageID -ne "") { $body.volume.add("imageRef", $ImageID) }

    $body = $body | ConvertTo-Json -Compress -depth 10

    write-verbose "Updating CBS Volume $VolumeID"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

    (Invoke-RSAPICall -product $product -Uri $uri -Method $method -body $body).($apiResult)
}

function Update-RSCBSVolume{
    param( 
        [Parameter(Mandatory=$True)][string]$VolumeID,
        [Parameter()][string]$name,
        [Parameter()][string]$description
    )

    $product = "cloudBlockStorage"
    $apiResult="volume"
    $uri = "/volumes/$VolumeID"
    $method = "PUT"
    
    $body = @{"volume" =  @{}} 
    
    if ($name -ne "") { $body.volume.add("display_name", $Name) }
    if ($description -ne "") { $body.volume.add("display_description", $Description) }

     $body = $body | ConvertTo-Json -Compress -depth 10

    write-verbose "Updating CBS Volume $VolumeID"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

    (Invoke-RSAPICall -product $product -Uri $uri -Method $method -body $body).($apiResult)
}

function Delete-RSCBSVolume{
param( 
        [Parameter(Mandatory=$True)][string]$VolumeID
    )

    $product = "cloudBlockStorage"
    $apiResult="volumes"
    $uri = "/volumes/$VolumeID"
    $method = "DELETE"

    write-verbose "Deleting CBS Volume $VolumeID"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

    (Invoke-RSAPICall -product $product -Uri $uri -Method $method).($apiResult)
}

function Get-RSCBSSnapshot{
}

function New-RSCBSSnapshot{
}

function Update-RSCBSSnapshot{
}

function Delete-RSCBSSnapshot{
}
