﻿#Still need Update Image function, Add Image Tag, Remove Image Tag, List Image tasks, import image and export image functions


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
        $member = get-RSDDI
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
function Get-RSImageTasks(){
    param( 
        [Parameter()][string[]]$taskID
    )

    $product = "cloudImages"
    $apiResult="tasks"
    $uri = "/tasks"
    $method = "GET"

    write-verbose "Listing Image Tasks"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"
    if ($taskID.count -gt 0){
        (Invoke-RSAPICall -product $product -Uri $uri -Method $method -body $body).($apiResult)
    } else {
        foreach ($task in $taskID) {
            (Invoke-RSAPICall -product $product -Uri "$uri/$task" -Method $method -body $body)
        }
    }
}

#Import Image
function Import-RSImage(){
    param( 
        [Parameter()][string]$ImageName,
        [Parameter()][string]$ImagePath
    )

    $product = "cloudImages"
    $uri = "/tasks"
    $method = "POST"
    $body = @{"type"="import";"input"=@{"image_properties"=@{"name" = "$ImageName"};"import_from"="$ImagePath"}} | convertto-json -depth 10

    write-verbose "Exporting Image $imageID"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"
    (Invoke-RSAPICall -product $product -Uri "$uri" -Method $method -body $body)
    
}

#Export Image
function Export-RSImage(){
    param( 
        [Parameter()][string]$ImageID,
        [Parameter()][string]$Container
    )

    $product = "cloudImages"
    $uri = "/tasks"
    $method = "POST"
    $body = @{"type"="export";"input"=@{"image_uuid"="$imageID";"receiving_swift_container"="$Container"}} | convertto-json -depth 10


    write-verbose "Exporting Image $imageID"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"
    (Invoke-RSAPICall -product $product -Uri "$uri" -Method $method -body $body)
    
}