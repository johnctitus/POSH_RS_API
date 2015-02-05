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
