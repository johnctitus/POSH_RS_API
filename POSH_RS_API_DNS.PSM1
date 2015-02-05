
#Get DNS Zones
function Get-RSDNSZone(){
param( 
        [Parameter()][string[]]$DomainID,
        [Parameter()][string[]]$Name,
        [Parameter()][string]$comment,
        [Parameter()][DateTime]$CreatedBefore,
        [Parameter()][DateTime]$CreatedAfter,
        [Parameter()][DateTime]$UpdatedBefore,
        [Parameter()][DateTime]$UpdatedAfter
    )
    BEGIN {
        $product = "cloudDNS"    
    }
    PROCESS {
        write-verbose "Getting DNS Zone List"
        write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

        $baseuri = GetEndpoint -product $product

        if ($DomainID.count -gt 0) {
            foreach ($did in $DomainID) {
                $uri = $baseuri + "/domains/$($did[0])"
                (Invoke-RestMethod -Uri $uri -Method GET  -Headers (GetAuthToken) -ContentType application/json)
            }

        } else {
            $uri = $baseuri + "/domains" 
            $apiResult="domains"

            $continue = $true
            $result = @()
            do {
                write-verbose $uri
        
                $result_json = (Invoke-RestMethod -Uri $uri -Method GET  -Headers (GetAuthToken) -ContentType application/json)
                $result +=  $result_json.($apiResult)
            } while ($result_json.next -ne $null)

            if ($continue) {
                if ($name.count -gt 1) {
                    Write-verbose "Filtering list by exact name"
                    $result = $result | where-object {$name -contains $_.name }
                }
                if ($name.count -eq 1) {
                    Write-verbose "Filtering list by name"
                    $result = $result | where-object {$_.name -like $name}
                }
                if ($status.count -ne "") {
                    Write-verbose "Filtering list by Comment"
                    $result = $result |  where-object {$_.comment -like $comment}
                }
                if ($createdBefore -gt 0) {
                    Write-verbose "Filtering list by before Created Date"
                    $result = $result | where-object { [dateTime]$_.created -le $changeDate} 
                }
                if ($createdAfter -gt 0) {
                    Write-verbose "Filtering list by after Created Date"
                    $result = $result | where-object { [dateTime]$_.created -ge $changeDate} 
                }
                if ($UpdatedBefore -gt 0) {
                    Write-verbose "Filtering list by Before Updated Date"
                    $result = $result | where-object { [dateTime]$_.updated -le $changeDate} 
                }
                if ($UpdatedAfter -gt 0) {
                    Write-verbose "Filtering list by After Updated Date"
                    $result = $result | where-object { [dateTime]$_.updated -ge $changeDate} 
                }
                $result
                if ($result_json.next -ne $null) { $uri = $baseURI + $result_json.next.subString(3)}
            }          
        }
    } 
    END {

    }   
}

#List Subdomains

#Create DNS Zone

#Update DNS Zone(s)

#Delete DNS Zone(s)

#Show Domain Changes

#Export Domain

#Import Domain

#Clone Domain

#List Records

#Add Record(s)

#Delete Record(s)

#Update Record(s)

#List PTR records

#Add PTR records

#Update PTR records

#Delete PTR records
