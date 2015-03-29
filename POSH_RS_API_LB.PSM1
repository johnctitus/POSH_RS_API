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
function New-RSLoadBalancer {
Param (
    #[Parameter(Mandatory=$True)][string]$LoadBalancerID,
    #[Parameter(Mandatory=$True)][string[]]$NodeAddress,
    [Parameter(Mandatory=$True)][string]$Name,
    [Parameter(Mandatory=$True)][string]$Protocol,
    [Parameter()][ValidateSet("ENABLED","DISABLED")][string]$halfClosed,
    [Parameter(Mandatory=$True)][string]$VirtualIPs,
    #[Parameter()][string]$AccessList,
    [Parameter()][string]$Algorithm,
    [Parameter()][ValidateSet("ENABLED","DISABLED")][string]$ConnectionLogging,
    [Parameter()][string]$ConnectionThrottle,
    [Parameter()][string]$HealthMonitor,
    [Parameter()][string]$Metadata,
    [Parameter()][int]$port,
    [Parameter()][int]$timeout,
    [Parameter()][ValidateSet("ENABLED","DISABLED")][string]$SessionPersistance,
    [Parameter()][ValidateSet("ENABLED","DISABLED")][string]$HTTPSRedirect
)
    $product = "cloudLoadBalancers"
    write-host "Unfinished"
    write-verbose "Adding nodes for Load Balancer $LoadBalancerID"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"
    $lb = @{"name"="$name";"protocol"="$protocol";}
            
        if ($condition -ne "") { 
            $n.add("condition", $condition)
        }
        if ($type -ne "") { 
            $n.add("type", $type)
        }
        if ($weight -ge 1 -and $weight -le 100) { 
            $n.add("weight", $weight)
        }
        $nodes += $N
    
    $uri = (GetEndpoint -product $product) + "/loadbalancers"
    $body = @{"loadBalancer" = $lb} | convertTo-Json  -Compress
    write-verbose "BODY: $body"

    #(Invoke-RestMethod -Uri $uri -Method POST -Headers (GetAuthToken) -body $body  -ContentType application/json).nodes
}

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
function Add-RSLoadBalancerNodes {
Param (
    [Parameter(Mandatory=$True)][string]$LoadBalancerID,
    [Parameter(Mandatory=$True)][string[]]$NodeAddress,
    [Parameter(Mandatory=$True)][int]$port,
    [Parameter(Mandatory=$True)][ValidateSet("ENABLED","DISABLED","DRAINING")][string]$condition,
    [Parameter()][ValidateSet("PRIMARY","SECONDARY")][string]$Type,
    [Parameter()][int]$weight
)
    $product = "cloudLoadBalancers"

    write-verbose "Adding nodes for Load Balancer $LoadBalancerID"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"
    $nodes = @()
    foreach ($node in $NodeAddress){
        $n = @{"address"="$node";"port"=$port}
            
        if ($condition -ne "") { 
            $n.add("condition", $condition)
        }
        if ($type -ne "") { 
            $n.add("type", $type)
        }
        if ($weight -ge 1 -and $weight -le 100) { 
            $n.add("weight", $weight)
        }
        $nodes += $N
    }
    $uri = (GetEndpoint -product $product) + "/loadbalancers/$LoadBalancerID/nodes"
    $body = @{"nodes" = $nodes} | convertTo-Json  -Compress
    write-verbose "BODY: $body"

    (Invoke-RestMethod -Uri $uri -Method POST -Headers (GetAuthToken) -body $body  -ContentType application/json).nodes
}

#Update Load Balancer Node
function Update-RSLoadBalancerNodes {
Param (
    [Parameter(Mandatory=$True)][string]$LoadBalancerID,
    [Parameter(Mandatory=$True)][string[]]$NodeID,
    [Parameter()][ValidateSet("ENABLED","DISABLED","DRAINING")][string]$condition,
    [Parameter()][ValidateSet("PRIMARY","SECONDARY")][string]$Type,
    [Parameter()][int]$weight
)
    $product = "cloudLoadBalancers"

    write-verbose "Updating nodes for Load Balancer $LoadBalancerID"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"
    $nodes = @()
    foreach ($node in $NodeID){
        $n = @{}
            
        if ($condition -ne "") { 
            $n.add("condition", $condition)
        }
        if ($type -ne "") { 
            $n.add("type", $type)
        }
        if ($weight -ge 1 -and $weight -le 100) { 
            $n.add("weight", $weight)
        }
   
        $uri = (GetEndpoint -product $product) + "/loadbalancers/$LoadBalancerID/nodes/$node"
        $body = @{"node" = $n} | convertTo-Json  -Compress
        write-verbose "BODY: $body"

        (Invoke-RestMethod -Uri $uri -Method PUT -Headers (GetAuthToken) -body $body  -ContentType application/json).nodes
    }
}

#Delete Load Balancer Nodes
function Delete-RSLoadBalancerNodes {
Param (
    [Parameter(Mandatory=$True)][string]$LoadBalancerID,
    [Parameter(Mandatory=$True)][string[]]$NodeID
)
    $product = "cloudLoadBalancers"

    write-verbose "Deleting nodes for Load Balancer $LoadBalancerID"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"
    $nodes = @()
    foreach ($node in $NodeID){
           
        $uri = (GetEndpoint -product $product) + "/loadbalancers/$LoadBalancerID/nodes/$node"

        (Invoke-RestMethod -Uri $uri -Method DELETE -Headers (GetAuthToken) -body $body  -ContentType application/json).nodes
    }
}

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

function Get-RSLoadBalancerCertMapping {
Param (
    [Parameter(Mandatory=$True)][string]$LoadBalancerID
)
    $product = "cloudLoadBalancers"
    #$apiResult="volumes"
    $uri = "/loadbalancers/$LoadBalancerID/ssltermination/certificatemappings"
    $method = "GET"

    write-verbose "Listing CLB Certificate Mappings"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

    (Invoke-RSAPICall -product $product -Uri $uri -Method $method -body $body).certificateMappings.certificateMapping
}
#Add certificate mappings
function Add-RSLoadBalancerCertMapping {
Param (
    [Parameter(Mandatory=$True)][string]$LoadBalancerID,
    [Parameter(Mandatory=$True)][string]$hostname,
    [Parameter(Mandatory=$True)][string]$privateKey,
    [Parameter(Mandatory=$True)][string]$certificate,
    [Parameter(Mandatory=$True)][string]$IntermediateCertificate
)
    $product = "cloudLoadBalancers"
    $apiResult="certificateMapping"
    $uri = "/loadbalancers/$LoadBalancerID/ssltermination/certificatemappings"
    $method = "POST"

    $body = @{
                "certificateMapping" = @{
                   "hostName"                = "$hostName";
                   "privateKey"              = "$privateKey";
                   "certificate"             = "$certificate";
                   "intermediateCertificate" = "$IntermediateCertificate"
                }
            
            } | ConvertTo-Json -depth 10

    write-verbose "Adding CLB Certificate Mappings"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

    (Invoke-RSAPICall -product $product -Uri $uri -Method $method -body $body).($apiResults)
}

#Update certificate mapping

#Delete certificate mapping

#Add LB metadata

#Show LB Metadata

function Get-RSLoadBalancerQuota {
Param (
    [Parameter()][switch]$rateLimit
)
    $product = "cloudLoadBalancers"

    write-verbose "GettingLoad Balancer Quota"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"
    $uri = (GetEndpoint -product $product)

    if ($rateLimit.IsPresent) { 
        (Invoke-RestMethod -Uri "$uri/limits" -Method GET -Headers (GetAuthToken) -ContentType application/json).limits.rate
    } else {
        (Invoke-RestMethod -Uri "$uri/loadbalancers/absolutelimits" -Method GET -Headers (GetAuthToken) -ContentType application/json).absolute
    }
}
   