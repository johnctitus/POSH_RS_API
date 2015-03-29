#List Agent(s)
function Get-RSBackupAgents{
    param( 
     <#   [Parameter()][string[]]$VolumeID,
        [Parameter()][ValidateSet("SATA","SSD")][string]$VolumeType,
        [Parameter()][ValidateRange(50,1024)][int]$MinSize,
        [Parameter()][ValidateRange(50,1024)][int]$MaxSize,
        [Parameter()][string]$name,
        [Parameter()][string]$description,
        [Parameter()][string]$SnapshotID,
        [Parameter()][string]$SourceVolumeID,
        [Parameter()][string]$ImageID#>
    )
<#
$agents_temp = Invoke-RSAPICall -Method GET -product "cloudBackup" -URI "/user/agents"

$agents = @()
$activity = @()
$backups = @()
foreach ($agentID in $agents_temp.MachineAgentId) {
    $agents += Invoke-RSAPICall -Method GET -product "cloudBackup" -URI "/agent/$agentID"
    $Activity += Invoke-RSAPICall -Method GET -product "cloudBackup" -URI "/system/activity/$agentId"
}
#>
    $product = "cloudBackup"
    $apiResult="volumes"
    $uri = "/volumes"
    $method = "GET"

    write-verbose "Listing CBS Volumes"
    write-debug "Parameters:$($MyInvocation.BoundParameters | format-table -AutoSize | out-string)"

    (Invoke-RSAPICall -product $product -Uri $uri -Method $method -body $body).($apiResult)
}

#Wakeup Agents

#Enable\Disable Agent

#Enable Backup Encryption

#Change Encryption Password

#Delete Agent

#Migrate Vault

#Update Agent Behavior

#Create Backup Config

#Update Backup Config

#List Backup Configurations

#Enable\Disable Backup Configurations

#Delete Backup Configuration

#Start\Stop a backup

#List Backup Activity
#List Completed Backups

#Get Backup Report