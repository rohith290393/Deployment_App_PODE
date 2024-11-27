################################################
# Script Purpose: Triggers deployment of the package
# Site: UBP - Sites
# Author: Rohith Vignesh
# Date: 14/03/2024
#################################################

#Primary checks

#1. check connection to FE and BE server
#2. Check the folders are available
#3. set rule only if this pass continue to next or exit and report back.

# Setting up the current directory
$Deploymentsite = $args[0]
$SelectedPackage = $args[1]
$Operation = $args[2]
$site = $args[3]
$Deploymenttype = $args[4]
$path = $args[5]
$query = $args[6]
$DBName = $args[7]
$query_order = $args[8]
$crmoperation = $args[9]
$s2i_integration_setting = $args[10]

"#### Deployment Application log started ####" | Out-File -FilePath $path -Append
$CurrentDirectory = "E:\WDX\Deployment_application\UBP"  #Enter the current Directory path # **** Change Path **** #

write-host "Deploymentsite $Deploymentsite" -ForegroundColor Blue
if($pwd.Path -ne $CurrentDirectory)
{
    Write-Host "Setting the PS directory path to $CurrentDirectory"
    Set-Location -Path $CurrentDirectory
}

"#### loading required paramters ####" | Out-File -FilePath $path -Append
#Get Json file

$GetJson = Get-Content -path "$CurrentDirectory\parameter_UBP.json" | ConvertFrom-Json

#Variables
if($site -eq "FLW"){
    $Packageloc = $GetJson.Packageloc.Replace('$SelectedPackage' , $SelectedPackage).Replace('$site', "UFW")
}
else{
    $Packageloc = $GetJson.Packageloc.Replace('$SelectedPackage' , $SelectedPackage).Replace('$site', $site)
}
$Module = $GetJson.Module
$EnvName = $Deploymentsite
$API = $GetJson.API.Replace('$site', $site)
$Portal = $GetJson.Portal.Replace('$site', $site)
$RestartServiceNames = $GetJson.RestartServiceNames
$APICopyFile_Source = $GetJson.APICopyFile_Source.Replace('$Deploymentsite', $Deploymentsite).Replace('$SelectedPackage', $SelectedPackage)
$APICopyFile_Destination = $GetJson.APICopyFile_Destination.Replace('$Deploymentsite', $Deploymentsite)
$PortalCopyFile_Source = $GetJson.PortalCopyFile_Source.Replace('$Deploymentsite', $Deploymentsite).Replace('$SelectedPackage', $SelectedPackage)
$PortalCopyFile_Destination = $GetJson.PortalCopyFile_Destination.Replace('$Deploymentsite', $Deploymentsite)
$APICustomAssembliesCopyFile_Source = $GetJson.APICustomAssembliesCopyFile_Source.Replace('$Deploymentsite', $Deploymentsite).Replace('$SelectedPackage', $SelectedPackage)
$APICustomAssembliesCopyFile_Destination = $GetJson.APICustomAssembliesCopyFile_Destination.Replace('$Deploymentsite', $Deploymentsite)
$FolderPath = $GetJson.FolderPath
$BE_FolderPath = $GetJson.BE_FolderPath
$NewPoolUsername = $GetJson.NewPoolUsername
$NewPoolPassword = $GetJson.NewPoolPassword
$WindowsFeatures = $GetJson.WindowsFeatures
$IISFeatures = $GetJson.IISFeatures
$ConfigFilePath = $GetJson.ConfigFilePath.Replace('$Deploymentsite', $Deploymentsite)
$Service_UserName = $GetJson.Service_UserName
$Service_Password = $GetJson.Service_Password
$FE_Server = $GetJson.FE_Server
$BE_Server = $GetJson.BE_Server
$ServerInstance = $GetJson.ServerInstance
$UBPserver = $GetJson.UBP_server
$UBP_password = $GetJson.UBP_password
$UBP_Username = $GetJson.UBP_username
#$Path = "$($GetJson.Path)\output_$(Get-Date -Format 'dd-MM-yyyy_HH-mm-ss').txt"


#Edit WDXAPI & WDXPORTAL URI Values
#Variables

$CRM_Password = $GetJson.CRM_Password
$CRM_UserName = $GetJson.CRM_UserName
$wdx_setting_LogicalName = $GetJson.wdx_setting_LogicalName
$ServerURL = $GetJson.ServerURL.Replace('$Deploymentsite', $Deploymentsite)
$WDXAPI_Value = $GetJson.WDXAPI_Value.Replace('$Deploymentsite', $Deploymentsite)
$WDXPORTAL_Value = $GetJson.WDXPORTAL_Value.Replace('$Deploymentsite', $Deploymentsite)
$EncryptionKey = $GetJson.EncryptionKey
$OrgName = $GetJson.OrgName.Replace('$Deploymentsite', $Deploymentsite)
"#### Paramters loading completed ####" | Out-File -FilePath $path -Append

#$Path = "E:\WDX_Automation\WDX_Sites\$EnvName\logs.txt"
try{
"#### Connecting to Backend and frontend servers started ####" | Out-File -FilePath $path -Append
$Service_Password = ConvertTo-SecureString ($Service_Password) -AsPlainText -Force
    
$FE_Cred = New-Object System.Management.Automation.PSCredential ($Service_UserName, $Service_Password)

$BE_Cred = New-Object System.Management.Automation.PSCredential ($Service_UserName, $Service_Password)

$FE_Session = New-PSSession -ComputerName $FE_Server -Credential $FE_Cred -ErrorAction Stop

$BE_Session = New-PSSession -ComputerName $BE_Server -Credential $BE_Cred -ErrorAction Stop

$UBP_password1 = ConvertTo-SecureString ("RUZjfswe76428/hkoas5") -AsPlainText -Force

$UBP_cred = New-Object System.Management.Automation.PSCredential ("ADCHPBK\CT884", $UBP_password1)

$UBP_session = New-PSSession -ComputerName $UBPserver -Credential $UBP_cred -ErrorAction Stop 

Write-Host "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') Connection to the servers $FE_Server, $BE_Server Established" -ForegroundColor Green
"$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') Connection to the servers $FE_Server, $BE_Server Established" | Out-File -FilePath $path -Append
"#### Server connection completed ####" | Out-File -FilePath $path -Append
}
catch{
    Write-Host "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') Connection to the servers $FE_Session, $BE_Session failed... ERROR: $($_)" -ForegroundColor Red
    "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') Connection to the servers $FE_Session, $BE_Session failed... ERROR: $($_)" | Out-File -FilePath $path -Append
    "#### Unable to connect to the servers ####" | Out-File -FilePath $path -Append
    Exit;
}

Write-Host $FE_Session -ForegroundColor Green
Write-Host $BE_Session -ForegroundColor Green

try{
#Import-Module -name "E:\Rohith\Script\Deployment_application\Latest_25-07-2024\IIS_framework.ps1" -Force
# change path here
"#### Loading functions from framework ####" | Out-File -FilePath $path -Append
. $CurrentDirectory\IIS_framework_UBP.ps1 -Module $Module -ENVName $ENVName -FolderPath $FolderPath -API $API -Portal $Portal -Packageloc $Packageloc -Service_UserName $Service_UserName -Service_Password $Service_Password -FE_Server $FE_Server -BE_Server $BE_Server -RestartServiceNames $RestartServiceNames -path $path -ServerInstance $ServerInstance -DBName $DBName -query $query -ServerURL $ServerURL -CRM_UserName $CRM_UserName -CRM_Password $CRM_Password -OrgName $OrgName -EncryptionKey $EncryptionKey -wdx_setting_LogicalName $wdx_setting_LogicalName -WDXAPI_Value $WDXAPI_Value -WDXPORTAL_Value $WDXPORTAL_Value # **** Change Path **** #
"#### Functions loaded from framework ####" | Out-File -FilePath $path -Append
Write-Host "envname = $EnvName" -BackgroundColor DarkRed 
try{
"#### Package extraction started ####" | Out-File -FilePath $path -Append
if($($site) -eq "FLW"){
    if(!(Test-Path -Path "\\$BE_Server\WDX_temp\WDX_TEMP_Package\UFWDeployment\packages\$selectedpackage")){
        Write-Host "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') Extraction of the package started selectedpackage"
        "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') Extraction of the package started $selectedpackage " | Out-File -FilePath $path -Append
        Expand-Archive -Path "\\$BE_Server\WDX_temp\WDX_TEMP_Package\UFWDeployment\Packages\$selectedpackage.zip" -DestinationPath "\\$BE_Server\WDX_temp\WDX_TEMP_Package\UFWDeployment\packages\$selectedpackage" -ErrorAction Stop
        Write-Host "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') Extraction done" -ForegroundColor Green
        "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') Extraction done" | Out-File -FilePath $path -Append
    }
    else{
        Write-Host "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') Package extracted already $selectedpackage" -ForegroundColor Green
        "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') Package extracted already $selectedpackage" | Out-File -FilePath $path -Append
    }
    "#### Package extraction completed ####" | Out-File -FilePath $path -Append
}
else{
    if(!(Test-Path -Path "\\$BE_Server\WDX_temp\WDX_TEMP_Package\$($site)Deployment\packages\$selectedpackage")){
        Write-Host "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') Extraction of the package started selectedpackage"
        "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') Extraction of the package started $selectedpackage " | Out-File -FilePath $path -Append
        Expand-Archive -Path "\\$BE_Server\WDX_temp\WDX_TEMP_Package\$($site)Deployment\Packages\$selectedpackage.zip" -DestinationPath "\\$BE_Server\WDX_temp\WDX_TEMP_Package\$($site)Deployment\packages\$selectedpackage" -ErrorAction Stop
        Write-Host "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') Extraction done" -ForegroundColor Green
        "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') Extraction done" | Out-File -FilePath $path -Append
    }
    else{
        Write-Host "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') Package extracted already $selectedpackage" -ForegroundColor Green
        "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') Package extracted already $selectedpackage" | Out-File -FilePath $path -Append
    }
        "#### Package extraction completed ####" | Out-File -FilePath $path -Append
}
}
catch{
    Write-Host "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') Extraction of the package failed... Stopping the deployment Error: $($_)" -ForegroundColor Red
    "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') Extraction of the package failed... Stopping the deployment Error: $($_)" | Out-File -FilePath $path -Append
"#### Package extraction not completed ####" | Out-File -FilePath $path -Append
    Exit;
}

#Run Sql query
if($Operation.Contains("1. Run SQL Query")){
    if(($query_order -eq "Before Deployment") -and ($Operation.Contains("5. Start Deployment"))){
    "#### Running SQL Query operation started ####" | Out-File -FilePath $path -Append
        $RunSQLQuery = Run_SqlScript -ENVName $EnvName -DBName $DBName -ServerInstance $ServerInstance -query $query
        $RunSQLQuery | Out-File -FilePath $path -Append
        $RunSQLQuery
    "#### Running SQL Query operation ended ####" | Out-File -FilePath $path -Append
     }
    elseif (($query_order -eq "After Deployment") -and ($Operation.Contains("5. Start Deployment"))) {
        
    }
    else
    {
    "#### Running SQL Query operation started ####" | Out-File -FilePath $path -Append
        $RunSQLQuery = Run_SqlScript -ENVName $EnvName -DBName $DBName -ServerInstance $ServerInstance -query $query
        $RunSQLQuery | Out-File -FilePath $path -Append
        $RunSQLQuery
    "#### Running SQL Query operation ended ####" | Out-File -FilePath $path -Append

    }

}

#Binaries of Backup
if($Operation.Contains("2. Binaries Backup")){
"#### Binaries Backup operation started ####" | Out-File -FilePath $path -Append
$binarybackup = Invoke-Command -Session $FE_Session `
-ScriptBlock ${Function:Binaries_Backup} `
-ArgumentList $EnvName
$binarybackup | Out-File -FilePath $path -Append
$binarybackup
"#### Binaries Backup operation ended ####" | Out-File -FilePath $path -Append
}

#Set Maintenance Page
if($Operation.Contains("3. Set Maintenance page")){
"#### Set Maintenance page operation started ####" | Out-File -FilePath $path -Append
$set_maintenancepage = Invoke-Command -Session $FE_Session `
-ScriptBlock ${Function:Set-MaintenancePage} `
-ArgumentList $EnvName
$set_maintenancepage | Out-File -FilePath $path -Append
$set_maintenancepage
"#### Set Maintenance page operation ended ####" | Out-File -FilePath $path -Append
}

#Stop IIS services
if($Operation.Contains("4. Stop IIS Services")){
"#### Stop IIS Services operation started ####" | Out-File -FilePath $path -Append
$stop_services = Invoke-Command -Session $FE_Session `
-ScriptBlock ${function:Stop-IISservices} `
-ArgumentList $EnvName,$API,$Portal
$stop_services | Out-File -FilePath $path -Append
$stop_services
"#### Stop IIS Services operation ended ####" | Out-File -FilePath $path -Append

}
#Invoke-Command -Session $FE_Session -FilePath "E:\WDX_Automation\Scripts\anusha\Deployment script\functions.ps1" -ArgumentList $EnvName,$API,$Portal,$Path

<#
# Deployment starts at this step
if($Operation.Contains("5. Start Deployment")){
"#### Start Deployment operation started ####" | Out-File -FilePath $path -Append
Write-Host "Deployment starting..."
"$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Deployment starting..." | Out-File -FilePath $path -Append
$Password = ConvertTo-SecureString ("RUZjfswe76428/hkoas5") -AsPlainText -Force
$UserName = "ADCHPBK\ct884"
$Cred = New-Object System.Management.Automation.PSCredential ($UserName, $Password)

$session = New-PSSession -ComputerName $BE_Server -Credential $BE_Cred


#Invoke-Command -Session $session -ScriptBlock { cd "$Packageloc"} 
#Invoke-Command -Session $session -ScriptBlock {New-Item -ItemType Directory "\\swdxve1041ubp\e$\WDX\WDXFLW-SIM\API" -Force | Out-Null } 

$deploy_output = Invoke-Command -Session $session -ScriptBlock {
    $output += " *** tracking parameters $Packageloc, $Deploymenttype ***"

    try{
    $Password = ConvertTo-SecureString ("RUZjfswe76428/hkoas5") -AsPlainText -Force
    $UserName = "ADCHPBK\ct884"
    $Cred = New-Object System.Management.Automation.PSCredential ($UserName, $Password)

#Maping the Drives

    $driveletter = "Z" # **** Change Path **** #
    $sharedfolder = "\\SWDXVE1041UBP\E$" # **** Change Path **** #
    New-PSDrive -Name $driveletter -Root $sharedfolder -PSProvider FileSystem -Credential $Cred

    $output = @()
    $Packageloc = $using:Packageloc
    $Deploymenttype = $using:Deploymenttype
    Set-Location -Path "E:\$Packageloc"
    & "E:\$Packageloc\Run.cmd" -deploymentType "$Deploymenttype" 
    #. "Run.cmd" -deploymentType "$Deploymenttype" 
    Write-Host "Deploymenttype: $Deploymenttype"
    Write-Host "Deployment done" -ForegroundColor Green 
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Deployment done $($_)" 
    }
    catch{
    Write-Host "An error occured while performing deployment" -ForegroundColor Red
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') ERROR: An error occured while performing deployment $($_)"
    }
    Remove-PSDrive -Name $driveletter
    return $output
    }  #Select the deployment type here. 
$deploy_output | Out-File -FilePath $Path -Append
$deploy_output
#Enter-PSSession -Session $session

#Exit-PSSession

# Deployment Ends
"#### Start Deployment operation ended ####" | Out-File -FilePath $path -Append
}#>



#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

# Deployment starts at this step
if($Operation.Contains("5. Start Deployment")){
    "#### Start Deployment operation started ####" | Out-File -FilePath $path -Append
    Write-Host "Deployment starting..."
    "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Deployment starting..." | Out-File -FilePath $path -Append
    $Password = ConvertTo-SecureString ("$Service_Password") -AsPlainText -Force
    $UserName = "$Service_UserName"
    $Cred = New-Object System.Management.Automation.PSCredential ($UserName, $Password)
    
    $session = New-PSSession -ComputerName $BE_Server -Credential $BE_Cred
    
    
    #Invoke-Command -Session $session -ScriptBlock { cd "$Packageloc"} 
    #Invoke-Command -Session $session -ScriptBlock {New-Item -ItemType Directory "\\swdxve1041ubp\e$\WDX\WDXFLW-SIM\API" -Force | Out-Null } 
    
    $deploy_output = Invoke-Command -Session $session -ScriptBlock {
        $output += " *** tracking parameters Packageloc: $Packageloc, Deploymenttype: $Deploymenttype ***"
    
        try{
    
        $Password = ConvertTo-SecureString ("RUZjfswe76428/hkoas5") -AsPlainText -Force
        $UserName = "ADCHPBK\CT884"
        $Cred = New-Object System.Management.Automation.PSCredential ($UserName, $Password)
    
    #Maping the Drives
    
        $driveletter = "Z" # **** Change Path **** #
        $sharedfolder = "\\SWDXVE1041UBP\E$" # **** Change Path **** #
        New-PSDrive -Name $driveletter -Root $sharedfolder -PSProvider FileSystem -Credential $Cred
    
        $output = @()
        $Packageloc = $using:Packageloc
        $Deploymenttype = $using:Deploymenttype
        $output += " *** tracking parameters $Packageloc, $Deploymenttype *** --> 2"
    
        Set-Location -Path "E:\$Packageloc"
        & "E:\$Packageloc\Run.cmd" -deploymentType "$Deploymenttype" 
        #. "Run.cmd" -deploymentType "$Deploymenttype" 
        Write-Host "Deploymenttype: $Deploymenttype"
        Write-Host "Deployment done" -ForegroundColor Green 
        $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Deployment done $($_)" 
        }
        catch{
            $Packageloc = $using:Packageloc
            $Deploymenttype = $using:Deploymenttype
            $output += " *** tracking parameters $Packageloc, $Deploymenttype *** --> 2"
        
        Write-Host "An error occured while performing deployment" -ForegroundColor Red
        $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') ERROR: An error occured while performing deployment $($_)"
        }
        Remove-PSDrive -Name $driveletter
        return $output
        }  #Select the deployment type here. 
    $deploy_output | Out-File -FilePath $Path -Append
    $deploy_output
    #Enter-PSSession -Session $session
    
    #Exit-PSSession
    
    # Deployment Ends
    "#### Start Deployment operation ended ####" | Out-File -FilePath $path -Append
    }
    



#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++






#Run Sql query
if($Operation.Contains("1. Run SQL Query")){
    if(($query_order -eq "After Deployment") -and ($Operation.Contains("5. Start Deployment"))){
        "#### Run SQL Query operation started ####" | Out-File -FilePath $path -Append
        $RunSQLQuery = Run_SqlScript -ENVName $EnvName -DBName $DBName -ServerInstance $ServerInstance -query $query
        $RunSQLQuery | Out-File -FilePath $path -Append
        $RunSQLQuery
        "#### Run SQL Query operation ended ####" | Out-File -FilePath $path -Append
     }
}

#Remove Binary Files
if($Operation.Contains("6. Remove Binaries")){
"#### Remove Binaries operation started ####" | Out-File -FilePath $path -Append
$RemoveFiles = Invoke-Command -Session $FE_Session `
-ScriptBlock ${Function:Remove-Files} `
-ArgumentList $EnvName
$RemoveFiles | Out-File -FilePath $path -Append
$RemoveFiles
"#### Remove Binaries operation ended ####" | Out-File -FilePath $path -Append
}

#Copy Binary Files
if($Operation.Contains("7. Copy Binaries")){
<#$CopyFiles = Invoke-Command -Session $FE_Session `
-ScriptBlock ${Function:Copy-Files1} `
-ArgumentList $EnvName,$BE_Server,$Packageloc,$SelectedPackage,$FE_Server
#>
"#### Copy Binaries operation started ####" | Out-File -FilePath $path -Append
$CopyFiles = Copy-Files1 -ENVName $EnvName -BE_Server $BE_Server -Packageloc $Packageloc -FE_Server $FE_Server
$CopyFiles | Out-File -FilePath $path -Append
$CopyFiles
"#### Copy Binaries operation ended ####" | Out-File -FilePath $path -Append
}

##Start-IISservices
if($Operation.Contains("8. Start IIS Services")){
"#### Start IIS Services operation started ####" | Out-File -FilePath $path -Append
$StartIISservices = Invoke-Command -Session $FE_Session `
-ScriptBlock ${Function:Start-IISservices} `
-ArgumentList $EnvName,$API,$Portal
$StartIISservices | Out-File -FilePath $path -Append
$StartIISservices
"#### Start IIS Services operation ended ####" | Out-File -FilePath $path -Append
}

#add bg services restart
if($Operation.Contains("9. Restart BG Services")){
"#### Restart BG Services operation started ####" | Out-File -FilePath $path -Append
$RestartBGService = Invoke-Command -Session $BE_Session `
-ScriptBlock ${Function:RestartBGService} `
-ArgumentList (,$RestartServiceNames)
$RestartBGService | Out-File -FilePath $path -Append
$RestartBGService
"#### Restart BG Services operation ended ####" | Out-File -FilePath $path -Append
}

#Remove-MaintenancePage
if($Operation.Contains("10. Remove Maintenance")){
"#### Remove Maintenance operation started ####" | Out-File -FilePath $path -Append
    $RemoveMaintenancePage = Invoke-Command -Session $FE_Session `
    -ScriptBlock ${Function:Remove-MaintenancePage} `
    -ArgumentList $EnvName
    $RemoveMaintenancePage | Out-File -FilePath $path -Append
    $RemoveMaintenancePage
    "#### Remove Maintenance operation ended ####" | Out-File -FilePath $path -Append
    }
#CRM Operations
#DataEncryptionKey
if($crmoperation.Contains("1. Set DataEncryption Key")){
    "#### DataEncryptionKey operation started ####" | Out-File -FilePath $path -Append
    $DataEncryptionKey = Invoke-Command -Session $UBP_session `
    -ScriptBlock ${Function:DataEncryptionKey} `
    -ArgumentList $ServerURL,$CRM_UserName,$CRM_Password,$OrgName,$EncryptionKey
    $DataEncryptionKey | Out-File -FilePath $path -Append
    $DataEncryptionKey
    <#$DataEncryptionKey = DataEncryptionKey –ServerUrl $ServerURL -CRM_UserName $CRM_UserName -CRM_Password $CRM_Password -Orgname $OrgName -EncryptionKey $EncryptionKey
    $DataEncryptionKey | Out-File -FilePath $path -Append
    $DataEncryptionKey#>
    "#### DataEncryptionKey operation ended ####" | Out-File -FilePath $path -Append
    }
    
    # Get-APIPORTALValue
    if($crmoperation.Contains("2. Get WDX API & PORTAL Value")){
    
    "#### Get API PORTAL Value operation started ####" | Out-File -FilePath $path -Append
    $Get_APIPORTALValue = Invoke-Command -Session $UBP_session `
    -ScriptBlock ${Function:Get-APIPORTALValue} `
    -ArgumentList $ServerURL,$CRM_UserName,$CRM_Password,$OrgName,$wdx_setting_LogicalName
    $Get_APIPORTALValue | Out-File -FilePath $path -Append
    $Get_APIPORTALValue
    <#$Get_APIPORTALValue = Get-APIPORTALValue –ServerUrl $ServerURL -Credential $CRM_Cred -OrganizationName $OrgName -wdx_setting_LogicalName $wdx_setting_LogicalName
    $Get_APIPORTALValue | Out-File -FilePath $path -Appends
    $Get_APIPORTALValue#>
    "#### Get API PORTAL Value operation ended ####" | Out-File -FilePath $path -Append
    }
    
    # DisablePlugin
    if($crmoperation.Contains("3. Disable Plugin")){
    "#### DisablePlugin operation started ####" | Out-File -FilePath $path -Append
    $DisablePlugin = Invoke-Command -Session $UBP_session `
    -ScriptBlock ${Function:DisablePlugin} `
    -ArgumentList $ServerURL,$CRM_UserName,$CRM_Password,$OrgName
    $DisablePlugin | Out-File -FilePath $path -Append
    $DisablePlugin
    <#$DisablePlugin = DisablePlugin –ServerUrl $ServerURL -Credential $CRM_Cred -OrganizationName $OrgName
    $DisablePlugin | Out-File -FilePath $path -Append
    $DisablePlugin #>
    "#### DisablePlugin operation ended ####" | Out-File -FilePath $path -Append
    }
    
    # Set-APIPORTALValue
    if($crmoperation.Contains("4. Set WDX API & PORTAL Value")){
    "#### Set API PORTAL Value operation started ####" | Out-File -FilePath $path -Append
    $setapiportal = Invoke-Command -Session $UBP_session `
    -ScriptBlock ${Function:Set-APIPORTALValue} `
    -ArgumentList $ServerURL,$CRM_UserName,$CRM_Password,$OrgName,$wdx_setting_LogicalName,$WDXAPI_Value,$WDXPORTAL_Value
    $setapiportal | Out-File -FilePath $path -Append
    $setapiportal
    <#$setapiportal = Set-APIPORTALValue –ServerUrl $ServerURL -Credential $CRM_Cred -OrganizationName $OrgName -wdx_setting_LogicalName $wdx_setting_LogicalName -WDXAPI_Value $WDXAPI_Value -WDXPORTAL_Value $WDXPORTAL_Value
    $setapiportal | Out-File -FilePath $path -Append
    $setapiportal#>
    "#### Set API PORTAL Value operation ended ####" | Out-File -FilePath $path -Append
    }
    
    # Set-wdx_setting_Value
    if($crmoperation.Contains("5. Set S2i Integration setting Value")){
    "#### Setting S2IIntegrationSetting Value ####" | Out-File -FilePath $path -Append
    #$s2i_integration_setting | Out-File -FilePath $path -Append
    $wdx_value,$setwdxxsetting = Invoke-Command -Session $UBP_session `
    -ScriptBlock ${Function:Set-wdx_setting_Value} `
    -ArgumentList $ServerURL,$CRM_UserName,$CRM_Password,$OrgName,$wdx_setting_LogicalName,$s2i_integration_setting
    $wdX_value | Out-File -FilePath "E:\WDX\Deployment_application\UBP\Backup\S2IIntegrationsettings_$($Deploymentsite).Json"
    $setwdxxsetting | Out-File -FilePath $path -Append
    $setwdxxsetting
    <#$setwdxxsetting = Set-wdx_setting_Value –ServerUrl $ServerURL -Credential $CRM_Cred -OrganizationName $OrgName -wdx_setting_LogicalName $wdx_setting_LogicalName 
    $setwdxxsetting | Out-File -FilePath $path -Append
    $setwdxxsetting#>
    "#### S2IIntegrationSetting Value has been set ####" | Out-File -FilePath $path -Append
    }
    
    # EnablePlugin
    if($crmoperation.Contains("6. Enable Plugin")){
    "####  EnablePlugin operation started ####" | Out-File -FilePath $path -Append
    $EnablePlugin = Invoke-Command -Session $UBP_session `
    -ScriptBlock ${Function:EnablePlugin} `
    -ArgumentList $ServerURL,$CRM_UserName,$CRM_Password,$OrgName
    $EnablePlugin | Out-File -FilePath $path -Append
    $EnablePlugin
    <#$EnablePlugin = EnablePlugin –ServerUrl $ServerURL -Credential $CRM_Cred -OrganizationName $OrgName  
    $EnablePlugin | Out-File -FilePath $path -Append
    $EnablePlugin#>
    "#### EnablePlugin operation ended ####" | Out-File -FilePath $path -Append
    }
    
    #update CRM version
    if($crmoperation.Contains("7. Update CRM Version")){
    "#### Update CRM Version operation started ####" | Out-File -FilePath $path -Append
    "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') Getting CRM version from the package operation started" | Out-File -FilePath $path -Append
    $getcrmoutput,$getcrmversion = get-version -packageloc $packageloc 
    $getcrmoutput,$getcrmversion | Out-File -FilePath $path -Append
    $getcrmoutput,$getcrmversion
    "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') Getting CRM version from the package operation ended" | Out-File -FilePath $path -Append
    
    "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') Updating CRM version operation started" | Out-File -FilePath $path -Append
    $updatecrmversion = update-version -version $getcrmversion -Env $EnvName -IWMSite $site
    $updatecrmversion | Out-File -FilePath $path -Append
    $updatecrmversion
    "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') Updating CRM version operation ended" | Out-File -FilePath $path -Append
    
    "#### Update CRM Version operation ended ####" | Out-File -FilePath $path -Append
    }    

    "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') All selected options are executed successfully" | Out-File -FilePath $path -Append
    "#### Deployment Application log ended ####" | Out-File -FilePath $path -Append
}
catch{
    "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') An error occured $($_)" | Out-File -FilePath $path -Append
    "#### Deployment Application log ended ####" | Out-File -FilePath $path -Append
}
