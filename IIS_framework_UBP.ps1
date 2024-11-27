##########################################################################
# Script Purpose: Framework - holds all functions
# Site: UBP - Sites
# Author: Rohith Vignesh
# Date: 14/03/2024
##########################################################################

param(
        $Module,
[String]$ENVName,
[String]$FolderPath,
        $IISFeatures,
        $WindowsFeatures,
        $EncryptData,
        $plaintext,
        $NewPoolUsername,
        $NewPoolPassword,
        $API,
        $Portal,
        $ConfigFilePath,
[String]$BE_FolderPath,
        $CRM_Password,
        $CRM_UserName,
        $CRM_Cred,
        $wdx_setting_LogicalName,
        $OrgName,
        $ServerURL,
        $WDXAPI_Value,
        $WDXPORTAL_Value,
        $EncryptionKey,
        $RestartServiceNames,
        $APICopyFile_Source,
        $APICopyFile_Destination,
        $PortalCopyFile_Source,
        $PortalCopyFile_Destination,
        $APICustomAssembliesCopyFile_Source,
        $APICustomAssembliesCopyFile_Destination,
        $Packageloc,
        $Service_UserName,
        $Service_Password,
        $FE_Server,
        $BE_Server
)

#Variables

    #$API = "API$ENVName"
    #$Portal = "PORTAL$ENVName"
    $RootFolderPath = "\\SWDXVE1041UBP\e$\WDX"
    #$SubFolderPaths = @("$FolderPath\WDX_Sites\$ENVName\Binaries\API","$FolderPath\WDX_Sites\$ENVName\Binaries\Portal","$FolderPath\WDX_Sites\$ENVName\Binaries\APICustomAssemblies")
    



#Import the Required Module

Function ImportModule()
{
    $output = @()
    try{
    Write-Host "Importing module..."
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Importing module..."
    Import-Module $Module
    Write-Host "Module import done." -ForegroundColor Green
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Importing module..."
    }
    Catch{
    Write-Host "There was an error during importing the module" -ForegroundColor Red
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') ERROR: There was an error during importing the module.$($_)"
    }
    return $output
}

#Remove the Required Module

Function RemoveModule()
{
    $output = @()
    try{
    Write-Host "Removing module..."
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Removing module..."
    Remove-Module $Module
    Write-Host "Module removed." -ForegroundColor Green
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Module removed."
        }
    Catch{
    Write-Host "There was an error during removing the module" -ForegroundColor Red
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') ERROR: There was an error during removing the module.$($_)"
    }
    return $output
}


#Install Windows feature

function InstallWindowsFeature(){
    $output = @()
    Try{
    Write-Host "Installing Windows Features..."
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Installing Windows Features..."
    # IIS Features 
    #$IISFeatures = @("IIS-WebServerRole", "IIS-WebServer", "iis-commonhttpfeatures", "IIS-DefaultDocument", "IIS-DirectoryBrowsing ", "IIS-HttpErrors", "IIS-StaticContent","IIS-HealthAndDiagnostics", "IIS-HttpLogging", "iis-HttpTracing", "iis-Performance","IIS-HttpCompressionDynamic", "IIS-HttpCompressionStatic" ,"iis-Security","IIS-RequestFiltering","IIS-WindowsAuthentication","IIS-ApplicationDevelopment","IIS-ISAPIExtensions","IIS-ISAPIFilter", "IIS-WebServerManagementTools","IIS-ManagementConsole", "IIS-IIS6ManagementCompatibility", "IIS-Metabase" , "IIS-ManagementScriptingTools")
    #$IISFeatures01 = @("NetFx4Extended-ASPNET45","IIS-ApplicationDevelopment","IIS-NetFxExtensibility","IIS-NetFxExtensibility45","iis-AspNet45")

    #Install IIS features
    Enable-WindowsOptionalFeature -Online -FeatureName $IISFeatures
    Add-WindowsFeature $WindowsFeatures

    Write-Host "Windows Features installation done." -ForegroundColor Green
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Windows Features installation done."
    }
    catch
    {
    Write-Host "There was an error during Windows Features installation." -ForegroundColor Red
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') ERROR: There was an error during Windows Features installation.$($_)"
    }
    return $output
}

function Encrypt-Data() {

    ConvertTo-SecureString $EncryptData -AsPlainText -Force

}

function Decrypt-Data() {

    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($CRM_Password)
    $plaintext = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
}

Function Run_SqlScript(){
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)] 
        $EnvName,
        [Parameter(Position = 1)] 
        $DBName,
        [Parameter(Position = 2)] 
        $ServerInstance,
        [Parameter(Position = 3)] 
        $query
    )
    $output = @()
    Try{
        Write-Host "Executing the query on the database - $DBName $($_)"
        $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Executing the query on the database - $DBName"
        
        $output += Invoke-Sqlcmd -ServerInstance $ServerInstance -Database $DBName -Query $query -AbortOnError -Encrypt Optional -ErrorAction Stop -WarningAction SilentlyContinue

        Write-Host "Query ran successfully against the database - $DBName $($_)"
        $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Query ran successfully against the database - $DBName $($_)"
    }
    catch{
        Write-Host "An error occured when running the query" -ForegroundColor Red
        $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: An error occured when running the query $($_)"
    }
    return $output
}


Function Binaries_Backup(){
# Function to take Binaries bakup
        
        [CmdletBinding()]
    Param (
        [Parameter(Position = 0)] 
        $EnvName
        
    )
    $output = @()
    Try{
        Write-Host "$ENVName" -BackgroundColor DarkYellow
   
    Write-Host "Taking backup of the binaries from site $ENVName"
    Get-ChildItem -Path "E:\WDX\WDX$ENVName" | Copy-Item -Destination "E:\Binaries_Backup\WDX$ENVName\" -Recurse -Container
    
    Write-Host "Binaries are backedup" -ForegroundColor Green
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Binaries are backedup $($_)"
    }
    catch
    {
    Write-Host "An error during taking backup of the binaries..." -ForegroundColor Red
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') ERROR: An error during taking backup of the binaries...$($_)"
    }
    return $output
}

Function Check-FolderStructure{
    $output = @()
    Try {
# Check if the E:\WDX - Root folder exists and create sub folders under it.
    Write-Host "Checking Folder strucutre"
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Checking Folder strucutre."
    if (Test-Path  "$RootFolderPath" -PathType Container){
        if (Test-Path  "$RootFolderPath\$ENVName" -PathType Container){}
        else{Write-Host "Folders Do Not Exist For $ENVName Under E:\WDX"
        $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Folders Do Not Exist For $ENVName Under E:\WDX"
        Write-Host "Creating The Necessary Folders Under E:\WDX For $ENVName"
        $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Creating The Necessary Folders Under E:\WDX For $ENVName"
        New-Item "$RootFolderPath" -Name "$ENVName" -Type Directory -ErrorAction SilentlyContinue
        New-Item "$RootFolderPath\$ENVName" -Name "API" -Type Directory -ErrorAction SilentlyContinue
        New-Item "$RootFolderPath\$ENVName" -Name "APICustomAssemblies" -Type Directory -ErrorAction SilentlyContinue
        New-Item "$RootFolderPath\$ENVName" -Name "PORTAL" -Type Directory -ErrorAction SilentlyContinue
        New-Item "$RootFolderPath\$ENVName\PORTAL" -Name "Assets" -Type Directory -ErrorAction SilentlyContinue
        Write-Host "Necessary Folders created Under E:\WDX for $ENVName"
        $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Necessary Folders created Under E:\WDX for $ENVName"
        }
            }
    Write-Host "Folder Strucutre Check Completed." -ForegroundColor Green
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Folder Strucutre Check Completed."
    }
    catch
    {
    Write-Host "There was an error during creating folder structure." -ForegroundColor Red
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') ERROR: There was an error during creating folder structure.$($_)" 
    }
    return $output
}


function Create-Folder{

    $output = @()
    try
    {    
        if (-not (Test-Path  "$RootFolderPath\$ENVName" -PathType Container))
        {
#This loop executes for new folder creation
            Write-Host "Creating $ENVName Folder..."
            $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Creating $ENVName Folder..."
            New-Item $RootFolderPath -Name $ENVName -Type Directory -ErrorAction SilentlyContinue
            Write-Host "Folder created." -ForegroundColor Green
            $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Folder created."
        }
        else
        {
            Write-Host "$RootFolderPath already exist"
            $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: $RootFolderPath already exist"
        }
    }
    Catch
    {
    Write-Host "There was an error. Please check your input in the Json file" -ForegroundColor Red
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') ERROR: There was an error. Please check your input in the Json file. $($_)"
    }

    if(-not (Test-Path "$RootFolderPath\$ENVName" -PathType Container))
    {

    }
    else{
    Write-Host "Checking Subfolders..."
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Checking Subfolders..."
    New-Item "$RootFolderPath\$ENVName" -Name "API" -ItemType Directory -ErrorAction SilentlyContinue
    New-Item "$RootFolderPath\$ENVName" -Name "APICustomAssemblies" -ItemType Directory -ErrorAction SilentlyContinue
    New-Item "$RootFolderPath\$ENVName" -Name "Portal" -ItemType Directory -ErrorAction SilentlyContinue
    New-Item "$RootFolderPath\$ENVName\Portal" -Name "Assets" -ItemType Directory -ErrorAction SilentlyContinue
    }
    return $output
} 


Function CreateAppPoolandIISSite() {
    
    $output = @()
    # Creating new apppool
    $Availableapppools = Get-IISAppPool | select name
    foreach($Availableapppool in $Availableapppools)
    {
        if($Availableapppool.Name -eq $ENVName)
        {
        Write-Host "This environment exist in app pool" -ForegroundColor Red
        $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') WARNING: This environment exist in app pool"
        #exit; # skip and continue
        }
    }
        
        
        #Write-Host "Creating App pool..."
        New-WebAppPool -Name $ENVName -Force -ErrorAction SilentlyContinue
        New-WebAppPool -Name $API -Force -ErrorAction SilentlyContinue
        New-WebAppPool -Name $Portal -Force -ErrorAction SilentlyContinue
        #Write-Host "App pool created" -ForegroundColor Green
        
        

    # Create New IIS Site
    
    $hostname = [Environment]::MachineName+".ch.pbk"
    $bindings=  @{protocol="https";bindingInformation=":"+"443"+":" + $hostname}
    $IISModule = Get-Module IISAdministration
        if($IISModule -ne $null)
        {
        Remove-Module IISAdministration
        }
    try{
    New-IISSite -Name "$ENVName" -PhysicalPath "$RootFolderPath\$ENVName" -BindingInformation "*:443:" -ErrorAction SilentlyContinue
    }
    Catch{
    Write-Host "Web site '$ENVName' already exists." -ForegroundColor Red
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') ERROR: Web site '$ENVName' already exists. $($_)"
    }
    #New-IISSite -Name "TestSite" -PhysicalPath "E:\WDX\Test" -BindingInformation "*:443:" -CertificateThumbPrint "‎19b92ced275dd850f540af069dc3b67b9849b539" -CertStoreLocation "Cert:\LocalMachine\Certificates" -Protocol https
    try{
    New-WebBinding -Name $ENVName -Protocol https -Port 443 -HostHeader $hostname -ErrorAction SilentlyContinue
    }
    catch{
    Write-Host "Cannot add duplicate collection entry of type 'binding'." -ForegroundColor Red
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') ERROR: Cannot add duplicate collection entry of type 'binding'. $($_)"
    }
    return $output
}

Function SetAPPPoolIdentity(){
    $output = @()
    Try{
    Write-Host "Setting $ENVName Pool Identity to $NewPoolUsername..."
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Setting $ENVName Pool Identity to $NewPoolUsername..."
    $NewPool = Get-Item IIS:\AppPools\$ENVName
    $NewPool.ProcessModel.Username = $NewPoolUsername
    $NewPool.ProcessModel.Password = $NewPoolPassword
    $NewPool.ProcessModel.IdentityType = 3
    $NewPool.ProcessModel.loadUserProfile = "True"
    $NewPool.processModel.idleTimeout = "0"
    $NewPool | Set-Item

    $AIPPool = Get-Item IIS:\AppPools\$API
    $AIPPool.ProcessModel.Username = $NewPoolUsername
    $AIPPool.ProcessModel.Password = $NewPoolPassword
    $AIPPool.ProcessModel.IdentityType = 3
    $AIPPool.ProcessModel.loadUserProfile = "True"
    $AIPPool.processModel.idleTimeout = "0"
    $AIPPool | Set-Item

    $PortalPool = Get-Item IIS:\AppPools\$Portal
    $PortalPool.ProcessModel.Username = $NewPoolUsername
    $PortalPool.ProcessModel.Password = $NewPoolPassword
    $PortalPool.ProcessModel.IdentityType = 3
    $PortalPool.ProcessModel.loadUserProfile = "True"
    $PortalPool.processModel.idleTimeout = "0"
    $PortalPool | Set-Item

    Write-Host "Setting $ENVName pool identity to $NewPoolUsername done" -ForegroundColor Green;
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Setting $ENVName pool identity to $NewPoolUsername done"
    #Set regular time interval to 0

    Set-WebConfiguration `/system.applicationHost/applicationPools/applicationPoolDefaults/recycling/periodicRestart ` -value "0"
    }
    catch
    {
    Write-Host "There was an error occured during setting $ENVName pool identity to $NewPoolUsername" -ForegroundColor Red
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') ERROR: There was an error occured during setting $ENVName pool identity to $NewPoolUsername $($_)"
    }
    return $output
    }


Function CertBinding(){
    $output = @()
    Try{
    # Cert Binding

    #Import-PfxCertificate –FilePath E:\scripts\wildcard.pfx cert:\localMachine\Personal\Certificates -Password (ConvertTo-SecureString -String "0p3nss1" -Force –AsPlainText) 
    Write-Host "Binding certificate..."
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Binding certificate..."
    $AllCert = Get-ChildItem -path Cert:\LocalMachine\My
    $Cert = $AllCert | where thumbprint -Like "19b9*"
    $Expiry_from = $Cert.NotBefore
    $Expiry_to = $Cert.NotAfter
    $binding = Get-WebBinding -Name "$ENVName" -Protocol "https"
    $binding.AddSslCertificate($Cert.GetCertHashString(), "my")
    Write-Host "Binding certificate Done" -ForegroundColor Green
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Binding certificate Done"
    Write-Host "Certificate expiry from $Expiry_from to $Expiry_to" -ForegroundColor White
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Certificate expiry from $Expiry_from to $Expiry_to"
    }
    catch
    {
    Write-Host "There was an error occured during binding certificate..." -ForegroundColor Red
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') ERROR: There was an error occured during binding certificate... $($_)"
    }
    return $output
}

Function ConvertFoldertoApplication(){
    $output = @()
    Try{
    Write-Host "Converting API and Portal to a webapplication"
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Converting API and Portal to a webapplication"
    # Converting API and Portal to a webapplication

    New-WebApplication -name "API" -Site $ENVName -PhysicalPath "$RootFolderPath\$ENVName\API" -ApplicationPool $ENVName -Force 
    New-WebApplication -name "Portal" -Site $ENVName -PhysicalPath "$RootFolderPath\$ENVName\Portal" -ApplicationPool $ENVName -Force

    # Setting up application for the Application pool

    Set-ItemProperty "IIS:\Sites\$ENVName" -name applicationPool -value $ENVName
    Set-ItemProperty "IIS:\Sites\$ENVName\API" -name applicationPool -value $API
    Set-ItemProperty "IIS:\Sites\$ENVName\Portal" -name applicationPool -value $Portal

    Write-Host "Conversion done" -ForegroundColor Green
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Conversion done"
    }
    catch
    {
    Write-Host "There was an error occured during converting API and Portal to a webapplication" -ForegroundColor Red
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') ERROR: There was an error occured during converting API and Portal to a webapplication $($_)"
    }
    return $output
}

Function SetAuthentication(){
    $output = @()
    Try{
    Write-Host "Setting authentication..."
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Setting authentication..."
    #Set-IISConfigAttributeValue -ConfigElement $ConfigSection -AttributeName "useAppPoolCredentials" -AttributeValue "True"

    # Set Windows Authentication to enabled and set Provider to Negotiate

    #Set-WebConfiguration system.webServer/security/authentication/anonymousAuthentication -PSPath IIS:\ -Location $ENVName -Value @{enabled="True"}
    Set-WebConfiguration system.webServer/security/authentication/windowsAuthentication -PSPath IIS:\ -Location $ENVName -Value @{enabled="True"}

    # [Portal] Set Windows Authentication to Disabled and anonymous Authentication to Enabled

    Set-WebConfiguration system.webServer/security/authentication/windowsAuthentication -PSPath IIS:\ -Location "$ENVName/portal" -Value @{enabled="False"}
    Set-WebConfiguration system.webServer/security/authentication/anonymousAuthentication -PSPath IIS:\ -Location "$ENVName/portal" -Value @{enabled="true"}

    Set-WebConfiguration system.webServer/security/authentication/windowsAuthentication -PSPath IIS:\ -Location $ENVName -Value @{useAppPoolCredentials="True"}

    Remove-WebConfigurationProperty -PSPath IIS:\ -Location $ENVName -filter system.webServer/security/authentication/windowsAuthentication/providers -name "."
    Add-WebConfiguration -Filter system.webServer/security/authentication/windowsAuthentication/providers -PSPath IIS:\ -Location $ENVName -Value Negotiate

    Write-Host "Authentication setup done" -ForegroundColor Green
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Authentication setup done"
    }
    catch
    {
    Write-Host "There was an error occured during setting authentication..." -ForegroundColor Red
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') ERROR: There was an error occured during setting authentication... $($_)"
    }
    return $output
}


##################################################################################################

#Edit Config.json file

Function EditConfig{
    $output = @()
    Try{
    #Get Secret

    $ConfigFilePath = Get-Content "$FolderPath\WDX_Sites\$ENVName\WDX_Config_Files\config_json.json" | ConvertFrom-Json

    if (-not (Test-Path  "$FolderPath\WDX_Sites\$ENVName\Binaries\Portal\Assets\config.json")){
        Write-Host "Config.json file does not exist" -ForegroundColor Red
        $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') WARNING: Config.json file does not exist"
        Exit;
    }
    else{
        $ConfigJson = Get-Content "$FolderPath\WDX_Sites\$ENVName\Binaries\Portal\Assets\config.json" | ConvertFrom-Json

#Edit Config.json file

        $Name = $ENVName.Remove(0,3).ToLower()
        $API_BASE = "https://wdx$Name.ch.pbk/API/"
        $CRM_URL = "https://crm$Name.ch.pbk/main.aspx?"
        $AuthenticationClientId = $ConfigFilePath.AuthenticationClientId;
        $AuthenticationResource = "https://wdx$Name.ch.pbk/API"
        $AuthenticationCallback = "https://wdx$Name.ch.pbk/Portal"

#Setting Values in Config.json

        $ConfigJson.API_BASE = $API_BASE
        $ConfigJson.CRM_URL = $CRM_URL
        $ConfigJson.AuthenticationClientId = $AuthenticationClientId  
        $ConfigJson.AuthenticationResource = $AuthenticationResource
        $ConfigJson.AuthenticationCallback = $AuthenticationCallback
        $ConfigJson | ConvertTo-Json | Set-Content "$FolderPath\WDX_Sites\$ENVName\Binaries\Portal\Assets\config.json"
    }
    }
    catch
    {
    Write-Host "There was an error occured during config file editing" -ForegroundColor Red
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') ERROR: There was an error occured during config file editing $($_)"
    }
    return $output
}


##################################################################################################
#Backend server script

#Checking and creating folder structure

function Create-FolderStructure(){
    $output = @()
       
    if (-not (Test-Path  "$BE_FolderPath\$ENVName" -PathType Container))
    {
        Write-Host "Creating the necessary folder structure for the environment $ENVName"
        $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Creating the necessary folder structure for the environment $ENVName"
        try{
        New-Item "$BE_FolderPath\$ENVName" -Name "Binaries" -Type Directory
        New-Item "$BE_FolderPath\$ENVName" -Name "Config_Files" -Type Directory
        New-Item "$BE_FolderPath\$ENVName" -Name "IIS_Installer_Files" -Type Directory
        New-Item "$BE_FolderPath\$ENVName" -Name "Package_To_Use" -Type Directory
        Write-Host "Folder created." -ForegroundColor Green
        $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Folder created."
        }
        catch{
        Write-Host "Please check your input in parameter file" -ForegroundColor Red
        $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') ERROR: Please check your input in parameter file $($_)"
        }
    }
    else{
    Write-Host "$BE_FolderPath\$ENVName Folder already exist" -ForegroundColor Red
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') WARNING: $BE_FolderPath\$ENVName Folder already exist"
#    Exit;
    }

    if(-not (Test-Path "$BE_FolderPath\$ENVName\IIS_Installer_Files")){
    Write-Host "$BE_FolderPath\$ENVName\IIS_Installer_Files folder does not exist" -ForegroundColor Red
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') WARNING: $BE_FolderPath\$ENVName\IIS_Installer_Files folder does not exist"
#    Exit;
    }
   return $output 
} 

##################################################################################################
#Edit Web.config file

Function Editweb{
    $output = @()
    Try{
#Get values for web.config

    $Web_Config_Values = Get-Content "$FolderPath\WDX_Sites\$ENVName\WDX_Config_Files\Web_Config_Values.json" | ConvertFrom-Json

    if (-not (Test-Path  "$FolderPath\WDX_Sites\$ENVName\Binaries\API\Web.config" )){
        Write-Host "Web.config file does not exist" -ForegroundColor Red
        $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') WARNING: Web.config file does not exist"
        #Exit;
    }
    else{
        $webConfigpath = "$FolderPath\WDX_Sites\$ENVName\Binaries\API\Web.config"
        }

# <appSettings>

    $GEDAPI_technical_user_name = $Web_Config_Values.GEDAPI_technical_user_name
    $GEDAPI_technical_user_password = $Web_Config_Values.GEDAPI_technical_user_password
    $S2iAPIToken_client_id = $Web_Config_Values.S2iAPIToken_client_id
    $OrganisationName = $ENVName
    $CorsOrigins = $Web_Config_Values.CorsOrigins 
    $Authentication_WSO2_Audience = $Web_Config_Values.Authentication_WSO2_Audience
    $Authentication_WSO2_AudienceId = $Web_Config_Values.Authentication_WSO2_AudienceId
    $ConnectionStringspwd = $Web_Config_Values.ConnectionStringspwd
    $WDX = $Web_Config_Values.WDX
    $WDXShared = $Web_Config_Values.WDXShared
    $RabbitMQ = $Web_Config_Values.RabbitMQ #>
    
    $CustomAssemblyFolder = "$FolderPath\WDX_Sites\$ENVName\Binaries\APICustomAssemblies"



    #$webConfig = "$BE_FolderPath\$ENVName\Binaries\API\Web.config"
    $doc = (Get-Content $webConfigpath) -as [Xml]
    $obj = $doc.DocumentElement.appSettings.add

    $GEDAPI_technical_user_name_old = $obj | Where-Object {$_.key -eq "GEDAPI_technical_user_name"}
    $GEDAPI_technical_user_name_old[0].value = $GEDAPI_technical_user_name

    $GEDAPI_technical_user_password_old = $obj | Where-Object {$_.key -eq "GEDAPI_technical_user_password"}
    $GEDAPI_technical_user_password_old[0].value = $GEDAPI_technical_user_password

    $S2iAPIToken_client_id_old = $obj | Where-Object {$_.key -eq "S2iAPIToken_client_id"}
    $S2iAPIToken_client_id_old[0].value = $S2iAPIToken_client_id

    $OrganisationName_old = $obj | Where-Object {$_.key -eq "OrganisationName"}
    $OrganisationName_old.value = $OrganisationName

    $CorsOrigins_old = $obj | Where-Object {$_.key -eq "CorsOrigins"}
    $CorsOrigins_old.value = $CorsOrigins

    $CustomAssemblyFolder_old = $obj | Where-Object {$_.key -eq "CustomAssemblyFolder"}
    $CustomAssemblyFolder_old.value = $CustomAssemblyFolder

    $Authentication_WSO2_Audience_old = $obj | Where-Object {$_.key -eq "Authentication.WSO2.Audience"}
    $Authentication_WSO2_Audience_old.value = $Authentication_WSO2_Audience

    $Authentication_WSO2_AudienceId_old = $obj | Where-Object {$_.key -eq "Authentication.WSO2.AudienceId"}
    $Authentication_WSO2_AudienceId_old.value = $Authentication_WSO2_AudienceId

# <connectionStrings>

    $connectionStrings = $doc.DocumentElement.connectionStrings.add

    $connectionStringspwd = $Web_Config_Values.connectionStringspwd
    $WDX = $Web_Config_Values.WDX
    $WDXShared = $Web_Config_Values.WDXShared
    $RabbitMQ = $Web_Config_Values.RabbitMQ


    $WDX_old = $connectionStrings | Where-Object {$_.name -eq "WDX"}
    $WDX_old.connectionString = $WDX

    $WDXShared_old = $connectionStrings | Where-Object {$_.name -eq "WDXShared"}
    $WDXShared_old.connectionString = $WDXShared

    $RabbitMQ_old = $connectionStrings | Where-Object {$_.name -eq "RabbitMQ"}
    $RabbitMQ_old.connectionString = $RabbitMQ


    $doc.Save($webConfigpath)
    }
    catch
    {
    Write-Host "There was an error occured during config file editing" -ForegroundColor Red
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') ERROR: There was an error occured during config file editing $($_)"
    }
    return $output
}

##################################################################################################
#Edit WDXAPI & WDXPORTAL URI Values
# Variables 
#$CRM_Password = ConvertTo-SecureString "" -AsPlainText -Force

<#$CRM_Password = ConvertTo-SecureString ($GetJson.CRM_Password) -AsPlainText -Force
$CRM_UserName = $GetJson.CRM_UserName
$CRM_Cred = New-Object System.Management.Automation.PSCredential ($CRM_UserName, $CRM_Password)
$wdx_setting_LogicalName = $GetJson.wdx_setting_LogicalName 
$OrgName = $GetJson.OrgName
$ServerURL = $GetJson.ServerURL
$WDXAPI_Value = $GetJson.WDXAPI_Value
$WDXPORTAL_Value = $GetJson.WDXPORTAL_Value
$EncryptionKey = $GetJson.EncryptionKey #>
#$CRMConn = Get-CrmConnection –ServerUrl $ServerURL -Credential $CRM_Cred -OrganizationName $OrgName


Function DisablePlugin{
[CmdletBinding()]
Param (
    [Parameter(Position = 0)] 
    $ServerURL,
    [Parameter(Position = 1)] 
    $CRM_UserName,
    [Parameter(Position = 2)] 
    $CRM_Password,
    [Parameter(Position = 3)] 
    $OrgName   
)
$output = @()
Try{
# Connection to crm 
$pass = ConvertTo-SecureString $CRM_Password -AsPlainText -Force
$CRM_Cred = New-Object System.Management.Automation.PSCredential ($CRM_UserName, $pass)

$CRMConn = Get-CrmConnection –ServerUrl $ServerURL -Credential $CRM_Cred -OrganizationName $OrgName

# Script Body 

$records = @()
$ReturnProperty_Ids = @()

$crmrecords = Get-CrmRecords -conn $CRMConn -EntityLogicalName "sdkmessageprocessingstep" -AllRows

$crmrecords = $crmrecords.CrmRecords
foreach($crmrecord in $crmrecords)
    {
    $ReturnProperty_Ids += $crmrecord.ReturnProperty_Id
    }
    foreach($ReturnProperty_Id in $ReturnProperty_Ids)
        {
        $record = Get-CrmRecord -conn $CRMConn -EntityLogicalName "sdkmessageprocessingstep" -Id $ReturnProperty_Id.Guid -Fields *
        $records += $record
        }
#Get the plugin details

    $Plugins = $records | where -Property name -Like "WDX.CRM.PLUGINS.CORE.PLUGINSETTING: UpdatePost*"

#Disable plugin
    $output += "Plugins: $Plugins"   
    foreach($Plugin in $Plugins){
    #Set-CrmRecordState -conn $CRMConn -CrmRecord $Plugin -StateCode "Disabled" -StatusCode "Disabled"
    }
    }
    catch
    {
    Write-Host "There was an error occured during disabling plugin" -ForegroundColor Red
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') ERROR: There was an error occured during disabling plugin $($_)"
    }
    return $output
}

Function EnablePlugin{
[CmdletBinding()]
Param (
    [Parameter(Position = 0)] 
    $ServerURL,
    [Parameter(Position = 1)] 
    $CRM_UserName,
    [Parameter(Position = 2)] 
    $CRM_Password,
    [Parameter(Position = 3)] 
    $OrgName   
)
$output = @()
Try{
# Connection to crm 
$pass = ConvertTo-SecureString $CRM_Password -AsPlainText -Force
$CRM_Cred = New-Object System.Management.Automation.PSCredential ($CRM_UserName, $pass)

$CRMConn = Get-CrmConnection –ServerUrl $ServerURL -Credential $CRM_Cred -OrganizationName $OrgName

# Script Body 

$records = @()
$ReturnProperty_Ids = @()

$crmrecords = Get-CrmRecords -conn $CRMConn -EntityLogicalName "sdkmessageprocessingstep" -AllRows

$crmrecords = $crmrecords.CrmRecords
foreach($crmrecord in $crmrecords)
    {
    $ReturnProperty_Ids += $crmrecord.ReturnProperty_Id
    }
    foreach($ReturnProperty_Id in $ReturnProperty_Ids)
        {
        $record = Get-CrmRecord -conn $CRMConn -EntityLogicalName "sdkmessageprocessingstep" -Id $ReturnProperty_Id.Guid -Fields *
        $records += $record
        }
#Get the plugin details

    $Plugins = $records | where -Property name -Like "WDX.CRM.PLUGINS.CORE.PLUGINSETTING: UpdatePost*"
    
#Enable plugin
    
    foreach($Plugin in $Plugins){
    Set-CrmRecordState -conn $CRMConn -CrmRecord $Plugin -StateCode "Enabled" -StatusCode "Enabled"
    }
    }
    catch
    {
    Write-Host "There was an error occured during enabling plugin" -ForegroundColor Red
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') ERROR: There was an error occured enabling plugin $($_)"
    }
    return $output
}


Function Get-APIPORTALValue{
[CmdletBinding()]
Param (
    [Parameter(Position = 0)] 
    $ServerURL,
    [Parameter(Position = 1)] 
    $CRM_UserName,
    [Parameter(Position = 2)] 
    $CRM_Password,
    [Parameter(Position = 3)] 
    $OrgName,
    [Parameter(Position = 4)] 
    $wdx_setting_LogicalName
)
$output = @()
Try{
# Connection to crm 
$pass = ConvertTo-SecureString $CRM_Password -AsPlainText -Force
$CRM_Cred = New-Object System.Management.Automation.PSCredential ($CRM_UserName, $pass)

$CRMConn = Get-CrmConnection –ServerUrl $ServerURL -Credential $CRM_Cred -OrganizationName $OrgName

# Script Body 

$crmrecords = Get-CrmRecords -conn $CRMConn -EntityLogicalName $wdx_setting_LogicalName -AllRows

$crmrecords = $crmrecords.CrmRecords

$records = @()
$ReturnProperty_Ids = @()

foreach($crmrecord in $crmrecords)
    {
    $ReturnProperty_Ids += $crmrecord.ReturnProperty_Id
    }
    foreach($ReturnProperty_Id in $ReturnProperty_Ids)
        {
        $record = Get-CrmRecord -conn $CRMConn -EntityLogicalName "wdx_setting" -Id $ReturnProperty_Id -Fields * 
        $records += $record
        }


$records = @()
$Property_Ids = @()
$WDXAPI = @()
$WDXPORTAL = @()

$Systemsettings = Get-CrmRecords -conn $CRMConn -EntityLogicalName $wdx_setting_LogicalName -AllRows
$Systemsettings = $Systemsettings.CrmRecords
    foreach($Systemsetting in $Systemsettings)
    {
    $Property_Ids += $Systemsetting.ReturnProperty_Id
    }
        foreach($Property_Id in $Property_Ids)
        {
        $record = Get-CrmRecord -conn $CRMConn -EntityLogicalName $wdx_setting_LogicalName -Id $Property_Id -Fields * 
        $records += $record 
        #$output += $record
        }

    $WDXPORTAL += $records | where -Property wdx_name -EQ "WDX.PORTAL"
    $WDXPORTAL = $WDXPORTAL.wdx_value
    #$output += $WDXPORTAL
    Write-Host "WDX.PORTAL value - $WDXPORTAL"
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: WDX.PORTAL value - $($WDXPORTAL)"
    $WDXAPI += $records | where -Property wdx_name -EQ "WDX.API"
    $WDXAPI = $WDXAPI.wdx_value
    Write-Host "WDX.API value - $($WDXAPI)"
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: WDX.API value - $($WDXAPI)"
    }
    catch
    {
    Write-Host "There was an error occured during getting Apiportal value" -ForegroundColor Red
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') ERROR: There was an error occured during getting Apiportal value $($_)"
    }
    return $output
}
 

Function Set-APIPORTALValue{
[CmdletBinding()]
Param (
    [Parameter(Position = 0)] 
    $ServerURL,
    [Parameter(Position = 1)] 
    $CRM_UserName,
    [Parameter(Position = 2)] 
    $CRM_Password,
    [Parameter(Position = 3)] 
    $OrgName,
    [Parameter(Position = 4)] 
    $wdx_setting_LogicalName,
    [Parameter(Position = 5)] 
    $WDXAPI_Value,
    [Parameter(Position = 6)] 
    $WDXPORTAL_Value
)
$output = @()
Try{
# Connection to crm 
$pass = ConvertTo-SecureString $CRM_Password -AsPlainText -Force
$CRM_Cred = New-Object System.Management.Automation.PSCredential ($CRM_UserName, $pass)

$CRMConn = Get-CrmConnection –ServerUrl $ServerURL -Credential $CRM_Cred -OrganizationName $OrgName

# Script Body 

$crmrecords = Get-CrmRecords -conn $CRMConn -EntityLogicalName $wdx_setting_LogicalName -AllRows

$crmrecords = $crmrecords.CrmRecords

$records = @()
$ReturnProperty_Ids = @()

foreach($crmrecord in $crmrecords)
    {
    $ReturnProperty_Ids += $crmrecord.ReturnProperty_Id
    }
    foreach($ReturnProperty_Id in $ReturnProperty_Ids)
        {
        $record = Get-CrmRecord -conn $CRMConn -EntityLogicalName "wdx_setting" -Id $ReturnProperty_Id -Fields * 
        $records += $record
        }


$records = @()
$Property_Ids = @()
$WDXAPI = @()
$WDXPORTAL = @()

$Systemsettings = Get-CrmRecords -conn $CRMConn -EntityLogicalName $wdx_setting_LogicalName -AllRows
$Systemsettings = $Systemsettings.CrmRecords
    foreach($Systemsetting in $Systemsettings)
    {
    $Property_Ids += $Systemsetting.ReturnProperty_Id
    }
        foreach($Property_Id in $Property_Ids)
        {
        $record = Get-CrmRecord -conn $CRMConn -EntityLogicalName $wdx_setting_LogicalName -Id $Property_Id -Fields * 
        $records += $record 
        }

    $WDXPORTAL += $records | where -Property wdx_name -EQ "WDX.PORTAL"
    $WDXAPI += $records | where -Property wdx_name -EQ "WDX.API"
    
#Set WDX API value
    $APIId = $WDXAPI.ReturnProperty_Id.Guid
    Set-CrmRecord -conn $CRMConn -Id $APIId -EntityLogicalName $wdx_setting_LogicalName -Fields @{"wdx_value"=$WDXAPI_Value}

    $PORTALId = $WDXPORTAL.ReturnProperty_Id.Guid
#Set WDX Portal value
    Set-CrmRecord -conn $CRMConn -Id $PORTALId -EntityLogicalName $wdx_setting_LogicalName -Fields @{"wdx_value"=$WDXPORTAL_Value}
}
catch
{
 Write-Host "There was an error occured during setting Apiportal value" -ForegroundColor Red
 $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') ERROR: There was an error occured during setting Apiportal value $($_)"
}
return $output
}


<#Function Set-wdx_setting_Value{
[CmdletBinding()]
Param (
    [Parameter(Position = 0)] 
    $ServerURL,
    [Parameter(Position = 1)] 
    $CRM_UserName,
    [Parameter(Position = 2)] 
    $CRM_Password,
    [Parameter(Position = 3)] 
    $OrgName,
    [Parameter(Position = 4)] 
    $wdx_setting_LogicalName
    
)
$output = @()
Try{
# Connection to crm 
$pass = ConvertTo-SecureString $CRM_Password -AsPlainText -Force
$CRM_Cred = New-Object System.Management.Automation.PSCredential ($CRM_UserName, $pass)
$CRMConn = Get-CrmConnection –ServerUrl $ServerURL -Credential $CRM_Cred -OrganizationName $OrgName

# Script Body 

$crmrecords = Get-CrmRecords -conn $CRMConn -EntityLogicalName $wdx_setting_LogicalName -AllRows

$crmrecords = $crmrecords.CrmRecords

$records = @()
$ReturnProperty_Ids = @()

foreach($crmrecord in $crmrecords)
    {
    $ReturnProperty_Ids += $crmrecord.ReturnProperty_Id
    }
    foreach($ReturnProperty_Id in $ReturnProperty_Ids)
        {
        $record = Get-CrmRecord -conn $CRMConn -EntityLogicalName "wdx_setting" -Id $ReturnProperty_Id -Fields * 
        $records += $record
        }


$records = @()
$Property_Ids = @()

$Systemsettings = Get-CrmRecords -conn $CRMConn -EntityLogicalName $wdx_setting_LogicalName -AllRows
$Systemsettings = $Systemsettings.CrmRecords
    foreach($Systemsetting in $Systemsettings)
    {
    $Property_Ids += $Systemsetting.ReturnProperty_Id
    }
        foreach($Property_Id in $Property_Ids)
        {
        $record = Get-CrmRecord -conn $CRMConn -EntityLogicalName $wdx_setting_LogicalName -Id $Property_Id -Fields * 
        $records += $record 
        }

$a = $records | where wdx_name -Like "s2iIntegrationsettings"
$s2iReturnProperty_Id = $a.ReturnProperty_Id.Guid  #088babd7-1945-eb11-b812-005056970ef5
$b = $a.wdx_value | ConvertFrom-Json
$b.DataIntegrationCustomerApiUrl = "https://sim-apigw-wso2.ch.pbk:8243/api/{S2iControllerName}/v3/"
$b.FircoSoftServiceSettings.DataIntegrationFircoSoftServiceBase = "https://firco-online-sim.ch.pbk/api/"

$afterconversion = $b | ConvertTo-Json

Set-CrmRecord -conn $CRMConn -Id $s2iReturnProperty_Id -EntityLogicalName $wdx_setting_LogicalName -Fields @{"wdx_value"=$afterconversion}
}
catch
{
Write-Host "There was an error occured during setting wdx setting Value" -ForegroundColor Red
$output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') ERROR: There was an error occured during setting wdx setting Value $($_)"
}
return $output
}#>

Function Set-wdx_setting_Value{
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)] 
        $ServerURL,
        [Parameter(Position = 1)] 
        $CRM_UserName,
        [Parameter(Position = 2)] 
        $CRM_Password,
        [Parameter(Position = 3)] 
        $OrgName,
        [Parameter(Position = 4)] 
        $wdx_setting_LogicalName,
        [Parameter(Position = 5)] 
        $s2i_integration_setting
        
    )
    $output = @()
    $wdx_value = @()
    
    <#$CRM_Password = "RUZjfswe76428/hkoas5"
    $CRM_UserName = "ADCHPBK\CT884"
    $ServerURL = "https://crmflw-sim.pbgate-cs.net"
    $OrgName = "crmflw-sim"
    $wdx_setting_LogicalName = "wdx_setting"
    $s2i_integration_setting = ''#>
    
    Try{
    $output  += "Value: $s2i_integration_setting"
    # Connection to crm 
    $pass = ConvertTo-SecureString $CRM_Password -AsPlainText -Force
    $CRM_Cred = New-Object System.Management.Automation.PSCredential ($CRM_UserName, $pass)
    $CRMConn = Get-CrmConnection –ServerUrl $ServerURL -Credential $CRM_Cred -OrganizationName $OrgName
    
    # Script Body 
    
    $crmrecords = Get-CrmRecords -conn $CRMConn -EntityLogicalName $wdx_setting_LogicalName -AllRows
    
    $crmrecords = $crmrecords.CrmRecords
    
    $records = @()
    $ReturnProperty_Ids = @()
    
    foreach($crmrecord in $crmrecords)
        {
        $ReturnProperty_Ids += $crmrecord.ReturnProperty_Id
        }
        foreach($ReturnProperty_Id in $ReturnProperty_Ids)
            {
            $record = Get-CrmRecord -conn $CRMConn -EntityLogicalName "wdx_setting" -Id $ReturnProperty_Id -Fields * 
            $records += $record
            }
    
    
    $records = @()
    $Property_Ids = @()
    
    $Systemsettings = Get-CrmRecords -conn $CRMConn -EntityLogicalName $wdx_setting_LogicalName -AllRows
    $Systemsettings = $Systemsettings.CrmRecords
        foreach($Systemsetting in $Systemsettings)
        {
        $Property_Ids += $Systemsetting.ReturnProperty_Id
        }
            foreach($Property_Id in $Property_Ids)
            {
            $record = Get-CrmRecord -conn $CRMConn -EntityLogicalName $wdx_setting_LogicalName -Id $Property_Id -Fields * 
            $records += $record 
            }
    #$output += $records
    $a = $records | where wdx_name -Like "s2iIntegrationsettings"
    $wdx_value += $a.wdx_value
    $s2iReturnProperty_Id = $a.ReturnProperty_Id.Guid  #088babd7-1945-eb11-b812-005056970ef5
    #$b = $a.wdx_value | ConvertFrom-Json
    #$b.DataIntegrationCustomerApiUrl = "https://sim-apigw-wso2.ch.pbk:8243/api/{S2iControllerName}/v3/"
    #$b.FircoSoftServiceSettings.DataIntegrationFircoSoftServiceBase = "https://firco-online-sim.ch.pbk/api/"
    
    #$afterconversion = $b | ConvertTo-Json
    
    #Set-CrmRecord -conn $CRMConn -Id $s2iReturnProperty_Id -EntityLogicalName $wdx_setting_LogicalName -Fields @{"wdx_value"=$afterconversion}#>
    
    Set-CrmRecord -conn $CRMConn -Id $s2iReturnProperty_Id -EntityLogicalName $wdx_setting_LogicalName -Fields @{"wdx_value"=$s2i_integration_setting}
    
    }
    catch
    {
    Write-Host "There was an error occured during setting wdx setting Value" -ForegroundColor Red
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') ERROR: There was an error occured during setting wdx setting Value $($_)"
    #}
    }
    return $wdx_value,$output
    }
function DataEncryptionKey{
[CmdletBinding()]
Param (
    [Parameter(Position = 0)] 
    $ServerURL,
    [Parameter(Position = 1)] 
    $CRM_UserName,
    [Parameter(Position = 2)] 
    $CRM_Password,
    [Parameter(Position = 3)] 
    $OrgName,
    [Parameter(Position = 4)] 
    $EncryptionKey
)
$output = @()
Try{

#$output += "Values: $serverurl, $CRM_UserName, $CRM_Password, $OrgName, $EncryptionKey"

$pass = ConvertTo-SecureString $CRM_Password -AsPlainText -Force
$CRM_Cred = New-Object System.Management.Automation.PSCredential ($CRM_UserName, $pass)
# Connection to crm 

$CRMConn = Get-CrmConnection –ServerUrl $ServerURL -Credential $CRM_Cred -OrganizationName $OrgName

# Read current organization encryption key
    $output += "Previous Encryptionkey"
    $output += (Invoke-CrmAction -conn $CRMConn -Name "RetrieveDataEncryptionKey").Encryptionkey

# Set and activate a new key

    Invoke-CrmAction -conn $CRMConn -Name "SetDataEncryptionKey" -Parameters @{EncryptionKey = $EncryptionKey; ChangeEncryptionKey = $true} -ErrorAction SilentlyContinue | Out-Null

    $IsActiveReq = New-Object Microsoft.Xrm.Sdk.Messages.IsDataEncryptionActiveRequest
    $isactiveresult = $CRMConn.ExecuteCrmOrganizationRequest($IsActiveReq) 
    $SetReq = New-Object Microsoft.Xrm.Sdk.Messages.SetDataEncryptionKeyRequest
    $SetReq.ChangeEncryptionKey=$true
    $SetReq.EncryptionKey=$EncryptionKey
    $CRMConn.ExecuteCrmOrganizationRequest($SetReq) | out-null

    $setKey = New-Object Microsoft.Xrm.Sdk.Messages.SetDataEncryptionKeyRequest
    $setKey.EncryptionKey = $EncryptionKey;
    $CRMConn.ExecuteCrmOrganizationRequest($setKey)| out-null; 

    $output += "Current Encryptionkey"
    $output += (Invoke-CrmAction -conn $CRMConn -Name "RetrieveDataEncryptionKey").Encryptionkey
    }
    catch
    {
    Write-Host "There was an error occured during setting data encryption key" -ForegroundColor Red
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') ERROR: There was an error occured during setting data encryption key $($_)"
    }
    return $output
    
}

##################################################################################################
#BGServices

#Edit BG services config file

Function EditBGServices{
$output = @()
Try{
#Get values for web.config

    $BGServices_Config_Values = Get-Content "$FolderPath\WDX_Sites\$ENVName\WDX_Config_Files\BGServices_Config.json" | ConvertFrom-Json

    if (-not (Test-Path  "$FolderPath\WDX_Sites\$ENVName\BGServices\WDX.BackgroundProcessor.Service.exe.config" )){
        Write-Host "BGServices.config file does not exist" -ForegroundColor Red
        $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') WARNING: BGServices.config file does not exist"
        #Exit;
    }
    else{
        $BEServicesfile = "$FolderPath\$ENVName\BGServices\WDX.BackgroundProcessor.Service.exe.config"
        }

# <appSettings>

    $OrganisationName = $BGServices_Config_Values.OrganisationName
    $StatusAPI = $BGServices_Config_Values.StatusAPI
    $NodeName = $BGServices_Config_Values.NodeName
    $CustomAssemblyFolder = $BGServices_Config_Values.CustomAssemblyFolder
    $DataIntegrationFileInput = $BGServices_Config_Values.DataIntegrationFileInput 
    $S2iAPIToken_URI = $BGServices_Config_Values.S2iAPIToken_URI
    $GEDAPI_technical_user_name = $BGServices_Config_Values.GEDAPI_technical_user_name
    $GEDAPI_technical_user_password = $BGServices_Config_Values.GEDAPI_technical_user_password
    $S2iAPIToken_client_id = $BGServices_Config_Values.S2iAPIToken_client_id
    $WDX = $BGServices_Config_Values.WDX
    $WDXShared = $BGServices_Config_Values.WDXShared
    $RabbitMQ = $BGServices_Config_Values.RabbitMQ


    #$webConfig = "$BE_FolderPath\$ENVName\Binaries\API\Web.config"
    $doc = (Get-Content $BEServicesfile) -as [Xml]
    $obj = $doc.DocumentElement.appSettings.add

    $OrganisationName_old = $obj | Where-Object {$_.key -eq "OrganisationName"}
    $OrganisationName_old.value = $OrganisationName

    #StatusAPI

    $StatusAPI_old = $obj | Where-Object {$_.key -eq "StatusAPI"}
    $StatusAPI_old.value = $StatusAPI


    #NodeName

    $NodeName_old = $obj | Where-Object {$_.key -eq "NodeName"}
    $NodeName_old.value = $NodeName



    #CustomAssemblyFolder

    $CustomAssemblyFolder_old = $obj | Where-Object {$_.key -eq "CustomAssemblyFolder"}
    $CustomAssemblyFolder_old.value = $CustomAssemblyFolder


    #DataIntegrationFileInput

    $DataIntegrationFileInput_old = $obj | Where-Object {$_.key -eq "DataIntegrationFileInput"}
    $DataIntegrationFileInput_old.value = $DataIntegrationFileInput


    #S2iAPIToken_URI
    
    $S2iAPIToken_URI_old = $obj | Where-Object {$_.key -eq "S2iAPIToken_URI"}
    $S2iAPIToken_URI_old[0].value = $S2iAPIToken_URI



    #GEDAPI_technical_user_name

    $GEDAPI_technical_user_name_old = $obj | Where-Object {$_.key -eq "GEDAPI_technical_user_name"}
    $GEDAPI_technical_user_name_old[0].value = $S2iAPIToken_URI


    #GEDAPI_technical_user_password

    $GEDAPI_technical_user_password_old = $obj | Where-Object {$_.key -eq "GEDAPI_technical_user_password"}
    $GEDAPI_technical_user_password_old[0].value = $GEDAPI_technical_user_password


    #S2iAPIToken_client_id

    $S2iAPIToken_client_id_old = $obj | Where-Object {$_.key -eq "S2iAPIToken_client_id"}
    $S2iAPIToken_client_id_old[0].value = $S2iAPIToken_client_id


    # <connectionStrings>

    $connectionStrings = $doc.DocumentElement.connectionStrings.add

    $WDX = $BGServices_Config_Values.WDX
    $WDXShared = $BGServices_Config_Values.WDXShared
    $RabbitMQ = $BGServices_Config_Values.RabbitMQ

    $WDX_old = $connectionStrings | Where-Object {$_.name -eq "WDX"}
    $WDX_old.connectionString = $WDX

    $WDXShared_old = $connectionStrings | Where-Object {$_.name -eq "WDXShared"}
    $WDXShared_old.connectionString = $WDXShared

    $RabbitMQ_old = $connectionStrings | Where-Object {$_.name -eq "RabbitMQ"}
    $RabbitMQ_old.connectionString = $RabbitMQ


    
    $doc.Save($BEServicesfile)
    }
    catch
    {
    Write-Host "There was an error occured during editing bg services" -ForegroundColor Red
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') ERROR: There was an error occured during editing bg services $($_)"
    }
    return $output
    }

##################################################################################################
#If Site exist already.


Function Stop-IISservices{


        [CmdletBinding()]
    Param (
        [Parameter(Position = 0)] 
        $EnvName,
        [Parameter(Position = 1)] 
        $API,
        [Parameter(Position = 2)] 
        $Portal
    )
$output = @()
Try{
#Stop IIS Services

Write-Host "Stopping IIS Services"
$output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Stopping IIS Services"

#Stop IIS Site
    
    Get-IISSite -Name "WDX$EnvName" | Stop-IISSite -Confirm:$false

#Stop IIS App pool
    
    Get-IISAppPool -Name "WDX$EnvName" | Stop-WebAppPool

    Get-IISAppPool -Name $API | Stop-WebAppPool
    
    Get-IISAppPool -Name $Portal | Stop-WebAppPool


Write-Host "IIS Services Stopped" -ForegroundColor Green
$output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: IIS Services Stopped"

}
catch
{
Write-Host "There was an error occured during stopping IIS services" -ForegroundColor Red
$output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') ERROR: There was an error occured during stopping IIS services services $($_)"
}
return $output
   
}

Function Remove-Files{

#Use this function with CAUTION!

#To remove the files from API, APICustomAssemblies, Portal.

        [CmdletBinding()]
    Param (
        [Parameter(Position = 0)] 
        $EnvName
    )
    $output = @()
    TRY{
    Write-Host "Removing the necessary files..."
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Removing the necessary files..."
    #API
    Get-ChildItem -Path "E:\wdx\WDX$EnvName\API" -Recurse |
    Where-Object { $_.Name -ne "Web.config"} |
    Remove-Item -Recurse -ErrorAction SilentlyContinue
    
    #APICustomAssemblies
    Get-ChildItem -Path "E:\wdx\WDX$EnvName\APICustomAssemblies" -Recurse |
    Remove-Item -Recurse -ErrorAction SilentlyContinue
    
    #Portal
    Get-ChildItem -Path "E:\wdx\WDX$EnvName\Portal" -File -Recurse |
    Where-Object { $_.Parent -ne "assets" -and $_.Name -ne "config.json" -and $_.Name -ne "index.html" -and $_.Name -ne "index_old.html"} |
    Remove-Item -Recurse -ErrorAction SilentlyContinue

    #Asset
    Get-ChildItem -Path "E:\wdx\WDX$EnvName\Portal\Assets" -Recurse |
    Where-Object { $_.Name -ne "config.json"} |
    Remove-Item -Recurse -ErrorAction SilentlyContinue

    Write-Host "Files removed" -ForegroundColor Green
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Files removed"
    }
    catch
    {
    Write-Host "There was an error occured during removing the files" -ForegroundColor Red
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') ERROR: There was an error occured during removing the files $($_)"
    }
    return $output

}

Function Set-MaintenancePage{

# Set the Maintenanace Page

        [CmdletBinding()]
    Param (
        [Parameter(Position = 0)] 
        $EnvName
        
    )
$output = @()
Try{
Write-Host "Setting the Maintanence page for WDX$EnvName"
$output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Setting the Maintanence page for WDX$EnvName"
Copy-Item -Path "E:\WDX\WDX$EnvName\Portal\Index.html" -Destination "E:\WDX\WDX$EnvName\Portal\Index_Copy.html" -ErrorAction Stop

Rename-Item -Path "E:\WDX\WDX$EnvName\Portal\Index.html" -NewName "Index_old.html" -ErrorAction Stop

New-Item -Path "E:\WDX\WDX$EnvName\Portal\Index.html" -Value "This Page Is Under Maintenance" -ErrorAction Stop

Write-Host "Maintanence page is set" -ForegroundColor Green
$output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Maintanence page is set"
}
catch
{
Write-Host "There was an error occured during setting maintenance page" -ForegroundColor Red
$output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') ERROR: There was an error occured during setting maintenance page $($_)"
}
return $output

}

Function Remove-MaintenancePage{

    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)] 
        $EnvName
        
    )
$output = @()
Try{   
Write-Host "Removing the Maintanence page for WDX$EnvName"
$output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Removing the Maintanence page..."
#Copy-Item -Path "E:\WDX\$EnvName\Portal\Index.html" -NewName "Index_Copy.html"

Remove-Item -Path "E:\WDX\WDX$EnvName\Portal\Index.html"

Rename-Item -Path "E:\WDX\WDX$EnvName\Portal\index_old.html" -NewName "Index.html"

Write-Host "Maintanence page removed" -ForegroundColor Green
$output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Maintanence page removed"
}
catch
{
Write-Host "An error occured during removing maintenance page" -ForegroundColor Red
$output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') ERROR: An error occured during removing maintenance page $($_)"
}
return $output
}


Function Start-IISservices{

        [CmdletBinding()]
    Param (
        [Parameter(Position = 0)] 
        $EnvName,
        [Parameter(Position = 1)] 
        $API,
        [Parameter(Position = 2)] 
        $Portal
    )

$output = @()
Try{
#Start IIS Services

    Write-Host "Starting the IIS services..."
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Starting the IIS services..."

#Start IIS Site
    
    Get-IISSite -Name "WDX$EnvName" | Start-IISSite

#Start IIS App pool
    
    Get-IISAppPool -Name "WDX$EnvName" | Start-WebAppPool

    Get-IISAppPool -Name $API | Start-WebAppPool
    
    Get-IISAppPool -Name $Portal | Start-WebAppPool

    Write-Host "IIS services started" -ForegroundColor Green
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: IIS services started" 
    }
    catch
    {
    Write-Host "An error occured during starting IIS services" -ForegroundColor Red
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') ERROR: An error occured during starting IIS services $($_)"
    }
    return $output    
}

Function Copy-Files{

        [CmdletBinding()]
    Param (
        [Parameter(Position = 0)] 
        $EnvName,
        [Parameter(Position = 1)] 
        $BE_Server,
        [Parameter(Position = 2)] 
        $Packageloc
    )

#Use this function with CAUTION!

$output = @()
Try{
#To copy the files from API, APICustomAssemblies, Portal.

    Write-Host "Copying the files from the package to E:\WDX\$ENVName"
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Copying the files from the package to E:\WDX\$ENVName"
    
    #API
    if(Test-Path  "\\$BE_Server\$Packageloc\web\API" -PathType Container){
    Get-ChildItem -Path "\\$BE_Server\$Packageloc\web\API" |
    Where-Object { $_.Name -ne "web.config" } |
    Copy-Item -Destination "E:\wdx\$ENVName\API" -Recurse -Container # -ErrorAction SilentlyContinue
        Write-Host "copy done"
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: copy done"

    }
    else{
    Write-Host "API folder does not exist in package.. copying from backup"
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: API folder does not exist in package.. copying from backup"
    }
    }
    catch
    {
    Write-Host "There was an error occured during copying files" -ForegroundColor Red
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') ERROR: There was an error occured during copying files $($_)"
    }
    return $output
    }

Function Copy-Files1{

    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)] 
        $EnvName,
        [Parameter(Position = 1)] 
        $BE_Server,
        [Parameter(Position = 2)] 
        $Packageloc,
        [Parameter(Position = 3)] 
        $FE_Server
    )

#Use this function with CAUTION!
$Output = @()
Try{
#To copy the files from API, APICustomAssemblies, Portal.

    Write-Host "Copying the files from the package to E:\WDX\WDX$ENVName"
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Copying the files from the package to E:\WDX\WDX$ENVName"
    Write-Host "\\$BE_Server\$Packageloc\web\API" -BackgroundColor DarkMagenta

    #API
    if(Test-Path  "\\$BE_Server\$Packageloc\web\API" -PathType Container){
    Get-ChildItem -Path "\\$BE_Server\$Packageloc\web\API" |
    Where-Object { $_.Name -ne "web.config" } |
    Copy-Item -Destination "\\$FE_Server\wdx\WDX$ENVName\API" -Recurse -Container -ErrorAction SilentlyContinue
    }
    else{
    Write-Host "API folder does not exist in package.. copying from backup"
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: API folder does not exist in package.. copying from backup"
    Get-ChildItem -Path "\\$FE_Server\WDX_Automation\WDX_Sites\WDX$ENVName\Binaries_Backup\API" |
    Where-Object { $_.Name -ne "web.config" } |
    Copy-Item -Destination "\\$FE_Server\wdx\WDX$ENVName\API" -Recurse -Container -ErrorAction SilentlyContinue
    }

    #Portal
    if(Test-Path  "\\$BE_Server\$Packageloc\web\Portal" -PathType Container){
    Get-ChildItem -Path "\\$BE_Server\$Packageloc\web\Portal" |
    Where-Object { $_.Name -ne "config.json" -and $_.Name -ne "index.html"} |
    Copy-Item -Destination "\\$FE_Server\wdx\WDX$ENVName\Portal" -Recurse -Container -ErrorAction SilentlyContinue
    }
    else{
    Write-Host "Portal folder does not exist in package.. copying from backup"
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Portal folder does not exist in package.. copying from backup"
    Get-ChildItem -Path "\\$FE_Server\WDX_Automation\WDX_Sites\WDX$ENVName\Binaries_Backup\Portal" | 
    Where-Object { $_.Name -ne "config.json" -and $_.Name -ne "index.html"} |
    Copy-Item -Destination "\\$FE_Server\wdx\WDX$ENVName\Portal" -Recurse -Container -ErrorAction SilentlyContinue
    }

    #APICustomAssemblies
    if(Test-Path  "\\$BE_Server\$Packageloc\CustomAssemblies\API" -PathType Container){
    Get-ChildItem -Path "\\$BE_Server\$Packageloc\CustomAssemblies\API" |
    Copy-Item -Destination "\\$FE_Server\wdx\WDX$ENVName\APICustomAssemblies" -Recurse -Container -ErrorAction SilentlyContinue
    }
    else{
    Write-Host "APICustomAssemblies folder does not exist in package.. copying from backup"
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: APICustomAssemblies folder does not exist in package.. copying from backup"
    Get-ChildItem -Path "\\$FE_Server\WDX_Automation\WDX_Sites\WDX$ENVName\Binaries_Backup\APICustomAssemblies" |
    Copy-Item -Destination "\\$FE_Server\wdx\WDX$ENVName\APICustomAssemblies" -Recurse -Container -ErrorAction SilentlyContinue
    }

    Write-Host "Copy done" -ForegroundColor Green
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Copy done"
    }
    catch
    {
    Write-Host "There was an error occured during copying files" -ForegroundColor Red
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') ERROR: There was an error occured during copying files $($_)"
    }
    return $Output
}

Function RestartBGService{

#Function to restart the background Services
    
    [CmdletBinding()]
        Param (
        [Parameter(Position = 0)] 
        $RestartServiceNames
    )   
    $output = @()
    Try{
    Write-Host "Restarting Background service"
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Restarting Background service"
    foreach($RestartServiceName in $RestartServiceNames){
    Restart-Service -Name $RestartServiceName
    Get-Service -Name $RestartServiceName | Select-Object Name, Status

    Write-Host "Background Service restarted" -ForegroundColor Green
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Background Service restarted $($_)"
    #add logs
    }
    }
    catch
    {
    Write-Host "An error occured during restarting bg service" -ForegroundColor Red
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') ERROR: An error occured during restarting bg service $($_)"
    }
    return $output
}
# Package version
function get-version
{
    [CmdletBinding()]
        Param (
        [Parameter(Position = 0)] 
        $packageloc
    )
    $output = @()
    if(Test-Path -Path $packageloc){
       Write-Host "$packageloc is available"
       $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: $packageloc is available"
       #$version = Get-Content -Path "E:\WDX_temp\WDX_TEMP_Package\LUXDeployment\Packages\WDX_LUXONLINE-4.4.2-IWM-9912-04062024\VersionInfo\version.json" 
       Write-Host "Getting version details..."
       $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Getting version details..."
       $version = Get-Content -Path "$packageloc\VersionInfo\version.json" |`
        ConvertFrom-Json
       Write-Host "Package version is $($version.PackageVersion)"
       $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Package version is $($version.PackageVersion)"
    }
    else{
        Write-Host "$packageloc is not available to get the version details"
       $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: $packageloc is not available to get the version details"
    }
    return $output,$version
}
function update-version
{
    [CmdletBinding()]
        Param (
        [Parameter(Position = 0)] 
        $version,
        [Parameter(Position = 1)] 
        $Env,
        [Parameter(Position = 2)] 
        $IWMSite
    )
    $output = @()
    try{
    Write-Host "Importing Powershell CRM module"
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Importing Powershell CRM module"

    Import-Module Microsoft.xrm.data.powershell

    Write-Host "Powershell CRM module imported."
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Powershell CRM module imported."

    if($Env -eq "SIM2") #SIM2 Creds
    {
    $pass = ConvertTo-SecureString 'HGFkuhziuJHgvf7623$' -AsPlainText -Force
    $Cred = New-Object System.Management.Automation.PSCredential ("ADCHPBK\CT493", $pass)
    }
    elseif($Env -eq "SIM") #SIM1 Creds
    {
    $pass = ConvertTo-SecureString 'Welcome012345$$$$$$$6789' -AsPlainText -Force
    $Cred = New-Object System.Management.Automation.PSCredential ("ADCHPBK\CT401", $pass)
    }
    elseif($Env -eq "PPR2") #PPR2 Creds
    {
    $pass = ConvertTo-SecureString 'HGFkuhziuJHgvf7623$' -AsPlainText -Force
    $Cred = New-Object System.Management.Automation.PSCredential ("ADCHPBK\CT511", $pass)
    }
    elseif($Env -eq "") #Prod Creds
    {
    $pass = ConvertTo-SecureString 'SperN0v@WDX2020!' -AsPlainText -Force
    $Cred = New-Object System.Management.Automation.PSCredential ("ADCHPBK\CT471", $pass)
    }
    Write-Host "Connecting to $IWMSite-$ENV CRM"
    $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Connecting to $IWMSite-$ENV CRM"
    $CRMConn = $null
    $Result = @()
    $CRMConn = Get-CrmConnection -ServerUrl "https://crm$IWMSite-$ENV.ch.pbk" -Credential $Cred -OrganizationName "CRM$IWMSite-$ENV" -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    if($CRMConn){
        Write-Host "Connected to $IWMSite-$ENV CRM"
        $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Connected to $IWMSite-$ENV CRM"

        Write-Host "Fetching wdx_configurationxml file...."
        $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Fetching wdx_configurationxml file...."

        $id = "763c176a-acf8-ed11-b82b-0050560115a8"
        $Result = Get-CrmRecord -conn $CRMConn -EntityLogicalName wdx_entitydashboard -Id $id -Fields wdx_configurationxml
        
        Write-Host "wdx_configurationxml file fetched from crm."
        $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: wdx_configurationxml file fetched from crm."

        $value = $Result.wdx_configurationxml

        Write-Host "Updating package version in crm..."
        $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Updating package version in crm..."

        if($value -match "Package Version:")
        {
            #$value.IndexOf("Package Version")
            $item = $value.Substring($value.IndexOf("Package Version")).split("}}")[0]
            $versionvalue = $item
            #$versionvalue
            if($versionvalue -match "Package Version:"){
                $Result_value = $Result.wdx_configurationxml.Replace($versionvalue,"Package Version: $version | label")
                #$Result.wdx_configurationxml.Replace($versionvalue,"$version | label")
                #set-CrmRecord -conn $CRMConn -Id $id -EntityLogicalName wdx_entitydashboard -Fields @{"wdx_configurationxml" = "$Result_value" }
                Write-Host "Package version updated in crm"
                $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Package version updated in crm"
            }
            else
            {
                Write-Host "Unable to update the package version because not able to get the expected pattern from CRM"
                $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Unable to update the package version because not able to get the expected pattern from CRM"
            }
        }
        else
        {
            $item = ($value.Substring($value.IndexOf("WDX Version"), ($value.LASTIndexOf("WDX Version")-$value.IndexOf("WDX Version"))))
            #$item
            $versionvalue = $item.split("}}")[0].split('{{')[-1]
            #$versionvalue
            if($versionvalue -match "label"){
                #$Result.wdx_configurationxml.Replace($versionvalue,"$version | label")
                $Result_value = $Result.wdx_configurationxml.Replace($versionvalue,"$version | label")
                #set-CrmRecord -conn $CRMConn -Id $id -EntityLogicalName wdx_entitydashboard -Fields @{"wdx_configurationxml" = "$Result_value" }
                Write-Host "Package version updated in crm"
                $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Package version updated in crm"
            }
            else{
                Write-Host "Unable to update the package version because not able to get the expected pattern from CRM"
                $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') INFO: Unable to update the package version because not able to get the expected pattern from CRM"
            }
        }
    }
    }
    catch
    {
        Write-Host "Some error occured while updating package version. Error: $($_)"
        $output += "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') ERROR: Some error occured while updating package version. Error: $($_)"
    }
    return $output  
}
