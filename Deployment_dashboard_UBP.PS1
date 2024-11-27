##########################################################################
# Script Purpose: PODE Framework - Front end application
# Site: UBP - Sites
# Author: Rohith Vignesh & Anusha Pachigolla
# Date: 14/03/2024
##########################################################################

Import-Module pode
Import-Module pode.web

Start-PodeServer -Name "Deploymentapp" {
    #Add-PodeEndpoint -Address "wdxdtUBP-sim.ch.pbk" -Port 443 -Protocol Https # -Name "login" -RedirectTo "login"
    Add-PodeEndpoint -Address localhost -Port 8082 -Protocol Http #-LookupHostname
    New-PodeLoggingMethod -Terminal | Enable-PodeErrorLogging -Levels @("Error","Warning","Informational")
    Use-PodeWebTemplates -Title 'Deployment Application' -Theme Light
    Enable-PodeSessionMiddleware -Duration 3600 -Extend
    $scheme = New-PodeAuthScheme -Form
    Add-PodeAuth -name 'login' -Scheme $scheme -SuccessUseOrigin -ScriptBlock {
        param($username,$password)
            if ($username -eq 'automation_user' -and $password -eq 'password') {
                $webevent.Session.Data.username = $username
                return @{Success = $true; user = @{username = $username;};}
            }
            else
            {
            return @{ Success = $false; Error = 'Invalid details supplied' }
            }
    }

#[1] Login page

Add-PodeWebPage -Hide -NoBackArrow -NoSidebar -Name 'Login' -Path '/login'  -ScriptBlock{
           New-PodeWebForm -Method Post -Name 'Login' -SubmitText 'Login' -Content @(
                New-PodeWebTextbox -Name 'UserName' -Type Text
                New-PodeWebTextbox -Name 'Password' -Type Password
            ) -ScriptBlock {
        $username = $webevent.data.username
        $password = $webevent.data.password
        if($username -eq 'automation_user' -and $password -eq 'A9Y4,N(j96j$') # *** Password recoreded here *** #
        { 
            $webevent.Session.Data.authenticated = $true
            $webevent.Session.Data.username = $username
            Write-Host "login success" -ForegroundColor Green
            Out-PodeVariable -Name username -Value $webevent.Session.Data.username
            New-PodeWebAlert -Type Info -Value "$username Authenticated"
            Move-PodeWebUrl -Url 'Select Deployment Site'  
           
        }
        else
        {
            Write-Host "login fail" -ForegroundColor Red
            $webevent.Session.Data.authenticated = $false
            New-PodeWebAlert -Type Error -Value "Invalid credentials"
        }
        Reset-PodeWebForm -Name 'login'
        
    } 
}

#[2] Middleware

$authmiddleware = {
    if(!$webevent.Session.Data.authenticated)
    { 
        Write-Host "Authentication status: $($webevent.Session.Data.authenticated)"
        Move-PodeResponseUrl -Url '/login'
    }
    else
    {
        $views = $WebEvent.Session.Data.Views++
        $user = $($webevent.Session.Data.username)
        write-host "$user accessed the web page $views times" -ForegroundColor Blue
    }
}
   
#[3] 

Add-PodeWebPage -HomePage -Hide -NoSidebar -NoBackArrow -Path 'Select Deployment Site' -Name '1.Select Deployment Site' -NewTab -Middleware @($authmiddleware) -Title 'Select Deployment Site' -ScriptBlock {
        $navhome = New-PodeWebNavLink -Name 'Home' -Url '/Select Deployment Site'
        $navDiv = New-PodeWebNavDivider
        $navlogin = New-PodeWebNavLink -Name 'Logout' -Url '/logout' 
        $navVersion = New-PodeWebNavLink -Name 'Version' -Url '/Version'
        $navToast = New-PodeWebNavLink -Name 'User Details' -Icon "Human" -ScriptBlock {
                Show-PodeWebToast -Message "Logged in as $($webevent.Session.Data.username)"
            }
        $navLogs = New-PodeWebNavLink -Name 'All Logs' -Url '/logssite'
        Set-PodeWebNavDefault -Items $navhome, $navLogs, $navVersion, $navToast, $navlogin
        Write-Host "Username $($webevent.Session.Data.username)" -ForegroundColor Green
         New-PodeWebCard -Name 'Select Deployment Site' -NoHide -Content @(
            New-PodeWebForm -Name 'Select Environment & Site' -Message "Refresh page if you have error and try again" -Content @(
                New-PodeWebSelect -Name 'Site' -Options 'FLW', 'USG', 'UCK' -Required
                New-PodeWebSelect -Name 'Environment' -Options 'SIM', 'SIM2'  -Required
            ) -ScriptBlock {
                $site = $webevent.data['Site']
                $env = $webevent.data['Environment']
                $deploymentsite = "$site-$env"
                #Reset-PodeWebForm -Name 'Select Environment & Site'
                Move-PodeWebPage -name 'WDX Deployment application' -DataValue $deploymentsite 
                Reset-PodeWebForm -Name 'Select Environment & Site'
                Reset-PodeWebForm -Name 'Select package'
            } 
         )
    }
    Add-PodeWebPage -Name 'WDX Deployment application' -Title '2.WDX Deployment application' -NoBackArrow -Hide -NoSidebar -ScriptBlock {
        if(!$webevent.query['value']){
            New-PodeWebHeader -Value "Please select Site and Environment" -Size 3
            return
        }
        $deploymentsite = $null
        $deploymentsite = $webevent.query['value']
        Write-Host "deployment site: $deploymentsite" -ForegroundColor Blue
        $site = ($deploymentsite -split "-")[0]
        $Environment = ($deploymentsite -split "-")[-1]
        New-PodeWebCard -Name 'Select where you want to perform the deployment' -NoHide -Content @(
            $Server =  "SWDXVE1043UBP" # ***** Change Server *****
            if($($site) -eq "FLW"){
            $packageloc = (Get-ChildItem -Path "\\$server\WDX_temp\wdx_temp_package\UFWDEPLOYMENT\Packages" | Where-Object {$_.Name -like "*.zip"} | Sort-Object -Property lastwritetime -Descending).Name 
            }
            else{
            $packageloc = (Get-ChildItem -Path "\\$server\WDX_temp\wdx_temp_package\$($site)DEPLOYMENT\Packages" | Where-Object {$_.Name -like "*.zip"} | Sort-Object -Property lastwritetime -Descending).Name 
            }
            New-PodeWebForm -Name 'Select package' -SubmitText "Deploy" -ShowReset -Message "Refresh page if you have error and try again" -Content @(
                New-PodeWebTextbox -Name 'Selected Site' -ReadOnly -Value $webevent.query['value']
                New-PodeWebSelect -Name 'Select Package' -Options $packageloc -Required
                New-PodeWebSelect -Name 'Deployment type' -DisplayOptions 'A: Install everything' , 'B: Install solutions only', `
                ` 'C: Install WDX solutions only (proceed with caution!)', 'D: Install non-WDX solutions only' ,`
                ` 'E: Install everything except solutions' , 'F: Install CRM data only' , 'G: Install SQL only', 'H: Install services only', 'I: Install web only', `
                ` 'J: Set WDX SIMPLE Settings only', 'K: Set WDX SYSTEM Settings only', 'L: Restart Sandbox', 'M: Deploy Dacpac', 'R: Run data remediation only' -Options 'A','B','C','D','E','F','G',`
                ` 'H','I','J','K','L','M','R' -Required
                New-PodeWebTextbox -Name 'SQL Query' -Multiline #-Placeholder "Write SQL Query" 
                if($($Environment) -eq "SIM" -and $($site) -eq "FLW"){
                    New-PodeWebSelect -Name 'DB Name' -Options "WDXSHARED_$($site)", "CRM$($site)_MSCRM" -Required
                }
                elseif($($Environment) -eq "SIM" -and $($site) -ne "FLW"){
                    New-PodeWebSelect -Name 'DB Name' -Options "WDXSHARED_$($site)", "CRM$($site)_$($Environment)_MSCRM" -Required
                }
                else{
                    New-PodeWebSelect -Name 'DB Name' -Options "WDXSHARED_$($site)_$($Environment)", "CRM$($site)_$($Environment)_MSCRM" -Required
                }
                New-PodeWebSelect -Name 'SQL Query Execution Order' -Options "Before Deployment","After Deployment" -Required
                New-PodeWebTextbox -Name 'S2I Integration Setting' -Multiline #-Placeholder "Write SQL Query" 
                New-PodeWebCheckbox -Name 'Operation' -Options '1. Run SQL Query', '2. Binaries Backup', '3. Set Maintenance page', '4. Stop IIS Services', '5. Start Deployment' , '6. Remove Binaries' , '7. Copy Binaries' , '8. Start IIS Services' , '9. Restart BG Services' , '10. Remove Maintenance' 
                New-PodeWebCheckbox -Name 'CRM Operation' -Options '1. Set DataEncryption Key','2. Get WDX API & PORTAL Value','3. Disable Plugins','4. Set WDX API & PORTAL Value','5. Set S2i Integration setting Value','6. Enable Plugin'
                ) -ScriptBlock {
                $deploymentsite = $WebEvent.Data['Selected Site']
                write-host "Deploymentsite: $deploymentsite"
                $site = ($deploymentsite -split "-")[0]
                $SelectedPackage = $WebEvent.Data['Select Package'] 
                $Operation = $WebEvent.Data['Operation']
                $Deploymenttype = $WebEvent.Data['Deployment type']
                $query = $WebEvent.Data['SQL Query']
                $DBName = $WebEvent.Data['DB Name']
                $query_order = $WebEvent.Data['SQL Query Execution Order']
                $crmoperation = $WebEvent.Data['CRM Operation']
                $s2i_integration_setting = $WebEvent.Data['S2I Integration Setting']
                $path = "E:\WDX\Deployment_application\UBP\Public\Logs\$site\output_$(Get-Date -Format 'dd-MM-yyyy_HH-mm-ss').txt" # ***** change path *****
                #$path = "E:\WDX_Automation\Scripts\anusha\pode-deploy\final\loginpage\public\logs\output_$(Get-Date -Format 'dd-MM-yyyy_HH-mm-ss').txt"
                <#if($Operation -like ''){
                    Out-PodeWebError -Message 'Please select atleast 1 operation'
                    return
                }#>
                $SelectedPackage = ($SelectedPackage -split ".zip")[0]
                $Parameters = "`"$deploymentsite`" `"$SelectedPackage`" `"$Operation`" `"$Site`" `"$Deploymenttype`" `"$path`" `"$query`" `"$DBName`" `"$query_order`" `"$crmoperation`" `'$s2i_integration_setting`'"               
                Write-Host $Parameters -BackgroundColor Blue
                $Scriptpath = "E:\WDX\Deployment_application\UBP\Functioncall_Existing_Sites_UBP.ps1" # ***** Change Path *****
                #$Scriptpath = "E:\WDX_Automation\Scripts\anusha\pode-deploy\deploment-script_new.ps1" # ***** Change Path *****
                $job = Start-Job -Name "Deploy" -ScriptBlock {
                param($Scriptpath,$Parameters)
                Invoke-Expression "$Scriptpath $Parameters"
                } -ArgumentList $Scriptpath,$Parameters
                #Receive-Job -Id $job.id -keep | Out-Default
                #$jobid = $job.Id
                $Path = "$path"
                Move-PodeWebPage -name 'Deployment result' -DataValue $path
                Reset-PodeWebForm -Name 'Select Environment & Site'
                Reset-PodeWebForm -Name 'Select package'
    
            } #-ArgumentList $packageloc

            
        )  
    }  
    Add-PodeWebPage -Name 'Deployment result' -Title '3.Deployment result' -NewTab -NoSidebar -NoBackArrow -ScriptBlock {
        Write-Host "3.Deployment result" -ForegroundColor Green
        
        $Path = $webevent.query['value']
        #$a = $webevent.query['value']
        Write-Host $Path -ForegroundColor Green
        #$Path = ($a -split ",")
        #$packageloc = ($a -split ",")[1]
        <#if(!$webevent.query['value']){
            # write-host "value is empty"
            New-PodeWebHeader -Value "Please submit WDX Deployment application form" -Size 3
            #return
        }#>
        $logpath = (($path) -split "public")[-1]
        New-PodeWebContainer -id "deploymentlog" -Content @(
            New-PodeWebFileStream -Name "Deployment Log" -Interval 1 -url "$($logpath)" -NoHeader -Height 100  #-path "E:\WDX_Automation\Scripts\anusha\pode-deploy\sample.txt" 
        )
        Write-Host $jobid
        New-PodeWebButton -Name Stopjob -Colour Red -Icon 'Stop-Circle' -DisplayName 'STOP DEPLOYMENT'-ScriptBlock {
        $job = Get-Job -Name "Deploy" | Sort-Object -Property Id -Descending | Select-Object -First 1
        $job | Remove-Job -Force
        Write-Host "$(Get-Date -Format 'dd-MM-yyyy HH:mm:ss') -- Job - $($job | out-string) Stopped"
        Show-PodeWebToast -Duration 9999999 -Message "Deployment intrupted" 
        #New-PodeWebAlert -Type Warning -Content @(
        #New-PodeWebText -Value 'Deployment Intrupted!!!')
        #New-PodeWebContainer -id "deploymentlog" -Content @(
        #    New-PodeWebText -Value "Deployment Intrupted!!!"
        #)
       }
    } 
    Add-PodeWebPage -Name 'logged out' -Path '/logout' -Hide -NoBackArrow -IfExists Error -NoSidebar -ScriptBlock {
            $webevent.Session.Data.authenticated = $false
            $webevent.session.data.username = $null
            $webevent.session.data.extend = $false
            #New-PodeWebAlert -Type Info -Value "Logged out successfully"
            #$podepage = Get-PodeWebPage -Name '/1.Select Deployment Site'
            #$podepage.clear()
            #$podepage | Reset-PodeWebPage
            Reset-PodeWebForm -Name 'Select package'
            Move-PodeWebUrl -Url '/login' 
            $navlogin = New-PodeWebNavLink -Name 'login' -Url '/login'  
            Set-PodeWebNavDefault -Items $navlogin
            return
    }

<#    Add-PodeWebPage -Name 'All logs' -Path '/logs' -NewTab -Hide -NoBackArrow -NoTitle -IfExists Error -NoSidebar -ScriptBlock {
        New-PodeWebCard -Name 'Logs' -NoHide -Content @(
            $logs = (Get-ChildItem -Path "E:\WDX\Deployment_application\UBP\Public\Logs" | Sort-Object -Property lastwritetime -Descending).Name  # Change Path #
            New-PodeWebForm -Name 'Check all logs here' -Message "Refresh page if you have error and try again" -Content @(
                New-PodeWebSelect -Name 'LogsSite' -Options "FLW" , "USG" , "UCK" -Required
                New-PodeWebSelect -Name 'Logs' -Options $logs -Required
            ) -ScriptBlock {
                $logssite = $WebEvent.Data['LogsSite']
                $file = $WebEvent.Data['Logs']
                $logpath = "/logs/$logssite/$file"
                New-PodeWebFileStream -Name "Logs" -url $logpath -Interval 1 -Height 20 -Id "PreviousLogs" -
                Clear-PodeWebFileStream -Name "Logs" 
            }
        )
    }#>
    
#All logs  - update

Add-PodeWebPage -Name 'All logs site selection' -Path '/logssite' -NewTab -Hide -Middleware @($authmiddleware) -NoBackArrow -NoSidebar -ScriptBlock {
    New-PodeWebCard -Name 'Logs site' -NoHide -Content @(
        New-PodeWebForm -Name 'Check all logs here' -Message "Refresh the page if there is an error" -Content @(
            New-PodeWebSelect -Name 'Logs site' -Options 'FLW' , 'USG' , 'UCK' -Required
            #New-PodeWebSelect -Name 'Logs' -Options $logs -Required
        ) -ScriptBlock {
            $logsSite = $WebEvent.Data['Logs site']
            Write-host $logsSite -BackgroundColor DarkRed
            Move-PodeWebPage -Name 'All logs' -DataValue $logsSite
            Reset-PodeWebForm -Name 'Check all logs here'
            Reset-PodeWebForm -Name 'Display the log file'             
        }
    )
}
Add-PodeWebPage -Name 'All logs' -Hide -Middleware @($authmiddleware) -NoBackArrow -NoSidebar -ScriptBlock {
    New-PodeWebCard -Name 'Logs' -NoHide -Content @(
        $logsSite = $webevent.query['value']
        write-host $logsSite -BackgroundColor DarkGreen
        $logs = (Get-ChildItem -Path "E:\WDX\Deployment_application\UBP\Public\Logs\$logsSite" | Sort-Object -Property lastwritetime -Descending).Name  # Change Path #
            New-PodeWebForm -Name 'Display the log file' -Message "Refresh the page if there is an error" -Content @(
                New-PodeWebSelect -Name 'Log file' -Options $logs -Required
                ) -ScriptBlock {
                    #param($logsSite)
                    $logsSite = $webevent.query['value']
                    $file = $WebEvent.Data['Log file']
                    $logpath = "/logs/$logsSite/$file"
                    Write-Host $logpath -BackgroundColor DarkYellow
                    Write-Host $logsSite -BackgroundColor DarkYellow
                    New-PodeWebFileStream -Name "Logs" -url $logpath -Interval 1 -Height 20 -Id "PreviousLogs" -NoHeader
                    Clear-PodeWebFileStream -Name "Logs"
                    Reset-PodeWebForm -Name 'Check all logs here'
                } #-ArgumentList $logsSite   
    )
}

# WDX Dashboard Version

$path = "E:\WDX\UBP_Dashboard\Output_json"
    Add-PodeWebPage -Name 'WDX Dashboard Version' -Path '/Version' -NewTab -Hide -Middleware @($authmiddleware) -NoBackArrow -NoSidebar -ScriptBlock {
        param($path)
        New-PodeWebHeader -Size 3 -Value $(Get-Date -Format 'dd-MM-yyyy HH:mm:ss')
        New-PodeWebCard -Name "WDX Dashboard Version" -Content @(
            New-PodeWebTable -Name "WDX Dashboard Version" -AutoRefresh -Paginate -ScriptBlock {
                param($path)
                $Version = Get-Content -path "$path\Version.json" | ConvertFrom-Json
                $Version | foreach-object {
                    [pscustomobject]@{
                    Site = "$($_.Site)"                 
                    Version = "$($_.Version)"
                    }
                } 
            } -ArgumentList $path
        )
    } -ArgumentList $path 

 
}
