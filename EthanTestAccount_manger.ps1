# Simple Account Manager for EthanTestAccount
# Handles both Azure AD and On-Premises AD

param(
    [string]$UserName = "EthanTestAccount"
)

Write-Host "Account Manager for: $UserName" -ForegroundColor Green
Write-Host "=" * 40

function Check-AccountStatus {
    param([string]$User)
    
    Write-Host "`nChecking account status..." -ForegroundColor Yellow
    
    # Check On-Premises AD first
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $adUser = Get-ADUser $User -Properties LockedOut, Enabled, LastLogonDate, BadLogonCount -ErrorAction Stop
        
        Write-Host "`n[ON-PREMISES AD]" -ForegroundColor Cyan
        Write-Host "Display Name: $($adUser.Name)"
        Write-Host "Enabled: $($adUser.Enabled)" -ForegroundColor $(if($adUser.Enabled) {"Green"} else {"Red"})
        Write-Host "Locked Out: $($adUser.LockedOut)" -ForegroundColor $(if($adUser.LockedOut) {"Red"} else {"Green"})
        Write-Host "Last Logon: $($adUser.LastLogonDate)"
        Write-Host "Bad Logon Count: $($adUser.BadLogonCount)"
        
        $onPremAvailable = $true
    } catch {
        Write-Host "`n[ON-PREMISES AD] ❌ Not available: $($_.Exception.Message)" -ForegroundColor Red
        $onPremAvailable = $false
    }
    
    # Check Azure AD
    try {
        # Try to connect to Microsoft Graph
        $graphConnection = Get-MgContext -ErrorAction SilentlyContinue
        if (-not $graphConnection) {
            Connect-MgGraph -Scopes "User.ReadWrite.All" -NoWelcome -ErrorAction Stop
        }
        
        # Look for user by display name or UPN
        $azureUser = $null
        
        # Try as display name first
        $azureUser = Get-MgUser -Filter "displayName eq '$User'" -ErrorAction SilentlyContinue
        
        # If not found, try as UPN (might need domain)
        if (-not $azureUser) {
            $domain = (Get-WmiObject Win32_ComputerSystem).Domain
            $upn = "$User@$domain"
            $azureUser = Get-MgUser -UserId $upn -ErrorAction SilentlyContinue
        }
        
        # Try just the username as UPN
        if (-not $azureUser) {
            $azureUser = Get-MgUser -UserId $User -ErrorAction SilentlyContinue
        }
        
        if ($azureUser) {
            Write-Host "`n[AZURE AD]" -ForegroundColor Cyan
            Write-Host "Display Name: $($azureUser.DisplayName)"
            Write-Host "UPN: $($azureUser.UserPrincipalName)"
            Write-Host "Account Enabled: $($azureUser.AccountEnabled)" -ForegroundColor $(if($azureUser.AccountEnabled) {"Green"} else {"Red"})
            Write-Host "User ID: $($azureUser.Id)"
            
            $azureAvailable = $true
        } else {
            Write-Host "`n[AZURE AD] ⚠️ User not found in Azure AD" -ForegroundColor Yellow
            $azureAvailable = $false
        }
        
    } catch {
        Write-Host "`n[AZURE AD] ❌ Not available: $($_.Exception.Message)" -ForegroundColor Red
        $azureAvailable = $false
    }
    
    return @{
        OnPremAvailable = $onPremAvailable
        AzureAvailable = $azureAvailable
        ADUser = $adUser
        AzureUser = $azureUser
    }
}

function Lock-Account {
    param([string]$User, [hashtable]$Status)
    
    Write-Host "`nLocking account..." -ForegroundColor Yellow
    
    # Lock on-premises AD
    if ($Status.OnPremAvailable) {
        try {
            # Disable the account
            Disable-ADAccount -Identity $User
            Write-Host "✅ On-premises AD account disabled" -ForegroundColor Green
        } catch {
            Write-Host "❌ Failed to disable on-premises AD account: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    # Lock Azure AD
    if ($Status.AzureAvailable -and $Status.AzureUser) {
        try {
            Update-MgUser -UserId $Status.AzureUser.Id -AccountEnabled:$false
            Write-Host "✅ Azure AD account disabled" -ForegroundColor Green
        } catch {
            Write-Host "❌ Failed to disable Azure AD account: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

function Unlock-Account {
    param([string]$User, [hashtable]$Status)
    
    Write-Host "`nUnlocking account..." -ForegroundColor Yellow
    
    # Unlock on-premises AD
    if ($Status.OnPremAvailable) {
        try {
            # Enable the account
            Enable-ADAccount -Identity $User
            # Unlock if locked
            Unlock-ADAccount -Identity $User
            Write-Host "✅ On-premises AD account enabled and unlocked" -ForegroundColor Green
        } catch {
            Write-Host "❌ Failed to unlock on-premises AD account: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    # Unlock Azure AD
    if ($Status.AzureAvailable -and $Status.AzureUser) {
        try {
            Update-MgUser -UserId $Status.AzureUser.Id -AccountEnabled:$true
            Write-Host "✅ Azure AD account enabled" -ForegroundColor Green
        } catch {
            Write-Host "❌ Failed to enable Azure AD account: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# Main script execution
try {
    # Check current status
    $accountStatus = Check-AccountStatus -User $UserName
    
    if (-not $accountStatus.OnPremAvailable -and -not $accountStatus.AzureAvailable) {
        Write-Host "`n❌ Cannot access either on-premises AD or Azure AD" -ForegroundColor Red
        Write-Host "Make sure you have the required permissions and modules installed" -ForegroundColor Yellow
        exit 1
    }
    
    # Show menu
    Write-Host "`n" + "=" * 40
    Write-Host "What would you like to do?" -ForegroundColor Green
    Write-Host "1. Refresh Status"
    Write-Host "2. Lock Account"
    Write-Host "3. Unlock Account"
    Write-Host "4. Exit"
    
    $choice = Read-Host "`nEnter your choice (1-4)"
    
    switch ($choice) {
        "1" {
            Write-Host "`nRefreshing..." -ForegroundColor Yellow
            $accountStatus = Check-AccountStatus -User $UserName
        }
        "2" {
            $confirm = Read-Host "`nAre you sure you want to LOCK the account? (y/N)"
            if ($confirm -eq 'y' -or $confirm -eq 'Y') {
                Lock-Account -User $UserName -Status $accountStatus
                Write-Host "`nRefreshing status..." -ForegroundColor Yellow
                Start-Sleep 2
                Check-AccountStatus -User $UserName | Out-Null
            } else {
                Write-Host "Lock cancelled" -ForegroundColor Yellow
            }
        }
        "3" {
            $confirm = Read-Host "`nAre you sure you want to UNLOCK the account? (y/N)"
            if ($confirm -eq 'y' -or $confirm -eq 'Y') {
                Unlock-Account -User $UserName -Status $accountStatus
                Write-Host "`nRefreshing status..." -ForegroundColor Yellow
                Start-Sleep 2
                Check-AccountStatus -User $UserName | Out-Null
            } else {
                Write-Host "Unlock cancelled" -ForegroundColor Yellow
            }
        }
        "4" {
            Write-Host "Goodbye!" -ForegroundColor Green
            exit 0
        }
        default {
            Write-Host "Invalid choice" -ForegroundColor Red
        }
    }
    
} catch {
    Write-Host "`n❌ Script error: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    # Clean up Graph connection
    try {
        if (Get-MgContext) {
            Disconnect-MgGraph | Out-Null
        }
    } catch {
        # Ignore cleanup errors
    }
}

Write-Host "`nScript completed. Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
