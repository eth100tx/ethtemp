# Quick test for on-premises AD
Import-Module ActiveDirectory -ErrorAction SilentlyContinue
if ($?) {
    Write-Host "✅ Active Directory module available"
    # Test getting a user
    $testUser = Read-Host "Enter domain username to test"
    try {
        $user = Get-ADUser $testUser -Properties LockedOut
        Write-Host "User found: $($user.Name)"
        Write-Host "Locked out: $($user.LockedOut)"
    } catch {
        Write-Host "❌ Cannot access on-premises AD: $($_.Exception.Message)"
    }
} else {
    Write-Host "❌ Active Directory module not available"
}
