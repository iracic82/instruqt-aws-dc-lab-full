<powershell>
$ErrorActionPreference = "Stop"
Start-Transcript -Path "C:\user_data.log" -Append

Write-Host "---- Starting Windows EC2 user_data ----"

# --- Step 1: Wait for network stack to be ready ---
Write-Host "Waiting for network..."
Start-Sleep -Seconds 30

# --- Step 2: Set Administrator password ---
Write-Host "Setting Administrator password..."
$AdminPassword = ConvertTo-SecureString "${admin_password}" -AsPlainText -Force
Set-LocalUser -Name "Administrator" -Password $AdminPassword
Set-LocalUser -Name "Administrator" -PasswordNeverExpires $true

# --- Step 3: Generate self-signed cert for HTTPS WinRM (optional fallback) ---
Write-Host "Generating self-signed certificate..."
$cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My
$pwd = ConvertTo-SecureString -String "P@ssword123" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath "C:\winrm.pfx" -Password $pwd

# --- Step 4: Configure WinRM (HTTP & HTTPS listener) ---
Write-Host "Configuring WinRM..."
try {
    winrm quickconfig -force
    Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true
    Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $true
    Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value "*"
} catch {
    Write-Host "WinRM setup failed: $_"
}

# --- Step 5: Set DNS client to internal DC1 IP ---
Write-Host "Setting DNS to 10.100.1.100..."
try {
    $interface = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
    Set-DnsClientServerAddress -InterfaceIndex $interface.InterfaceIndex -ServerAddresses ("10.100.1.100")
} catch {
    Write-Host "DNS config failed: $_"
}

# --- Step 6: Create HTTPS listener manually ---
Write-Host "Creating WinRM HTTPS listener..."
try {
    $thumbprint = $cert.Thumbprint
    Get-ChildItem WSMan:\Localhost\Listener | Where-Object { $_.Keys -like '*Transport=HTTPS*' } | Remove-Item -Force -ErrorAction SilentlyContinue
    winrm create winrm/config/Listener?Address=*+Transport=HTTPS "@{Hostname=`"$env:COMPUTERNAME`"; CertificateThumbprint=`"$thumbprint`"}"
} catch {
    Write-Host "HTTPS Listener creation failed: $_"
}

# --- Step 7: Open required firewall ports ---
Write-Host "Creating firewall rules..."
$firewallRules = @(
    @{ Name = "WinRM HTTP";  Port = 5985 },
    @{ Name = "WinRM HTTPS"; Port = 5986 },
    @{ Name = "RDP";         Port = 3389 }
)

foreach ($rule in $firewallRules) {
    try {
        New-NetFirewallRule -DisplayName $rule.Name -Direction Inbound -Action Allow -Protocol TCP -LocalPort $rule.Port -ErrorAction Stop
    } catch {
        Write-Host "Firewall rule '$($rule.Name)' failed: $_"
    }
}

# --- Step 8: Restart WinRM ---
Write-Host "Restarting WinRM service..."
Restart-Service winrm -Force

Write-Host "---- Finished Windows EC2 user_data ----"
Stop-Transcript
</powershell>
