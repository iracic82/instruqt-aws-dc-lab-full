# Configure WinRM and Firewall for Ansible on Windows Server
$ErrorActionPreference = "Stop"

# --- Generate self-signed certificate for HTTPS WinRM ---
$cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My
$pwd = ConvertTo-SecureString -String "P@ssword123" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath "C:\winrm.pfx" -Password $pwd

# --- Enable WinRM QuickConfig (HTTP, for lab/testing) ---
winrm quickconfig -force

# --- Set up WinRM HTTPS listener ---
$thumbprint = $cert.Thumbprint
# Remove default HTTPS listeners if any
Get-ChildItem WSMan:\Localhost\Listener | Where-Object { $_.Keys -like '*Transport=HTTPS*' } | Remove-Item -Force
# Create new HTTPS listener
winrm create winrm/config/Listener?Address=*+Transport=HTTPS "@{Hostname=`"$env:COMPUTERNAME`"; CertificateThumbprint=`"$thumbprint`"}"

# --- Allow Ansible connections ---
Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true
Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $true
Set-Item -Path WSMan:\localhost\Client\TrustedHosts -Value '*'

# --- Open Firewall Ports ---
New-NetFirewallRule -DisplayName "WinRM HTTP"  -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5985
New-NetFirewallRule -DisplayName "WinRM HTTPS" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5986
New-NetFirewallRule -DisplayName "RDP"         -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3389

# --- Optional: Restart WinRM service for good measure ---
Restart-Service winrm -Force
