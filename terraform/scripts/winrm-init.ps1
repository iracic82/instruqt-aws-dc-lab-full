<powershell>
Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*'
Enable-PSRemoting -Force
winrm quickconfig -force
winrm set winrm/config/service/auth @{Basic="true"}
winrm set winrm/config/service @{AllowUnencrypted="true"}
</powershell>
