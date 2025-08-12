:: Stop DNS Service
net stop dns

:: Export Zones and their parameters.  Zone data and records are in the AD DNS Partition.
reg export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones" Zones.reg

:: Export DNS Server Settings
reg export "HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters" DnsSettings.reg

:: Make a backup withing the registry of DNS zones and their settings
reg copy "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones" "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\ZonesBackup" /s /f

:: Delete all zones and their settings from the registery.  Zone data and records are in the AD DNS Poartition
reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones" /f

:: Change DNS Boot Method
:: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/dc737abd-3e84-4814-a62a-9398c770f28f
:: –    0    Clears the source of configuration information.
:: –    1    Loads from the BIND file that is located in the DNS directory, which is %systemroot%\System32\DNS by default.
:: –    2    Loads from the registry.   
:: –    3    Loads from AD DS and the registry. This is the default setting.

reg add "HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters" /v BootMethod /d 2 /t REG_DWORD /f


:: Update DNS Server Setting applying new forwarders
reg add "HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters" /v Forwarders /d N.N.N.N\0N.N.N.N /t REG_MULTI_SZ /f

:: Start DNS Service
net start dns

:: Stop netlogon service
net stop netlogon

:: Start netlogon service
net start netlogon

:: ###################### From Different File / Script #######################
::
:: Add Zones of Type Secondary Here
::
:: ##################### AD DC DNS Server Conversion Complete ################
