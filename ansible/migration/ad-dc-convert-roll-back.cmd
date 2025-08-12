

:: Rollback Procedures

:: Stop the DNS Service
net stop dns

:: Import the backup of zones.  This Zones.reg file was created during the go-live.
:: This file contains all zones and their paramerters.  Zone data and records are in the AD DNS Partition.
reg import Zones.reg

:: Import the DnsSettings.  This is the DnsSettings.reg file that was created during the go-live.
:: This file contains the DNS Server Settings
reg import DnsSettings.reg

:: Start the DNS service
net start DNS

:: Stop the netlogon service
net stop netlogon

:: Start the netlogon service
net start netlogon
