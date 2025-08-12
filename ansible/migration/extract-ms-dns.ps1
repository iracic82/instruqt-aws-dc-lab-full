 <#
.NOTES
Copyright (C) 2019-2023 Infoblox Inc. All rights reserved.

Version: 1.9
	improve pre-processing to use System.IO.File to process line-by-line.
             Performance is vastly improved!
Version: 1.8
    add option to disable pre-processing (shifting load requires preprocessing.pl)
Version: 1.7
    create clean named.conf with masters only

License: Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY INFOBLOX AND CONTRIBUTORS "AS IS" AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL INFOBLOX OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The views and conclusions contained in the software and documentation are
those of the authors and should not be interpreted as representing official
policies, either expressed or implied, of Infoblox.

.SYNOPSIS

Exports DNS configuration and zone data from Microsoft DNS Servers.

.DESCRIPTION

This tool extracts DNS configuration and zone data from a MS Windows DNS server.
It is designed to run on Windows DNS servers with the Powershell DnsServer module
installed. It executes a series of powershell commandlets for the server and for each
DNS zone defined on it. If all zones are AD-integrated, the tool can be run on
one server per AD domain. If there are non-integrated zones (e.g. slave zones or
non-integrated primary/stub/forwarder zones), the tool needs to be run against each
server configured with such zones.

The script can be run against remote Windows servers via the WinRM interface.
The WinRM service must be accessible in order for this to work, and access to
the hidden administrative file share (\\SERVER\ADMIN$) must be permitted.

Specify the -ComputerName parameter with a comma-delimited list of Windows DNS
server names, and the script will connect to those servers and extract the DNS
data. The script also has a DiscoverServers paramter, which when set to $true,
performs a query for all the Windows Domain Controllers listed in the Active
Directory Forest and automatically collects data from any server it can reach.

For each server specified, a directory is created in the current working
directory containing a set of configuration and data files for each one.

It is recommended to run this script on Windows Server 2012 R2 or later (Server
2016 is preferred). The DNS servers themselves do not need to be running this
version. Just the computer on which the script is running should be. The
Powershell DNSServer module must also be installed. To determine whther the
DHCPServer module is installed, run the following PS commandlet:

    Get-Module -ListAvailable -Name DnsServer

To install the DNSServer module on a supported platform, run the following
Powershell commandlet:

    Add-WindowsFeature -Name DNS -IncludeManagementTools

For systems running earlier versions of Windows, the script should run provided
that Powershell 3.0 or higher is installed (5.0+ is recommended). In this case
it will use only the legacy dnscmd commands to extract data, and additional
statistical information that can be retrieved from Powershell will not be
available.

The following steps/commands are executed to export the data:

- Use Get-Service to see if DNS is installed and check that it is 'Running'.

- Execute Invoke-Command with a script block to prepare the
  %WINDIR%\system32\dns directory for the data dump. A new directory,
  'ib_export', is created. The directory is removed if it already exists. The
  script block also contains a few lines to export the DNS services Registry
  keys.

- Call Get-DnsServer and Get-DnsServerStatistics to collect information about
  the server.

- Execute a WMI query to obtain a list of zones, and for each zone perform the
  following:

    - Output relevant entries for each zone in the zonelist.csv, named.conf,
      zonerestore.bat, zonedelete.bat, and info.txt files.

    - Execute dnscmd /zoneinfo - This is for some legacy scripts.

    - If the zone type is Primary, call Export-DnsServerZone to export the zone
      records to text files. Export-DnsServerZone writes the files under the
      %WINDIR%\system32\dns directory on the remote machine.

- Export-DnsServerZone does not create the data files on the local machine, so
  the script will use the ADMIN$ network share to copy the zone data files from
  the remote machine to the local one using Copy-Item.

- For each zone data file downloaded, the script performs some preprocessing to
  help with the data migratioun steps later.


PLEASE NOTE - To enable script execution on the server run:

    set-executionpolicy remotesigned

    Or:

    Unblock-File extract-ms-dns.ps1

To run this tool perform the following steps:
    1 - Log on to a Windows server.
    2 - Run Powershell as an Administrator.
    3 - CD to a writible directory where the output files are to be stored.
    4 - Run the script.
    5 - Examine output for errors.
    5 - Zip and send all files created in the local directory.

.PARAMETER ComputerName

Specifies a comma-delimited list of servers to export data. Either FQDN or IP
address can be used. This parameter can be combined with DiscoverServers. The default is
to extract data from the local server, only.

.PARAMETER DiscoverServers

When set to $true, get a list of all Domain Controllers from Active Directory, export
their data, and save it to files on the local filesystem. The default is $false,
where only data from the local server is exported.

.PARAMETER PreProcessing

When set to $false, preprocessing of zones will be disabled.  Disabling preprocessing
of large exports requires the use of preprocessing.pl in your lab.    The default is $true, 
preprocessing of zone exports is enabled.

.OUTPUTS

The script creates a folder for each server processes where it outputs the following files.

    - servername-logfile.txt - log of the data export process.
    - servername-serverinfo.txt - ouput of the dnscmd /info command.
    - servername-zonelist.csv - CSV file containing info for the DNS zones.
    - servername-server-stats.txt - Various DNS statistics for this server.
    - servername-named.conf - a BIND-style configuration file used during data import.
    - servername-zonerestore.bat - to be executed in the lab to load the zones for testing.
    - servername-zonedelete.bat - to be executed in the lab to remove the zones and reset the server.
    - servername-zones.reg - export of the DNS Server Zones registry key
    - servername-dnsparameters.reg - export of the DNS Server DNS Parameters registry key
    - zonename-info.txt - dnscmd /zoneinfo output for each zone defined.
    - zonename.dns - raw zone data exported from dnscmd /zoneexport for each zone.
    - zonename.db - pre-processed zone export data for each zone used during data import.

where 'servername' is the name of the computer running this script
and 'zonename' is the name of the DNS zone.

#>

#We need PS version 3 or higher
#Requires -Version 3

#define script params
param (
    [string]$ComputerName = '',
    [bool]$DiscoverServers = $false,
    [bool]$PreProcessing = $true
)

#define some globals
#
#  define where to store dns backup files
$ExportDir='ib_export'
$logfile='extract-ms-dns-logfile.txt'

#
#define logging function
function LogMessage ( [string] $text ) {
    Write-Host $text
    Add-Content $logfile $text
}
#
#define failure function
function Failure ( [string] $text )    {
    Write-Host -BackgroundColor:Black -ForegroundColor:Red $text
    Add-Content $logfile $text
    break
}

#check if the DnsServer module is installed
$dnsmod = Get-Module -ListAvailable -Name DnsServer
if ( ! $dnsmod ) {
    Failure("`nERROR: DnsServer module not detected. Please install the DnsServer module.")

}


#This will hold the list of servers to get data
$dns_servers = @()

#If a ComputerName was specified we only work on those machines
if ( $ComputerName ) {

    foreach ( $CmpName in $ComputerName.split(' ') ) {

        #use computername as a placeholder for IPAddress
        $IPaddr = $CmpName

        #try to lookup the IP using DNS
        $dnsresp = [System.Net.Dns]::GetHostAddresses($CmpName)
       foreach ($dnsobj in  $dnsresp )
       {
	        if ($dnsobj.AddressFamily -eq "InterNetwork")
	        {
		        $IPaddr = $dnsobj.IPAddressToString;
		        break;
	        }

        }

        $server = @{ DnsName = $CmpName; IPAddress = $IPaddr }
        $dns_servers += New-Object PSObject -Property $server

    }
}

#if the DiscoverServers param was flagged, pull data from AD
if ( $DiscoverServers ) {

	$forest = [DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()

	ForEach ($domain in $forest.domains)
	{
        if ( ! $domain.DomainControllers ) {
            Failure("ERROR: Forest returned empty Domain Controller list. Maybe you need to upgrade Powershell?")
        }

		foreach ($server in $domain.DomainControllers)
		{
			$CmpName = $server.name

            #use computername as a placeholder for IPAddress
            $IPaddr = $CmpName

            #try to lookup the IP addresses
            $dnsresp = [System.Net.Dns]::GetHostAddresses($CmpName)
            foreach ($dnsobj in  $dnsresp )
            {
                 if ($dnsobj.AddressFamily -eq "InterNetwork")
                 {
                     $IPaddr = $dnsobj.IPAddressToString;
                     break;
                 }

             }

             $server = @{ DnsName = $CmpName; IPAddress = $IPaddr }
             $dns_servers += New-Object PSObject -Property $server

		}
	}


}

if ( -not $DiscoverServers -and -not $ComputerName ) {
    #just pull data from the local host
    $ipaddr = ''

    try {
        #let see if we can guess the correct IP based on the default route using the PS modules
        $defif = Get-NetRoute | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' }
        $defaddr = Get-NetIPAddress | Where-Object { $_.ifIndex -eq $defif.ifIndex  -and $_.AddressFamily -eq 'IPv4' }
        $ipaddr = $defaddr.IPAddress
    }
    catch {
        #the right PS modules not available, so just use the loopback
        $ipaddr = '127.0.0.1'
    }

    # get the server name
    $DNSSERVER=Get-Content env:computername

    $server = @{ DnsName = $DNSSERVER; IPAddress = $ipaddr }
    $dns_servers += New-Object PSObject -Property $server

}


#
#define some enumerators
$zonetypes = @( '', 'Primary', 'Secondary', 'Stub', 'Forwarder' )
$sec_secondaries = @( 'Any', 'NStab', 'List', 'None' )
$notify_types = @( 'None', 'NStab', 'List'  )
$allow_update = @( 'None', 'Any', 'Secure' )
#list of fields in the zonelist CSV
$zonelistfields = @( 'Name','ZoneType','MasterServers','SecureSecondaries','SecondaryServers','NotifyServers','LocalMasterServers','ForwarderSlave','DsIntegrated','AllowUpdate','Notify','UseWins','DataFile' )

#list of fields to keep from the pPowershell outputs
# $srvinfofields = @( 'ServerSetting', 'ServerForwarder', 'ServerZone', 'Stub', 'Forwarder' )


foreach ( $server in $dns_servers) {


    $DNSSERVER = $server.DnsName
    $ipaddr = $server.IPAddress

    $DNSSERVER=$DNSSERVER.Tolower()


    $OutputDir=$DNSSERVER+'_'+$ExportDir
    $logfile = Join-Path -Path $OutputDir -ChildPath "$DNSSERVER-logfile.txt"
    $errorvar = ''

    # delete data if previous backup has been performed
    if( Test-Path -Path $OutputDir ){
        Write-Host "Deleting export folder for server $DNSSERVER"
        rm -force -recurse $OutputDir -ErrorVariable errorvar
    }

    #check for error
    if ( $errorvar ) {
        #There was an error, so fail
        Failure('ERROR: '+$errorvar)

    }

    #re-create the folder
    Write-Host "Creating export folder for server $DNSSERVER"
    mkdir -force $OutputDir -ErrorVariable errorvar

    #check for error
    if ( -not $? ) {
        #there was an error, so break
        Failure("ERROR: Could not create directory $OutputDir")

    }

    LogMessage("Exporting data for server: $DNSSERVER")

    #check if DNS is installed
    $errorvar = ''
    $dnssrv = Get-Service -Name DNS -ErrorVariable errorvar -ComputerName $DNSSERVER
    if ( $errorvar ) {

        LogMessage("`nServer is offline or DNS Service not installed on host: $DNSSERVER.")

        continue
    }

    #check if DNS is running
    if ( $dnssrv.Status -ne 'Running' ) {
        #DNS not running. So go to the next one

        LogMessage("`nDNS Service not running on host: $DNSSERVER.")

        continue

    }


    #first we need to do some work on the remote machine
    $errorvar = ''
    Invoke-Command -ComputerName $DNSSERVER -ErrorVariable errorvar -ScriptBlock {


        $rmtdir = "$env:WINDIR\system32\dns\$Using:ExportDir"

        $errorvar = ''
        # delete data if previous backup has been performed
        if( Test-Path -Path $rmtdir ){
            Write-Host "Deleting export folder on server: $Using:DNSSERVER"
            rm -force -recurse $rmtdir -ErrorVariable errorvar
        }

        #check for error
        if ( $errorvar ) {
            #There was an error, so fail
            break
        }

        #re-create the folder
        Write-Host "Creating export folder on server: $Using:DNSSERVER"
        mkdir -force $rmtdir -ErrorVariable errorvar

        #check for error
        if ( -not $? ) {
            #there was an error, so break
            Write-Host -BackgroundColor:Black -ForegroundColor:Red "ERROR: Could not create directory $rmtdir"
            break

        }

        #while we are here, export the two registry keys
        Write-Host "Exporting DNS Registry keys on server: $Using:DNSSERVER"
        reg export 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones' "$rmtdir\$Using:DNSSERVER-zones.reg"
        reg export 'HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters' "$rmtdir\$Using:DNSSERVER-dnsparameters.reg"

    }

    #check for error
    if ( $errorvar ) {
        #There was an error, so continue
        LogMessage('ERROR: '+$errorvar)
        continue

    }


    #setup some variables for output files
    $srvinfofile = $OutputDir+'\'+$DNSSERVER+'-serverinfo.txt'
    $serverstatsfile = $OutputDir+'\'+$DNSSERVER+'-server-stats.txt'

    #prep the zonelist file
    $zonelistfile = $OutputDir+'\'+$DNSSERVER+'-zonelist.csv'

    #output a few more files for import and validation
    $namedconf = $OutputDir+'\'+$DNSSERVER+'-named.conf'
    $zonedel = $OutputDir+'\'+$DNSSERVER+'-zonedelete.bat'
    $zonerst = $OutputDir+'\'+$DNSSERVER+'-zonerestore.bat'

    ## dbotham 20200514: Create a clean 'masters only' named.conf file used
    ## for loading data into bind without the need to edit the file.
    $bindLoadNamedconf = $OutputDir+'\'+$DNSSERVER+'-bind-load-named.conf'

    #get the server info
    LogMessage('Collecting info for server: '+$DNSSERVER)


    $errorvar = ''

    #Get the DNS Server object
    $serverinfo = Get-DnsServer -ComputerName $DNSSERVER

    if ( $errorvar ) {
        #There was an error, so log the error and continue
        LogMessage($errorvar)
        continue

    }


    #output server settings to serverinfo file
    $serverinfo.ServerSetting > $srvinfofile

    #check for error
    if ( -not $? ) {
        #There was an error, so fail
        Failure('ERROR: Failed to write serverinfo')

    }



    #output forwarders
    Add-Content $srvinfofile 'Forwarders:'
    $serverinfo.ServerForwarder >> $srvinfofile

    #check for error
    if ( -not $?  ) {
        #There was an error, so fail
        Failure('ERROR: Failed to write serverinfo')

    }


    #get server stats
    $errorvar = ''
    $srvstats = Get-DnsServerStatistics -ComputerName $DNSSERVER

    #output server stats
    $srvstats > $serverstatsfile

    #check for error
    if ( -not $? ) {
        #There was an error, so fail
        Failure('ERROR: Could not write serverstatsfile')

    }

#make header for named.conf
$namedheader = @"
acl GSS-TSIG { any; };
acl NStab { any; };
options {
    directory ".";
    recursion yes;
    notify no;
    pid-file "named.pid";
    allow-transfer {  any; };
    check-names master ignore;
};

logging {
         channel default_syslog {
                 file "syslog";
                 severity info;
                 print-time yes;
         };


         category default { default_syslog; };
         category general { default_syslog; };
         category security { default_syslog; };
         category config { default_syslog; };
         category resolver { default_syslog; };
         category xfer-in { default_syslog ; };
         category xfer-out { default_syslog ; };
         category notify { default_syslog ; };
         category client { default_syslog ; };
         category network { default_syslog ; };
         category update { default_syslog ; };
         category lame-servers { default_syslog; };

};

"@

    Add-Content $namedconf $namedheader -ErrorVariable errorvar

    #check for error
    if ( $errorvar ) {
        #There was an error, so fail
        Failure('ERROR: '+$errorvar)

    }

    ## dbotham 20200514: Write header info to clean masters only
    ## named.conf file.
    Add-Content $bindLoadNamedconf $namedheader -ErrorVariable errorvar

    #check for error
    if ( $errorvar ) {
        #There was an error, so fail
        Failure('ERROR: '+$errorvar)

    }


    #get list of dns zones from WMI object
    $zonelist = gwmi -Namespace root\MicrosoftDNS -Class MicrosoftDNS_Zone  -ComputerName $DNSSERVER -ErrorVariable errorvar | sort ZoneType

    #check for error
    if ( $errorvar ) {
        #There was an error, so fail
        Failure('ERROR: '+$errorvar)

    }

    $zonetable = @()

    foreach ($zoneobj in $zonelist  ) {

        #init the output
        $zone = [ordered]@{}
        $errorvar = ''

        #grab the values we want
        foreach ( $fld in $zonelistfields ) {
            $zone.$fld = $zoneobj.$fld
        }

        $zonename = $zone.Name

        if ( $zonename -eq 'TrustAnchors' ) {
            #skip TrustAnchors
            continue
        }
        elseif ( $zonename -match '127\.in\-addr\.arpa$' ) {
           #skip loopback zone
            continue
        }

        #enumerate the zone type
        $zone.ZoneType = $zonetypes[$zone.ZoneType]

        #enumerate the securesecondaries
        $zone.SecureSecondaries = $sec_secondaries[$zone.SecureSecondaries]

        #enumerate the updates
        $zone.AllowUpdate = $allow_update[$zone.AllowUpdate]

        #enumerate the notify type
        $zone.Notify = $notify_types[$zone.Notify]

        #compute masters list
        $masters = $zone.MasterServers -join '; '
        $dnscmd_masters = $zone.MasterServers -join ' '
        $zone.MasterServers = $zone.MasterServers -join ';'
        $zone.LocalMasterServers = $zone.LocalMasterServers -join ';'

        #computer allow-transfer list
        $slaves = $zone.SecondaryServers -join '; '
        $zone.SecondaryServers = $zone.SecondaryServers -join ';'
        if ( $slaves -and $zone.SecureSecondaries -eq 'List' ) {

            $slaves = 'allow-transfer { '+$slaves+'; };'

        }
        elseif ( $zone.SecureSecondaries -eq 'NStab' ) {

            #For now we will treat this as a named ACL
            $slaves = 'allow-transfer { NStab; };'

        }

        #computer notifiers
        $notifies = $zone.NotifyServers -join '; '
        $zone.NotifyServers = $zone.NotifyServers -join '; '
        if ( $notifies -and $zone.Notify -eq 'List' ) {

            $notifies = 'also-notify { '+$notifies+'; };'

        }

        #compute updates
        $updates = ''
        if ( $zone.AllowUpdate -eq 'Any' ) {

            $updates = 'allow-update { any; };'

        }
        elseif ( $zone.AllowUpdate -eq 'Secure' ) {

            #for now treat this as a named ACL
            $updates = 'allow-update { GSS-TSIG; };'

        }

        #we will also exec dnscmd /zoneinfo for legacy reasons
        LogMessage("Getting info for zone: $zonename")
        $zoneinfo = dnscmd $DNSSERVER /zoneinfo $zonename

        # check for errors
        #if ( $zoneinfo[$zoneinfo.Length-2] -notmatch 'successfully' ) {
        #    #there was an error, so fail
        #    Failure($zoneinfo)
        #}

        #write the output to a file
        $zoneinfofile = $OutputDir+'\'+$zonename+'-info.txt'
        Add-Content $zoneinfofile $zoneinfo -ErrorVariable errorvar

        #check for error
        if ( $errorvar ) {
            #There was an error, so fail
            Failure('ERROR: '+$errorvar)

        }


        #add line to delete the zone
        if ( $zone.DsIntegrated ) {
            Add-Content $zonedel "dnscmd /zonedelete $zonename /DsDel /f" -ErrorVariable errorvar
        }
        else {
            Add-Content $zonedel "dnscmd /zonedelete $zonename /f" -ErrorVariable errorvar
        }

        #check for error
        if ( $errorvar ) {
            #There was an error, so fail
            Failure('ERROR: '+$errorvar)

        }


        #depending on the ZoneType output zone data
        switch( $zone.Zonetype ) {

            'Secondary' {

                #add line to restore the zone
                Add-Content $zonerst "dnscmd /zoneadd $zonename /secondary $dnscmd_masters" -ErrorVariable errorvar

                #check for error
                if ( $errorvar ) {
                    #There was an error, so fail
                    Failure('ERROR: '+$errorvar)

                }

                #add named.conf block
                $confblock = @"

zone "$zonename" in {
    type slave;
    masters { $masters; };
    file "$zonename.db";
	$slaves
    $notifies
};
"@
                Add-Content $namedconf $confblock -ErrorVariable errorvar

                #check for error
                if ( $errorvar ) {
                    #There was an error, so fail
                    Failure('ERROR: '+$errorvar)

                }

            }
            'Stub' {

                #add line to restore the zone
                if ( $zone.DsIntegrated ) {
                    Add-Content $zonerst "dnscmd /zoneadd $zonename /DsStub $dnscmd_masters" -ErrorVariable errorvar
                }
                else {
                    Add-Content $zonerst "dnscmd /zoneadd $zonename /Stub $dnscmd_masters" -ErrorVariable errorvar

                }



                #check for error
                if ( $errorvar ) {
                    #There was an error, so fail
                    Failure('ERROR: '+$errorvar)

                }

                #add named.conf block
                $confblock = @"

zone "$zonename" in {
    type stub;
    masters { $masters; };
    file "$zonename.db";
};
"@

                Add-Content $namedconf $confblock -ErrorVariable errorvar

                #check for error
                if ( $errorvar ) {
                    #There was an error, so fail
                    Failure('ERROR: '+$errorvar)

                }

            }
            'Forwarder' {

                $fwdonly = ''
                $fwdslave = ''
                if ( $zone.ForwarderSlave ) {

                    $fwdonly = 'forward only;'
                    $fwdslave = ' /Slave '

                }

                #add line to restore the zone
                if ( $zone.DsIntegrated ) {
                    Add-Content $zonerst "dnscmd /zoneadd $zonename /DsForwarder $dnscmd_masters $fwdslave" -ErrorVariable errorvar
                }
                else {
                    Add-Content $zonerst "dnscmd /zoneadd $zonename /Forwarder $dnscmd_masters $fwdslave" -ErrorVariable errorvar

                }



                #check for error
                if ( $errorvar ) {
                    #There was an error, so fail
                    Failure('ERROR: '+$errorvar)

                }

                #add named.conf block
                $confblock = @"

zone "$zonename" in {
    type forward;
    forwarders { $masters; };
    $fwdonly
};
"@
                Add-Content $namedconf $confblock



                #check for error
                if ( $errorvar ) {
                    #There was an error, so fail
                    Failure('ERROR: '+$errorvar)

                }

            }
            'Primary' {
                #export zone data for Primary zones
                LogMessage("Exporting zone data for zone: $zonename")


                $errorvar = ''
                Export-DnsServerZone -Name $zonename -FileName $ExportDir'\'$zonename'.dns' -ErrorVariable errorvar -ComputerName $DNSSERVER

                # check for errors
                if ( $errorvar ) {
                    #there was an er
                    Failure('ERROR:'+$errorvar)
                }


                #add line to restore the zone
                Add-Content $zonerst "dnscmd /zoneadd $zonename /Primary /file $zonename.dns /load"
                if ( $zone.DsIntegrated ) {
                    Add-Content $zonerst "dnscmd /zoneresettype $zonename /DsPrimary " -ErrorVariable errorvar
                }



                #check for error
                if ( $errorvar ) {
                    #There was an error, so fail
                    Failure('ERROR: '+$errorvar)

                }

                $confblock = @"

zone "$zonename" in {
    type master;
    file "$zonename.db";
    $slaves
    $updates
};
"@
                Add-Content $namedconf $confblock -ErrorVariable errorvar



                #check for error
                if ( $errorvar ) {
                    #There was an error, so fail
                    Failure('ERROR: '+$errorvar)

                }


                ## dbotham 20200514: write a clean masters only zone definition
                ## for this master zone...
                $mastersOnlyconfblock = @"

zone "$zonename" in {
    type master;
    file "$zonename.db";
};
"@
                Add-Content $bindLoadNamedconf $mastersOnlyconfblock -ErrorVariable errorvar

                #check for error
                if ( $errorvar ) {
                    #There was an error, so fail
                    Failure('ERROR: '+$errorvar)

                }

            }

        }

        #add it to the zone CSV output
        $zonetable += New-Object PSObject -Property $zone


}

    #write the zonelist to the CSV file
    $zonetable | Export-CSV $zonelistfile -NoTypeInformation -ErrorVariable errorvar
    #check for error
    if ( $errorvar ) {
        #There was an error, so fail
        Failure('ERROR: '+$errorvar)

    }


    #copy the export files to the local directory
    LogMessage("Copying files from server: $DNSSERVER")
    $adminuncpath = "\\$DNSSERVER\ADMIN$\System32\dns\$ExportDir\*"
    Copy-Item -Path $adminuncpath -Destination $OutputDir


    #walk through the .dns files and cleanout the [AGE] stamps
    $dnsfiles = Get-ChildItem -Path "$OutputDir\*.dns"

    if ( $PreProcessing ) {
        foreach ( $dnsfile in $dnsfiles ) {

            $dnsname = $dnsfile.Name
            $dbname = $dnsname -replace '\.dns$', '.db'


            $input_file = Join-Path "$(Get-Location)\$OutputDir" -ChildPath $dnsname
            $output_file = Join-Path "$(Get-Location)\$OutputDir" -ChildPath $dbname

            if (Test-Path $output_file) {
                Remove-Item $output_file
            }

            LogMessage("Pre-processing file $input_file")

            $reader = [System.IO.File]::OpenText($input_file)
            try {
                for() {
                    $line = $reader.ReadLine()
                    if ($null -eq $line) { break }
                    $mod = $line -replace '\[AGE:\d+\]\s+', ''
                    Write-Output($mod) | Out-File -Encoding ascii -Append -FilePath $output_file
                }   
            }
            finally {
                $reader.close()
            }

        }

        LogMessage("Finished processing $DNSSERVER")
    }
    else { 
        LogMessage("Pre-processing disabled for $DNSSERVER")
    }

}

# SIG # Begin signature block
# MIIpCwYJKoZIhvcNAQcCoIIo/DCCKPgCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUmPiZdFnEEG0w6FLZk5A0WcD4
# /duggg4bMIIGsDCCBJigAwIBAgIQCK1AsmDSnEyfXs2pvZOu2TANBgkqhkiG9w0B
# AQwFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVk
# IFJvb3QgRzQwHhcNMjEwNDI5MDAwMDAwWhcNMzYwNDI4MjM1OTU5WjBpMQswCQYD
# VQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lD
# ZXJ0IFRydXN0ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEg
# Q0ExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1bQvQtAorXi3XdU5
# WRuxiEL1M4zrPYGXcMW7xIUmMJ+kjmjYXPXrNCQH4UtP03hD9BfXHtr50tVnGlJP
# DqFX/IiZwZHMgQM+TXAkZLON4gh9NH1MgFcSa0OamfLFOx/y78tHWhOmTLMBICXz
# ENOLsvsI8IrgnQnAZaf6mIBJNYc9URnokCF4RS6hnyzhGMIazMXuk0lwQjKP+8bq
# HPNlaJGiTUyCEUhSaN4QvRRXXegYE2XFf7JPhSxIpFaENdb5LpyqABXRN/4aBpTC
# fMjqGzLmysL0p6MDDnSlrzm2q2AS4+jWufcx4dyt5Big2MEjR0ezoQ9uo6ttmAaD
# G7dqZy3SvUQakhCBj7A7CdfHmzJawv9qYFSLScGT7eG0XOBv6yb5jNWy+TgQ5urO
# kfW+0/tvk2E0XLyTRSiDNipmKF+wc86LJiUGsoPUXPYVGUztYuBeM/Lo6OwKp7AD
# K5GyNnm+960IHnWmZcy740hQ83eRGv7bUKJGyGFYmPV8AhY8gyitOYbs1LcNU9D4
# R+Z1MI3sMJN2FKZbS110YU0/EpF23r9Yy3IQKUHw1cVtJnZoEUETWJrcJisB9IlN
# Wdt4z4FKPkBHX8mBUHOFECMhWWCKZFTBzCEa6DgZfGYczXg4RTCZT/9jT0y7qg0I
# U0F8WD1Hs/q27IwyCQLMbDwMVhECAwEAAaOCAVkwggFVMBIGA1UdEwEB/wQIMAYB
# Af8CAQAwHQYDVR0OBBYEFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB8GA1UdIwQYMBaA
# FOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAK
# BggrBgEFBQcDAzB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9v
# Y3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4
# oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJv
# b3RHNC5jcmwwHAYDVR0gBBUwEzAHBgVngQwBAzAIBgZngQwBBAEwDQYJKoZIhvcN
# AQEMBQADggIBADojRD2NCHbuj7w6mdNW4AIapfhINPMstuZ0ZveUcrEAyq9sMCcT
# Ep6QRJ9L/Z6jfCbVN7w6XUhtldU/SfQnuxaBRVD9nL22heB2fjdxyyL3WqqQz/WT
# auPrINHVUHmImoqKwba9oUgYftzYgBoRGRjNYZmBVvbJ43bnxOQbX0P4PpT/djk9
# ntSZz0rdKOtfJqGVWEjVGv7XJz/9kNF2ht0csGBc8w2o7uCJob054ThO2m67Np37
# 5SFTWsPK6Wrxoj7bQ7gzyE84FJKZ9d3OVG3ZXQIUH0AzfAPilbLCIXVzUstG2MQ0
# HKKlS43Nb3Y3LIU/Gs4m6Ri+kAewQ3+ViCCCcPDMyu/9KTVcH4k4Vfc3iosJocsL
# 6TEa/y4ZXDlx4b6cpwoG1iZnt5LmTl/eeqxJzy6kdJKt2zyknIYf48FWGysj/4+1
# 6oh7cGvmoLr9Oj9FpsToFpFSi0HASIRLlk2rREDjjfAVKM7t8RhWByovEMQMCGQ8
# M4+uKIw8y4+ICw2/O/TOHnuO77Xry7fwdxPm5yg/rBKupS8ibEH5glwVZsxsDsrF
# hsP2JjMMB0ug0wcCampAMEhLNKhRILutG4UI4lkNbcoFUCvqShyepf2gpx8GdOfy
# 1lKQ/a+FSCH5Vzu0nAPthkX0tGFuv2jiJmCG6sivqf6UHedjGzqGVnhOMIIHYzCC
# BUugAwIBAgIQDWuNXCs47NdhEBBXovjiajANBgkqhkiG9w0BAQsFADBpMQswCQYD
# VQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lD
# ZXJ0IFRydXN0ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEg
# Q0ExMB4XDTIyMTIwNTAwMDAwMFoXDTIzMTIwNTIzNTk1OVowaDELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFDASBgNVBAcTC1NhbnRhIENsYXJhMRYw
# FAYDVQQKEw1JbmZvYmxveCBJbmMuMRYwFAYDVQQDEw1JbmZvYmxveCBJbmMuMIIC
# IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAq2lT99WMbHlqhfw+aJW2wC9c
# Nx4/w+/hIsuR6t40lHyTYQ4aIC7qLw8j5kJCle6Qxpdwug4HEeVYKNIF/lhTkIUx
# DJn6DgdyMZSydScAtzkVlSqQhLU4Wtqk8cVBUEO0BymB32+BZGktduXVyzXzGQjt
# 44gQ0k646xfxnXzSrg2wWdYJtslVaZrjzAoCax5zDJfXh/FVKMG/8LmDaMNc4/Cl
# H6oNiB6u30+6TuwFzU9OCUXNydG4vg/HSnw51uOhFHRrXxtkUDdwYDXjH8hi8+a4
# YO6lJyZtW1skprMLo9PsM1ZoW74rH944gphmxyuicTNGD3eBLearfEPc4l287ZQN
# EoJ9nMNoEaj/QYx7jQzICmnqbt736EyRwpEyWNC8LlxQ5Mw7hyNs8SRIcXX78HV8
# flRBIqZFbDMpsRv+Qe7d1pkcnb4CqgpjGbkSqjorvi/+Zn4cG/8tYmThYW9iFaC1
# fsXEnaOeBjZjnrsbD6fID57Z7WJjmM5fz4ORu/95dwF+KRt5cXqR+bTdGtWUu7BL
# VVIl/M7XKyQ35+wY4r1M1m9jiILsl4X1MTtBABxvbPI0pipzsfGiy5rIDhxrGebQ
# zY5HGG3BrkbNhRCqQJlGZkToGRF5LUxIkyVtbW+MfiJBk2QDV/zevaIfrmD8DdJu
# Gxxurf2DiKVHgHONgukCAwEAAaOCAgYwggICMB8GA1UdIwQYMBaAFGg34Ou2O/hf
# EYb7/mF7CIhl9E5CMB0GA1UdDgQWBBTDoWtuti61vjkuHIWBFXElwS/a6DAOBgNV
# HQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwgbUGA1UdHwSBrTCBqjBT
# oFGgT4ZNaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0
# Q29kZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAyMUNBMS5jcmwwU6BRoE+GTWh0dHA6
# Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVTaWduaW5n
# UlNBNDA5NlNIQTM4NDIwMjFDQTEuY3JsMD4GA1UdIAQ3MDUwMwYGZ4EMAQQBMCkw
# JwYIKwYBBQUHAgEWG2h0dHA6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzCBlAYIKwYB
# BQUHAQEEgYcwgYQwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNv
# bTBcBggrBgEFBQcwAoZQaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lD
# ZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAyMUNBMS5jcnQw
# DAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAN7B9c10iN0Gl4w2IBgYA
# llHMfI8qdhGPhGX8vzhRlTlCarFvNtG4fTrpCobMj/bvKn29U8NLKm848PWtpC97
# 7LH9GcfhnBU83cGIkVpc6SnQiv1jlb3H/X/bQ5xRz7l/1B1Wi/uSMxByQ/3qjrZ+
# bfllf7cpORPpm7FZlvsGjZq7abS0hGkkpIUtO0V1G3Y8XMk80AT6i7XHYqL1o9vz
# Uv2bgrAQNAGZ7j9UXbQElKL2n5oyPzMC61yYEvzwyQFZ7nuV5nZEZLwMw8mZBtA7
# HnQabKAOU+p0OzV6iwnTWMfQfNXveJKS0uGHSxx9yW5WdGALnnaKUOoH0fG2738A
# 3QhCUx1S5OJpBBNb+Caqgvk7zSLRvoGy0nzTLNCTzSR3qmd8wXzVFXDkFznSJGXr
# yt5OoVujJxqG6+4Am+yydFais+SrjW4vAoAF5ZrXzp5763VxS16RQlKIu8pvrnBI
# Q22SKxiqi6MtAwa3UBz5U2gCHqEwHlaKBfq2KauET7tkmclu9UdHr+0j55urBnn3
# uDJndxOSn27HjlKZudT9owToUYlZwDcBxQDxicGSxo7d4VsPAqithlEwetcEmPVP
# RhpfYqcksFl1Jvj0UUSxfyQfWzfCRlmmnGpWhzRMgj0Q4st0DKtvxxD3fB+Msgnn
# ghk1z711Adk40cjFFypM+18xghpaMIIaVgIBATB9MGkxCzAJBgNVBAYTAlVTMRcw
# FQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3Rl
# ZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEzODQgMjAyMSBDQTECEA1rjVwr
# OOzXYRAQV6L44mowCQYFKw4DAhoFAKBwMBAGCisGAQQBgjcCAQwxAjAAMBkGCSqG
# SIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3
# AgEVMCMGCSqGSIb3DQEJBDEWBBSeke2zbwiaOkMe5cscPH2DXDI73TANBgkqhkiG
# 9w0BAQEFAASCAgCAuRzQmrKzEUxTkKm4VCH4+YuaYo4o/ub4eEN0+0w0wIcE77AF
# 0A+W/GGe725Z9p3p/PsPCKKYjhU19VkxEYz3Cqqdzne+04UaldK/TFUUheu5Em51
# bk/xoniIVcXuUsUPZ2FXSwCKXfWTbJ+EnkjLQT0XsAjzqx6TevsImunw9b3y93KA
# TbFSmpX0HoBkuIU4Y7ur9/bWj9xXzJT3RPZQYOQBCtfOJfzLD6LZYE4fRnfXLCeK
# SuCRwaLtDNeqX2zI7cszISAZgdxOYpYrF/CzBIG55JIGjq1s/mqDFh8Jb45R69fh
# JYu/gMj4vGFaxjPKXXlilv8Fs407G4TbSicdexsHHTn9LwAU0D3hsOVYpIqS1EEc
# 2Da1fjEgfz7HclSr4RNNJgAY6+WwvZRF8/8cu1dt2ZcnIYvtjrWvykp0iqtGgloF
# k8oSBT+Wzc1vH4tBCHPFWfSuiA6xEP2Ye/Jz0N9UpG4H6XDZJFYNZWt2BE89dTQg
# u7Pji3Xg6o2yZfzIPOXqP146qviFUvf1y+Ua4klvSaUcSdHV/s6sOQClNOnxAmoe
# 7J8ptFII2LnNzW8Y3g7D2o1WuxPLyjvisSOovJAYWtsZ1sqSxcxHqu8UWiM3iOCP
# k7IhWv9kUnWZrnX8hhGvTCG6A/muG7ReXAxWrq0u/6o+nXM4nhbIm/PoeKGCF0Aw
# ghc8BgorBgEEAYI3AwMBMYIXLDCCFygGCSqGSIb3DQEHAqCCFxkwghcVAgEDMQ8w
# DQYJYIZIAWUDBAIBBQAweAYLKoZIhvcNAQkQAQSgaQRnMGUCAQEGCWCGSAGG/WwH
# ATAxMA0GCWCGSAFlAwQCAQUABCDe2AaKOM1/i4Z53m8oXjxC/XETKP/3Rm0n+iJO
# S3gLqAIRALpGNxlR+mdOYYoyuBgDr5kYDzIwMjMxMDMxMTIxNzA3WqCCEwkwggbC
# MIIEqqADAgECAhAFRK/zlJ0IOaa/2z9f5WEWMA0GCSqGSIb3DQEBCwUAMGMxCzAJ
# BgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGln
# aUNlcnQgVHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0Ew
# HhcNMjMwNzE0MDAwMDAwWhcNMzQxMDEzMjM1OTU5WjBIMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xIDAeBgNVBAMTF0RpZ2lDZXJ0IFRpbWVz
# dGFtcCAyMDIzMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAo1NFhx2D
# jlusPlSzI+DPn9fl0uddoQ4J3C9Io5d6OyqcZ9xiFVjBqZMRp82qsmrdECmKHmJj
# adNYnDVxvzqX65RQjxwg6seaOy+WZuNp52n+W8PWKyAcwZeUtKVQgfLPywemMGjK
# g0La/H8JJJSkghraarrYO8pd3hkYhftF6g1hbJ3+cV7EBpo88MUueQ8bZlLjyNY+
# X9pD04T10Mf2SC1eRXWWdf7dEKEbg8G45lKVtUfXeCk5a+B4WZfjRCtK1ZXO7wgX
# 6oJkTf8j48qG7rSkIWRw69XloNpjsy7pBe6q9iT1HbybHLK3X9/w7nZ9MZllR1Wd
# SiQvrCuXvp/k/XtzPjLuUjT71Lvr1KAsNJvj3m5kGQc3AZEPHLVRzapMZoOIaGK7
# vEEbeBlt5NkP4FhB+9ixLOFRr7StFQYU6mIIE9NpHnxkTZ0P387RXoyqq1AVybPK
# vNfEO2hEo6U7Qv1zfe7dCv95NBB+plwKWEwAPoVpdceDZNZ1zY8SdlalJPrXxGsh
# uugfNJgvOuprAbD3+yqG7HtSOKmYCaFxsmxxrz64b5bV4RAT/mFHCoz+8LbH1cfe
# bCTwv0KCyqBxPZySkwS0aXAnDU+3tTbRyV8IpHCj7ArxES5k4MsiK8rxKBMhSVF+
# BmbTO77665E42FEHypS34lCh8zrTioPLQHsCAwEAAaOCAYswggGHMA4GA1UdDwEB
# /wQEAwIHgDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMCAG
# A1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATAfBgNVHSMEGDAWgBS6Ftlt
# TYUvcyl2mi91jGogj57IbzAdBgNVHQ4EFgQUpbbvE+fvzdBkodVWqWUxo97V40kw
# WgYDVR0fBFMwUTBPoE2gS4ZJaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lD
# ZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVTdGFtcGluZ0NBLmNybDCBkAYI
# KwYBBQUHAQEEgYMwgYAwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0
# LmNvbTBYBggrBgEFBQcwAoZMaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0Rp
# Z2lDZXJ0VHJ1c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVTdGFtcGluZ0NBLmNydDAN
# BgkqhkiG9w0BAQsFAAOCAgEAgRrW3qCptZgXvHCNT4o8aJzYJf/LLOTN6l0ikuyM
# IgKpuM+AqNnn48XtJoKKcS8Y3U623mzX4WCcK+3tPUiOuGu6fF29wmE3aEl3o+uQ
# qhLXJ4Xzjh6S2sJAOJ9dyKAuJXglnSoFeoQpmLZXeY/bJlYrsPOnvTcM2Jh2T1a5
# UsK2nTipgedtQVyMadG5K8TGe8+c+njikxp2oml101DkRBK+IA2eqUTQ+OVJdwha
# IcW0z5iVGlS6ubzBaRm6zxbygzc0brBBJt3eWpdPM43UjXd9dUWhpVgmagNF3tlQ
# tVCMr1a9TMXhRsUo063nQwBw3syYnhmJA+rUkTfvTVLzyWAhxFZH7doRS4wyw4jm
# WOK22z75X7BC1o/jF5HRqsBV44a/rCcsQdCaM0qoNtS5cpZ+l3k4SF/Kwtw9Mt91
# 1jZnWon49qfH5U81PAC9vpwqbHkB3NpE5jreODsHXjlY9HxzMVWggBHLFAx+rrz+
# pOt5Zapo1iLKO+uagjVXKBbLafIymrLS2Dq4sUaGa7oX/cR3bBVsrquvczroSUa3
# 1X/MtjjA2Owc9bahuEMs305MfR5ocMB3CtQC4Fxguyj/OOVSWtasFyIjTvTs0xf7
# UGv/B3cfcZdEQcm4RtNsMnxYL2dHZeUbc7aZ+WssBkbvQR7w8F/g29mtkIBEr4AQ
# QYowggauMIIElqADAgECAhAHNje3JFR82Ees/ShmKl5bMA0GCSqGSIb3DQEBCwUA
# MGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsT
# EHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9v
# dCBHNDAeFw0yMjAzMjMwMDAwMDBaFw0zNzAzMjIyMzU5NTlaMGMxCzAJBgNVBAYT
# AlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQg
# VHJ1c3RlZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwggIiMA0G
# CSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDGhjUGSbPBPXJJUVXHJQPE8pE3qZdR
# odbSg9GeTKJtoLDMg/la9hGhRBVCX6SI82j6ffOciQt/nR+eDzMfUBMLJnOWbfhX
# qAJ9/UO0hNoR8XOxs+4rgISKIhjf69o9xBd/qxkrPkLcZ47qUT3w1lbU5ygt69Ox
# tXXnHwZljZQp09nsad/ZkIdGAHvbREGJ3HxqV3rwN3mfXazL6IRktFLydkf3YYMZ
# 3V+0VAshaG43IbtArF+y3kp9zvU5EmfvDqVjbOSmxR3NNg1c1eYbqMFkdECnwHLF
# uk4fsbVYTXn+149zk6wsOeKlSNbwsDETqVcplicu9Yemj052FVUmcJgmf6AaRyBD
# 40NjgHt1biclkJg6OBGz9vae5jtb7IHeIhTZgirHkr+g3uM+onP65x9abJTyUpUR
# K1h0QCirc0PO30qhHGs4xSnzyqqWc0Jon7ZGs506o9UD4L/wojzKQtwYSH8UNM/S
# TKvvmz3+DrhkKvp1KCRB7UK/BZxmSVJQ9FHzNklNiyDSLFc1eSuo80VgvCONWPfc
# Yd6T/jnA+bIwpUzX6ZhKWD7TA4j+s4/TXkt2ElGTyYwMO1uKIqjBJgj5FBASA31f
# I7tk42PgpuE+9sJ0sj8eCXbsq11GdeJgo1gJASgADoRU7s7pXcheMBK9Rp6103a5
# 0g5rmQzSM7TNsQIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNV
# HQ4EFgQUuhbZbU2FL3MpdpovdYxqII+eyG8wHwYDVR0jBBgwFoAU7NfjgtJxXWRM
# 3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMI
# MHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNl
# cnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20v
# RGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRw
# Oi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAg
# BgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQAD
# ggIBAH1ZjsCTtm+YqUQiAX5m1tghQuGwGC4QTRPPMFPOvxj7x1Bd4ksp+3CKDaop
# afxpwc8dB+k+YMjYC+VcW9dth/qEICU0MWfNthKWb8RQTGIdDAiCqBa9qVbPFXON
# ASIlzpVpP0d3+3J0FNf/q0+KLHqrhc1DX+1gtqpPkWaeLJ7giqzl/Yy8ZCaHbJK9
# nXzQcAp876i8dU+6WvepELJd6f8oVInw1YpxdmXazPByoyP6wCeCRK6ZJxurJB4m
# wbfeKuv2nrF5mYGjVoarCkXJ38SNoOeY+/umnXKvxMfBwWpx2cYTgAnEtp/Nh4ck
# u0+jSbl3ZpHxcpzpSwJSpzd+k1OsOx0ISQ+UzTl63f8lY5knLD0/a6fxZsNBzU+2
# QJshIUDQtxMkzdwdeDrknq3lNHGS1yZr5Dhzq6YBT70/O3itTK37xJV77QpfMzmH
# QXh6OOmc4d0j/R0o08f56PGYX/sr2H7yRp11LB4nLCbbbxV7HhmLNriT1ObyF5lZ
# ynDwN7+YAN8gFk8n+2BnFqFmut1VwDophrCYoCvtlUG3OtUVmDG0YgkPCr2B2RP+
# v6TR81fZvAT6gt4y3wSJ8ADNXcL50CN/AAvkdgIm2fBldkKmKYcJRyvmfxqkhQ/8
# mJb2VVQrH4D6wPIOK+XW+6kvRBVK5xMOHds3OBqhK/bt1nz8MIIFjTCCBHWgAwIB
# AgIQDpsYjvnQLefv21DiCEAYWjANBgkqhkiG9w0BAQwFADBlMQswCQYDVQQGEwJV
# UzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQu
# Y29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcNMjIw
# ODAxMDAwMDAwWhcNMzExMTA5MjM1OTU5WjBiMQswCQYDVQQGEwJVUzEVMBMGA1UE
# ChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYD
# VQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQC/5pBzaN675F1KPDAiMGkz7MKnJS7JIT3yithZwuEppz1Y
# q3aaza57G4QNxDAf8xukOBbrVsaXbR2rsnnyyhHS5F/WBTxSD1Ifxp4VpX6+n6lX
# FllVcq9ok3DCsrp1mWpzMpTREEQQLt+C8weE5nQ7bXHiLQwb7iDVySAdYyktzuxe
# TsiT+CFhmzTrBcZe7FsavOvJz82sNEBfsXpm7nfISKhmV1efVFiODCu3T6cw2Vbu
# yntd463JT17lNecxy9qTXtyOj4DatpGYQJB5w3jHtrHEtWoYOAMQjdjUN6QuBX2I
# 9YI+EJFwq1WCQTLX2wRzKm6RAXwhTNS8rhsDdV14Ztk6MUSaM0C/CNdaSaTC5qmg
# Z92kJ7yhTzm1EVgX9yRcRo9k98FpiHaYdj1ZXUJ2h4mXaXpI8OCiEhtmmnTK3kse
# 5w5jrubU75KSOp493ADkRSWJtppEGSt+wJS00mFt6zPZxd9LBADMfRyVw4/3IbKy
# Ebe7f/LVjHAsQWCqsWMYRJUadmJ+9oCw++hkpjPRiQfhvbfmQ6QYuKZ3AeEPlAwh
# HbJUKSWJbOUOUlFHdL4mrLZBdd56rF+NP8m800ERElvlEFDrMcXKchYiCd98THU/
# Y+whX8QgUWtvsauGi0/C1kVfnSD8oR7FwI+isX4KJpn15GkvmB0t9dmpsh3lGwID
# AQABo4IBOjCCATYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU7NfjgtJxXWRM
# 3y5nP+e6mK4cD08wHwYDVR0jBBgwFoAUReuir/SSy4IxLVGLp6chnfNtyA8wDgYD
# VR0PAQH/BAQDAgGGMHkGCCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0cDov
# L29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0cy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MEUGA1UdHwQ+
# MDwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3Vy
# ZWRJRFJvb3RDQS5jcmwwEQYDVR0gBAowCDAGBgRVHSAAMA0GCSqGSIb3DQEBDAUA
# A4IBAQBwoL9DXFXnOF+go3QbPbYW1/e/Vwe9mqyhhyzshV6pGrsi+IcaaVQi7aSI
# d229GhT0E0p6Ly23OO/0/4C5+KH38nLeJLxSA8hO0Cre+i1Wz/n096wwepqLsl7U
# z9FDRJtDIeuWcqFItJnLnU+nBgMTdydE1Od/6Fmo8L8vC6bp8jQ87PcDx4eo0kxA
# GTVGamlUsLihVo7spNU96LHc/RzY9HdaXFSMb++hUD38dglohJ9vytsgjTVgHAID
# yyCwrFigDkBjxZgiwbJZ9VVrzyerbHbObyMt9H5xaiNrIv8SuFQtJ37YOtnwtoeW
# /VvRXKwYw02fc7cBqZ9Xql4o4rmUMYIDdjCCA3ICAQEwdzBjMQswCQYDVQQGEwJV
# UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRy
# dXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBAhAFRK/zlJ0I
# Oaa/2z9f5WEWMA0GCWCGSAFlAwQCAQUAoIHRMBoGCSqGSIb3DQEJAzENBgsqhkiG
# 9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcNMjMxMDMxMTIxNzA3WjArBgsqhkiG9w0B
# CRACDDEcMBowGDAWBBRm8CsywsLJD4JdzqqKycZPGZzPQDAvBgkqhkiG9w0BCQQx
# IgQgLkehvDXzoWAoRab+5vhQNM5BCzni1EBe2JW47WOGl8YwNwYLKoZIhvcNAQkQ
# Ai8xKDAmMCQwIgQg0vbkbe10IszR1EBXaEE2b4KK2lWarjMWr00amtQMeCgwDQYJ
# KoZIhvcNAQEBBQAEggIADyS/pnnZig8OFTaY5UcCgOmOeOKydGqOCRNSqWF7e5Z8
# CXl2X+RZxtMi5Z063MtJgecT8AuLg5aOmY9rqiotDljr5r9LVK3IJEq3bXc/hrbo
# LSTGKT7jNXiEIqhJJWVXrjPHGl6DBYRT8ccqeqemEn2DZy8+3rIvHdvRJ18gJ8Z+
# vP5TQjYEho6AwvFxmSFRxfqtCaCtTmxjYVi4SW9jlDIUznIiNm/O4qAz/3hl/pA4
# xxTCYv36yWPnaT56AjK2tfZSemShq5niOv78Nkpy7+1sB5PUA6BIEXxWQMsk+MA2
# pnjhn6IwUBQDQJ2I01mxpKuSVFaJGZevv4PNcjGZyJZertgunVbeB6lvVThX+mGm
# W4a/Z+s2g2Ucy4PHjriEbK5pLxnFWK0apBWLA7bXMzTyEmfZclaSIXTl1MnNl77V
# sXq6P/MK3n+reW9hE0h44Fav5G02zHFFZ27wjKNmLt1o5+eo4zaposdU1YTT2wbk
# 0LbBm8rAC6bsELHD1IklGpzti8IrSklaD327eOOGxVJ5NY8mE8BN9VnGLoqFDs4n
# /5D8X4LK0HJm6WkqduwtwT4VY8OxyoLAmTcrdoEsTyN3eBA3KlXII1u8o6H+6+ny
# cO6e9mzfkbMLjYwBGQawNDyTnHYsyEhsdRPjX1T2+o7LvXV6B0/XGfJHI44bW5E=
# SIG # End signature block
