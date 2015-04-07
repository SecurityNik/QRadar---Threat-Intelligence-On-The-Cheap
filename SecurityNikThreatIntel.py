#!/usr/bin/env python
# This is code is designed to download list of known bad IPs and domains
# Once the lists have been downloaded, 2 reference sets are created
# 1 for IPs and 1 for domains 
# Manual creation of QRadar rules are then done. These rules are then run against these 
# list to identify known bad IPs and Domain
#
# SecurityNikThreatIntel.py v1.0
# Author: Nik Alleyne, CISSP|GCIH|A < nikalleyne@gmail.com >
# Date: 2015-02-25
# Disclaimer: In no way am I responsible for any damages which you may 
# cause to your system by running this script. 

from os import uname, path, system, remove, getcwd
from shutil import rmtree,copytree
from subprocess import call
from sys import exit
from time import sleep


# This function checks to see if this script is running on Linux.
def check_os():
	qRadar_path = '/opt/qradar/conf/'
	qRadar_ver = '/opt/qradar/bin/myver'

	print(' Checking OS ... ')
	if ( uname()[0] == 'Linux' ) or ( uname()[0] == 'linux'):
		#print(' Running on Linux ... ')
		
		if ( path.exists('/etc/system-release') and path.isfile('/etc/system-release') ):
			call(['cat', '/etc/system-release'])
		else:
			print('\n Looks like you are running Linux. ')
			print('\n However, I am unable to determine your version info. ')
		
		print(' \n Looking for an installed version of QRadar')
		if ( path.exists(qRadar_path) and ( path.isdir(qRadar_path)) ):
			print(' \n looks like you are running QRadar version ... ')
			call([qRadar_ver])
			print(' \n Good stuff ... \n Blast off =>>>>>>> ')
		else:
			print(' An installed version of QRadar was not found on your system ')
			print(' This script will not work for you, it was designed to be used on box running IBM QRadar ')
			print(' Exiting ... ')
			exit(0)
		
		sleep(2)
	else:
		print(' Running this is a waste of your time. ')
		print(' This script is SPECIFICALLY for QRadar ')
		exit(0)


# This function downloads a list of known bad IPs and
def grab_ip_list():
	ip_path = ''
	bad_ip_list = 	['http://malc0de.com/bl/IP_Blacklist.txt' ,
					'http://malc0de.com/bl/IP_Blacklist.txt',
					'http://www.malwaredomainlist.com/hostslist/ip.txt',
					'https://zeustracker.abuse.ch/blocklist.php?download=badips' ,
					'http://www.spamhaus.org/drop/drop.txt',
					'http://www.spamhaus.org/drop/edrop.txt',
					'http://www.spamhaus.org/drop/drop.lasso', 
					'http://www.okean.com/chinacidr.txt' ,
					'http://myip.ms/files/blacklist/general/latest_blacklist.txt' ,
					'http://myip.ms/files/blacklist/csf/latest_blacklist.txt' ,
					'http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt' ,
					'http://rules.emergingthreats.net/blockrules/compromised-ips.txt' ,	
					'http://feeds.dshield.org/block.txt' ,
					'http://feeds.dshield.org/top10-2.txt',
					'http://www.dshield.org/feeds/topips.txt'
					'https://feodotracker.abuse.ch/blocklist/?download=ipblocklist',
					'https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist' ,
					'https://zeustracker.abuse.ch/blocklist.php?download=badips' ,
					]


	# Check to see if ip_tmp/ folder exists - This folder stores the files a the first download. 
	# Basically this will determine if its the first time the script is being run
	if ( path.exists('.ip_tmp/') and (path.isdir('.ip_tmp/')) ):
		ip_path = '.ip_tmp_path/'
	else:
		ip_path = '.ip_tmp/'

	try:
		print(' Preparing to download list of bad IP addresses ')
		for link in bad_ip_list:
			print(link)
			call(['wget', link, '--directory-prefix='+ip_path , '--tries=2', '--continue', '--timestamping', '--timeout=5', '--random-wait', '--no-proxy', '--inet4-only'])
			print(' \n  %s \n retrieved successfully \n' %link )
			sleep(2)
	except:
		print(' A problem occurred while downloading IP information from %s ' %link )
		print(' This link may be broken. Please copy the URL and paste into a browser to ensure it is accessible')
	else:
		# Looks like all went well
		print(' \n Looks like we have some baddddd IPs! ')



# This fuction download the list of malicious and or suspected domains
# DO NOT add entry to this list unless you are sure what you are doing
# These files are in different formats, thus may need to be manipulated the files individually

def grab_dns_list():
	dns_path = ''
	bad_dns_list = 	[ 'http://www.joewein.net/dl/bl/dom-bl.txt',
					   'http://www.joewein.net/dl/bl/dom-bl-base.txt',
					   'http://mirror1.malwaredomains.com/files/immortal_domains.txt',
					   'http://mirror1.malwaredomains.com/files/dynamic_dns.txt',
					   'https://zeustracker.abuse.ch/blocklist.php?download=baddomains',
					   'http://www.malwaredomainlist.com/hostslist/hosts.txt',
					   'http://malc0de.com/bl/BOOT',
					   'http://malc0de.com/bl/ZONES'
					]

	if ( path.exists('.dns_tmp') and (path.isdir('.dns_tmp')) ):
		dns_path = '.dns_tmp_path'
	else:
		dns_path = '.dns_tmp'

	try:
		print(' Preparing to download list of bad Domain  ')
		for dns in bad_dns_list:
			print(dns)
			call(['wget', dns, '--directory-prefix='+dns_path , '--tries=2', '--continue', '--timestamping', '--timeout=5', '--random-wait', '--no-proxy', '--inet4-only'])
			print(' \n  %s \n retrieved successfully \n' %dns )
			sleep(2)
	except:
		print(' A problem occurred while downloading DNS information from %s ' %dns )
		print(' This link may be broken. Please copy the URL and paste into a browser to ensure it is accessible')
	else:
		# Looks like all went well
		print(' \n Looks like we have some baddddd domains! ')


# Checking the directories to see if the last run added new info
def compare_ip_dirs():
	print(' Checking if there is need for an update .... ')

	#first check to see if .ip_tmp_path exists
	if ( path.exists('.ip_tmp_path') and (path.isdir('.ip_tmp_path')) ):
		print(' Give me just a few seconds more')
		sleep(2)
	
		if ( int(path.getsize('.ip_tmp')) <= int(path.getsize('.ip_tmp_path')) ):
			print(' \n Looks like new content is available ')
			# copying new content in .ip_tmp_path to .ip_tmp
			try:
				rmtree('.ip_tmp')
				copytree('.ip_tmp_path','.ip_tmp')
			except:
				print(' Failed to copy new data ... ')
				print(' Exiting ... ')
				exit(0)
			else:
				print(' Successfully moved new data')
		else:
			print(' Nothing new was added ... ')
			print(' Exiting ... ')
			exit(0)
	else:
		print(' This is first run ... \n moving on ... ')

	sleep(2)


# Comparing the DNS folders to see if new content may have been added
def compare_dns_dirs():
	print(' Checking if there is need for an update .... ')
	
	#first check to see if .ip_tmp_path exists
	if ( path.exists('.ip_tmp_path') and (path.isdir('.ip_tmp_path')) ):
		print(' Give me just a few seconds more')
		sleep(2)
		
		if ( int(path.getsize('.ip_tmp')) <= int(path.getsize('.ip_tmp_path')) ):
			print(' \n Looks like new content is available ')
			
			# copying new content in .dns_tmp_path to .dns_tmp
			try:
				rmtree('.dns_tmp')
				copytree('.dns_tmp_path','.dns_tmp')
			except:
				print(' Failed to copy new data ... ')
				print(' Exiting ... ')
				exit(0)
			else:
				print(' Successfully moved new data')				
		else:
			print(' Nothing new was added ... ')
			print(' Exiting ... ')
			exit(0)
	else:
		print(' This is first run ... \n moving on ... ')
		sleep(2)


# Now that the files have been successfully downloaded, let's combine them all
def combine_ip_files():
	print(' \n Checking for .ip_tmp folder ... ')
	sleep(2)
	if ( path.exists('.ip_tmp') and path.isdir('.ip_tmp') ):
		print(' directory .ip_tmp/ found ')
		system('cat .ip_tmp/* | grep --perl-regexp --only-matching "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" | sort -i | uniq --unique --check-chars=15 > SecurityNikBadIPs.txt')
		
		if ( path.exists('SecurityNikBadIPs.txt') and path.isfile('SecurityNikBadIPs.txt') ):
			print(' Successfully created file SecurityNikBadIPs.txt ')
		else:
			print(' Unable to create SecurityNikBadIPs.txt file ')
			print(' The program will now exit ... Exiting ... ')
			exit(0)
	else:
		print(' \n ip_tmp/ directory not found ')
		print(' Unable to continue ... Exiting!')
		exit(0)


# This function manipulates the downloaded DNS files, so that all can be placed into one standard file
def combine_dns_files():
	print(' Combining DNS files ')
	if ( path.exists('.dns_tmp') and  path.isdir('.dns_tmp') ):
		print(' directory .dns_tmp/ found ')
		try:
			print(' Combining downloaded files into .... ')
			system('cat .dns_tmp/dom-bl.txt > .SecurityNikBadDomains.txt')
			system('cat .dns_tmp/dom-bl-base.txt >> .SecurityNikBadDomains.txt')
			system("cat .dns_tmp/hosts.txt | awk  '/127.0.0.1/ { print $2 }'  >> .SecurityNikBadDomains.txt")
			system('cat .dns_tmp/immortal_domains.txt | grep -i -P "This is a list|^$" -v >> SecurityNikBadDomains.txt')
			system('cat .dns_tmp/BOOT | grep -i PRIMARY | cut -f 2 -d " " | grep -i -v -P "ibm\.com" -v >> .SecurityNikBadDomains.txt')
			system('cat .dns_tmp/dynamic_dns.txt | grep -P -v "^#|^$" | cut -f 1 -s >> .SecurityNikBadDomains.txt')
			system('cat .dns_tmp/blocklist.php\?download\=baddomains | grep -P -v "^#|^$" >> .SecurityNikBadDomains.txt')
			system('cat .SecurityNikBadDomains.txt | sort -i | uniq --unique > SecurityNikBadDomains.txt')
		
		except:
			print(' Looks like an error occurred while combining the files')
			print(' Please retry later ... \n Exiting ... ')
			exit(0)
		else:
			print(' files successfully combined ')
			print(' A list of known bad domains can be found in SecurityNikBadDomains.txt')
			remove('.SecurityNikBadDomains.txt')

	else:
		print(' \n dns_tmp/ directory not found ')
		print(' The program will now exit ... Exiting ... ')
		exit(0)




# This function does all the work for the IP reference set
def verify_create_ip_reference_set():
	reference_set_name = 'SecurityNik_IP_Darklist'
	ip_txt = getcwd()+'/SecurityNikBadIPs.txt'
	rows = []
	
	print('Checking to see if the reference set %s already exists' %reference_set_name)
	f =open('.count.txt', 'w')
	call(["psql", "-U", "qradar", "--command=SELECT COUNT(*) FROM reference_data WHERE name='SecurityNik_IP_Darklist'"], stdout=f )
	f.close()

	# Resting ... I'm tired
	sleep(2)
    
	f = open('.count.txt', 'r')
    	
	for line in f.readlines():
		rows.append(line.strip())
	#print(rows)
	
	if (rows[2].strip() != '0'):
		print(' Looks like reference set already exists \n ')
	else:
		print(' Reference Set %s not found ...  %reference_set_name ')
		print(' Looks like we will have to create this bad boy ...')
		
		try:    
			call(['/opt/qradar/bin/ReferenceSetUtil.sh', 'create', reference_set_name , 'IP'])
			print(' Successfully created reference set %s \n ' %reference_set_name )
			#print(' Looks like that went well ... ' )
		except:
			#This does not catch any java exception that may be created
			print(' Error occurred while creating reference set %s ' %reference_set)
			print(' You may create the reference set %s manually if needed ' %reference_set_name )
			exit(0)

	print(' Loading information into reference set %s ' %reference_set_name )
	try:	
		call(['/opt/qradar/bin/ReferenceSetUtil.sh', 'load', reference_set_name , ip_txt ])
		print(' \n You may need to verify that you have rules created to use %s ' %reference_set_name )
	except:
		print(' An error occurred while loading the reference set ... ')
		print(' Please retry later!')
		exit(0)
	remove('.count.txt')


# This function creates the DNS reference set
def verify_create_dns_reference_set():
	reference_set_name = 'SecurityNik_DNS_Darklist'
	dns_txt = getcwd()+'/SecurityNikBadDomains.txt'
	dns_rows = []
	
	print('Checking to see if the reference set %s already exists' %reference_set_name)
	f = open('.count.txt', 'w')
	call(["psql", "-U", "qradar", "--command=SELECT COUNT(*) FROM reference_data WHERE name='SecurityNik_DNS_Darklist'"], stdout=f )
	f.close()

	# Taking a nap ...
	sleep(2)

	f = open('.count.txt', 'r')
	for line in f.readlines():
		dns_rows.append(line.strip())
	#print(dns_rows)

	if (dns_rows[2].strip() != '0'):
		print(' Looks like reference set already exists \n ')
	else:
		print(' Reference Set %s not found ' %reference_set_name )
		print(' Looks like we will have to create this bad boy ...')
		try:
			call(['/opt/qradar/bin/ReferenceSetUtil.sh', 'create', reference_set_name , 'ALN'])
			print(' Successfully created reference set %s ' %reference_set_name )
			
			#print(' Looks like that went well ... ' )
		except:
			# This does not catch any java exception that may be created
			print(' Error occurred while creating reference set %s ' %reference_set)
			print(' You may create the reference set %s manually if needed ' %reference_set_name )
			exit(0)
				
	print(' Loading information into reference set %s ' %reference_set_name )
		
	try:
		call(['/opt/qradar/bin/ReferenceSetUtil.sh', 'load', reference_set_name , dns_txt ])
		print(' \n You may need to verify that you have rules created to use %s ' %reference_set_name )
	except:
		print(' An error occurred while loading the reference set ... ')
		print(' Please retry later!')
		exit(0)
	remove('.count.txt')



# Main Function
def main():
	#print('You are in the main part of the code')
	call('clear')
	check_os()

	# Let's work on the IP Reference Set
	grab_ip_list()
	compare_ip_dirs()
	combine_ip_files()
	verify_create_ip_reference_set()

	# Let's work on the DNS Reference Set
	grab_dns_list()
	compare_dns_dirs()
	combine_dns_files()
	verify_create_dns_reference_set()


if __name__ == "__main__":
	main()
