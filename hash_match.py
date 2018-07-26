#! /usr/bin/python

# Simple way to get Enabled/Disabled AD users
# Import-Module activedirectory
#
# Disabled Users
# Get-Aduser -Filter 'Enabled -eq $false' -Properties *|select SamAccountName |export-csv C:\outputDisabled.csv
#
# Enables Users
# Get-Aduser -Filter 'Enabled -eq $true' -Properties *|select SamAccountName  |export-csv C:\outputEnabled.csv

import os,sys,re

try:
	from termcolor import colored 
except ImportError:
	print ('termcolor appears to be missing - try: pip install termcolor')
	logging.error("termcolor missing")
	exit(1)

#Define stuff here
hashcat_output=[]
hash_list = []
unique_nt=[]
hash_match=[]
dup_hashes=[]
hash_sets=[]
da_reuse=[]
da_list=[]
dirty=""
enabled=[]
disabled=[]

#Print the banner out
print "\n\n"
print """
$$\   $$\                     $$\             $$\      $$\            $$\               $$\       
$$ |  $$ |                    $$ |            $$$\    $$$ |           $$ |              $$ |      
$$ |  $$ | $$$$$$\   $$$$$$$\ $$$$$$$\        $$$$\  $$$$ | $$$$$$\ $$$$$$\    $$$$$$$\ $$$$$$$\  
$$$$$$$$ | \____$$\ $$  _____|$$  __$$\       $$\$$\$$ $$ | \____$$\\\\_$$  _|  $$  _____|$$  __$$\ 
$$  __$$ | $$$$$$$ |\$$$$$$\  $$ |  $$ |      $$ \$$$  $$ | $$$$$$$ | $$ |    $$ /      $$ |  $$ |
$$ |  $$ |$$  __$$ | \____$$\ $$ |  $$ |      $$ |\$  /$$ |$$  __$$ | $$ |$$\ $$ |      $$ |  $$ |
$$ |  $$ |\$$$$$$$ |$$$$$$$  |$$ |  $$ |      $$ | \_/ $$ |\$$$$$$$ | \$$$$  |\$$$$$$$\ $$ |  $$ |
\__|  \__| \_______|\_______/ \__|  \__|      \__|     \__| \_______|  \____/  \_______|\__|  \__|
"""                                                                                         
print colored("                                                                             By Richard Davy 2018",'yellow')
print colored("                                                                                      Version 1.4",'blue')
print colored("                                                                                      @rd_pentest",'green')
print "\n"                                                                                       
                                                                                                  
Hashes=raw_input("[+]Please enter path to hash file: ")
DA_Path=raw_input("[+](Optional)If you have a list of Domain Admins enter path or press Enter: ")
second_hash_list=raw_input("[+](Optional)If you have a second set of hashes enter path or press Enter: ")
hashcat_path=raw_input("[+](Optional)If you have hashcat cracked hashes output enter path or press Enter: ")
Enabled_Accounts=raw_input("[+](Optional)If you have a list of Enabled AD account names enter path or press Enter: ")
Disabled_Accounts=raw_input("[+](Optional)If you have a list of Disabled AD account names enter path or press Enter: ")

#Check if hashfile exists and if so open and add to list
#any problems error out nicely
if os.path.exists(Hashes):
	print colored ("[+]Found file "+Hashes,'green')
	with open(Hashes) as fp:
		for line in fp:
			#Regex to check that it's a recognised hash
			pwdumpmatch = re.compile('^(\S+?):.*?:([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::\s*$')
			pwdump = pwdumpmatch.match(line)
			if pwdump:
				hash_list.append(line.rstrip())
else:
	print colored ("\n[-]Error File not found "+Hashes+"\n",'red')
	sys.exit()

#Check if DA list exists and if so open and add it list
if os.path.exists(DA_Path):
	print colored ("[+]Found file "+DA_Path,'green')
	with open(DA_Path) as dafp:
		for da in dafp:
			da_list.append(da.rstrip())

#Check to see if second hashes can be loaded
if os.path.exists(second_hash_list):
	print colored ("[+]Found file "+second_hash_list,'green')
	with open(second_hash_list) as fp:
		for line in fp:
			#Regex to check that it's a recognised hash
			pwdumpmatch = re.compile('^(\S+?):.*?:([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::\s*$')
			pwdump = pwdumpmatch.match(line)
			if pwdump:
				hash_list.append(line.rstrip())

#Check to see if hashcat hashes can be loaded
if os.path.exists(hashcat_path):
	print colored ("[+]Found file "+hashcat_path,'green')
	with open(hashcat_path) as fp:
		#Regex to check that it's a recognised hash
		for line in fp:
			pwdumpmatch = re.compile('^(\S+?):([0-9a-fA-F]{32}):.*?\s*$')
			pwdump = pwdumpmatch.match(line)
			if pwdump:
				hashcat_output.append(line)

#Check for enabled accounts file
if os.path.exists(Enabled_Accounts):
	print colored ("[+]Found file "+Enabled_Accounts,'green')
	with open(Enabled_Accounts) as fp:
		#Add account names to list
		for line in fp:
			if line.lstrip().rstrip().strip('"')!="SamAccountName" and line.lstrip().rstrip().strip('"') != "#TYPE Selected.Microsoft.ActiveDirectory.Management.ADUser":
				enabled.append(line.lstrip().rstrip().strip('"'))

	#Check account names against hash list and prefix hash list if found
	for item in enabled:
		for idx, usr in enumerate(hash_list):
			if item in usr:
				hash_list[idx]="AD Status - Enabled \t"+usr

#Chck for disabled accounts file
if os.path.exists(Disabled_Accounts):
	print colored ("[+]Found file "+Disabled_Accounts,'green')
	with open(Disabled_Accounts) as fp:
		#Add account names to list
		for line in fp:
			if line.lstrip().rstrip().strip('"')!="SamAccountName" and line.lstrip().rstrip().strip('"') != "#TYPE Selected.Microsoft.ActiveDirectory.Management.ADUser":
				disabled.append(line.lstrip().rstrip().strip('"'))

	#Check account names against hash list and prefix hash list if found
	for item in disabled:
		for idx, usr in enumerate(hash_list):
			if item in usr:
				hash_list[idx]="AD Status - Disabled \t"+usr

#Build a list of NT hashes and make unique
for nt in hash_list:
	unique_nt.append(nt.split(":")[3])

#Build Unique List of NT hashes
unique_nt=set(unique_nt)

#Cycle Unique Hashes
for unt in unique_nt:
	#Cycle hashlist
	for user in hash_list:
		#If unique hash is in big hash list
		#add to our match list
		if unt in user:
			hash_match.append(user)

	#If the match list is greater than one
	if len(hash_match)>1:
		
		#hashcat_output
		#Check to see if we have a cracked password
		if len(hashcat_output)>0:
			for hashcat in hashcat_output:
				#print hash_match[1].split(":")[3]+" "+hashcat.split(":")[1]
				if hash_match[1].split(":")[3]==hashcat.split(":")[1]:
					#Print the string hash match with a new line at the beginning and end
					if dirty!="HM":
						print colored ("\n[+]Hash Match ",'yellow')+colored (":***CRACKED PASSWORD***: ",'red')+colored(hashcat.split(":")[2],'green')
						hash_sets.append("Hash Match")
						dirty="HM"
			
			if dirty!="HM":
				#Print the string hash match with a new line at the beginning and end
				print colored ("\n[+]Hash Match",'yellow')
				hash_sets.append("Hash Match")
			dirty=""
		else:
			#Print the string hash match with a new line at the beginning and end
			print colored ("\n[+]Hash Match",'yellow')
			hash_sets.append("Hash Match")


		#If the list of Domain Admins is greater than zero
		if len(da_list)>0:
			#Cycle list of hashe matches
			for m in hash_match:
				#Cycle list of domain admins
				for d in da_list:
					#If domain admin found in hash match
					if d in m:
						#Print verbose message in red
						print colored(m +" ***DOMAIN ADMIN***",'red')
						#Add da reuse to list to create counter
						da_reuse.append(m)
						#Add duplicate hashes to list to create counter
						dup_hashes.append(m)
						#change the dirty flag
						dirty="da"
				#if dirty flag is empty print match
				if dirty!="da":
					print m
					#Add duplicate hashes to list to create counter
					dup_hashes.append(m)
				#Clear dirty flag
				dirty=""
		else:
		#If the list of Domain Admins is 0 just print out matches
			for m in hash_match:
				print m
				#Add duplicate hashes to list to create counter
				dup_hashes.append(m)

	#empty matching hash list
	hash_match=[]

#Display some basic stats.
print colored("\n[+]Statistics","green")	
print colored("[+]"+str(len(hash_list))+" Total Hashes in List",'yellow')
print colored("[+]"+str(len(unique_nt))+" Unique Hashes",'yellow')
print colored("[+]"+str(len(dup_hashes))+" Instances of password reuse were detected",'yellow')
print colored("[+]"+str(len(hash_sets))+" Sets of hash reuse",'yellow')

if len(da_list)>0:
	print colored("[+]"+str(len(da_reuse))+" instances of DA reuse detected",'yellow')
