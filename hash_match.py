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

from collections import Counter
from prettytable import PrettyTable

import hashlib,binascii

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
cracked_enabled=[]
cracked_enabled_freq=[]
cracked_enabled_password=[]
cracked_enabled_da=[]
lm_accounts=[]
bad_list=[]

usr1=""
filepath=""
badlistpath=""
fileoutput=[]


#Setup some header details for fileoutput
fileoutput.append("HashMatch File Output")
fileoutput.append("By Richard Davy - 2018")
fileoutput.append("https://github.com/rmdavy/hashmatch")
fileoutput.append("@rd_pentest\n")

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
print colored("                                                                                      Version 1.9.1",'blue')
print colored("                                                                                      @rd_pentest",'green')
print "\n"                                                                                       
                                                                                                  
Hashes=raw_input("[+]Please enter path to hash file: ")
DA_Path=raw_input("[+](Optional)If you have a list of Domain Admins enter path or press Enter: ")
second_hash_list=raw_input("[+](Optional)If you have a second set of hashes enter path or press Enter: ")
hashcat_path=raw_input("[+](Optional)If you have HashCat cracked hashes output enter path or press Enter: ")
Enabled_Accounts=raw_input("[+](Optional)If you have a list of Enabled AD account names enter path or press Enter: ")
Disabled_Accounts=raw_input("[+](Optional)If you have a list of Disabled AD account names enter path or press Enter: ")
badlistpath=raw_input("[+](Optional)If you have a list of Weak passwords to check for enter path or press Enter: ")
filepath=raw_input("[+](Optional)Enter file path to save to file or press Enter: ")

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
			#Cut out username from hashcat details for an exact username match
			usr1=usr.split(":")[0]
			if "\\" in usr1:
				usr1=usr1.split("\\")[1]
				
			if item.lstrip().rstrip()==usr1:
				if not "AD Status - Enabled" in hash_list[idx]:
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
			#Cut out username from hashcat details for an exact username match
			usr1=usr.split(":")[0]
			if "\\" in usr1:
				usr1=usr1.split("\\")[1]
				
			if item.lstrip().rstrip()==usr1:
				if not "AD Status - Disabled" in hash_list[idx]:
					hash_list[idx]="AD Status - Disabled \t"+usr

#Check to see if bad passwords list can be loaded
if os.path.exists(badlistpath):
	print colored ("[+]Found file "+badlistpath,'green')
	with open(badlistpath) as fp:
		#Regex to check that it's a recognised hash
		for line in fp:
			hash = hashlib.new('md4', line.encode('utf-16le')).digest()
			#Add to arrary in format badpassword:hash for easy retrieval
			bad_list.append(line.strip()+":"+binascii.hexlify(hash))

		print colored("Loaded "+str(len(bad_list))+" weak password(s) from file",'yellow')

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
						
						if len(hashcat.split(":")[2].rstrip().lstrip())==0:
							print colored ("\n[+]Hash Match ",'yellow')+colored (":***CRACKED PASSWORD***: ",'red')+colored(hashcat.split(":")[2].rstrip()+"***BLANK PASSWORD***",'red')
							#Check for fileoutput
							if len(filepath)!=0:
								fileoutput.append("\n[+]Hash Match :***CRACKED PASSWORD***: "+hashcat.split(":")[2].rstrip()+"***BLANK PASSWORD***")
						else:
							print colored ("\n[+]Hash Match ",'yellow')+colored (":***CRACKED PASSWORD***: ",'red')+colored(hashcat.split(":")[2].rstrip(),'green')
							#Check for fileoutput
							if len(filepath)!=0:
								fileoutput.append("\n[+]Hash Match :***CRACKED PASSWORD***: "+hashcat.split(":")[2].rstrip())
						
						hash_sets.append("Hash Match")
						dirty="HM"
			
			if dirty!="HM":
				#Print the string hash match with a new line at the beginning and end
				print colored ("\n[+]Hash Match",'yellow')
				#Check for fileoutput
				if len(filepath)!=0:
					fileoutput.append("\n[+]Hash Match")

				hash_sets.append("Hash Match")
			dirty=""
		else:
			#Print the string hash match with a new line at the beginning and end
			print colored ("\n[+]Hash Match",'yellow')
			#Check for fileoutput
			if len(filepath)!=0:
				fileoutput.append("\n[+]Hash Match")

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
						
						#Check for fileoutput
						if len(filepath)!=0:
							fileoutput.append(m +" ***DOMAIN ADMIN***")

						#Add da reuse to list to create counter
						da_reuse.append(m)
						#Add duplicate hashes to list to create counter
						dup_hashes.append(m)
						#change the dirty flag
						dirty="da"
				#if dirty flag is empty print match
				if dirty!="da":
					#Print result to screen
					print m

					#Check for fileoutput
					if len(filepath)!=0:
						fileoutput.append(m)

					#Add duplicate hashes to list to create counter
					dup_hashes.append(m)
				#Clear dirty flag
				dirty=""
		else:
		#If the list of Domain Admins is 0 just print out matches
			for m in hash_match:
				#Print result to screen
				print m

				#Check for fileoutput
				if len(filepath)!=0:
					fileoutput.append(m)

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

#Build List for file output
if len(filepath)!=0:
	fileoutput.append("\n[+]Statistics")
	fileoutput.append("[+]"+str(len(hash_list))+" Total Hashes in List")
	fileoutput.append("[+]"+str(len(unique_nt))+" Unique Hashes")
	fileoutput.append("[+]"+str(len(dup_hashes))+" Instances of password reuse were detected")
	fileoutput.append("[+]"+str(len(hash_sets))+" Sets of hash reuse")

#Output the number of instances of DA reuse this includes enabled and disabled accounts.
if len(da_list)>0:
	print colored("[+]"+str(len(da_reuse))+" instances of DA reuse detected",'yellow')
	#Check for fileoutput
	if len(filepath)!=0:
		fileoutput.append("[+]"+str(len(da_reuse))+" instances of DA reuse detected")

#Let's do a check for LM accounts find how many there are and output the account names to file.
if len(hash_list)>0:
	for item in hash_list:
		if not item.split(":")[2]=="aad3b435b51404eeaad3b435b51404ee":
			lm_accounts.append(item)
			
	if len(lm_accounts)>0:
		#Write lm account usernames to file
		fout=open("/tmp/lm_account_names.txt",'w')
		#Write details
		for x in lm_accounts:
			fout.write(x.split(":")[0]+"\n")
		#Close handle
		fout.close()

		print colored("[+]"+str(len(lm_accounts))+" LM hash(s) detected - account name(s) written to /tmp/lm_account_names.txt",'yellow')
		if len(filepath)!=0:
			fileoutput.append("[+]"+str(len(lm_accounts))+" LM hash(s) detected - account name(s) written to /tmp/lm_account_names.txt")

		#Write lm account usernames to file
		fout=open("/tmp/lm_accounts.txt",'w')
		#Write details
		for x in lm_accounts:
			fout.write(x+"\n")
		#Close handle
		fout.close()

		print colored("[+]"+str(len(lm_accounts))+" LM hash(s) detected - full account details written to /tmp/lm_accounts.txt",'yellow')
		if len(filepath)!=0:
			fileoutput.append("[+]"+str(len(lm_accounts))+" LM hash(s) detected - account details written to /tmp/lm_accounts.txt")


#If we have hashcat details and enabled accounts details let's get some stats
if len(hashcat_output)>0 and len(enabled)>0:
	for name in enabled:
		#Do an exact username match
		for acc_name in hashcat_output:
			usr1=acc_name.split(":")[0]
			if "\\" in usr1:
				usr1=usr1.split("\\")[1]

			if name == usr1:
				cracked_enabled.append(name)
				cracked_enabled_password.append(acc_name)
	
	#Write Cracked and Enabled Usernames to file
	fout=open("/tmp/cracked_enabled.txt",'w')
	#Write details
	for x in cracked_enabled:
		fout.write(x+"\n")
	#Close handle
	fout.close()

	print colored("[+]"+str(len(cracked_enabled))+" enabled account(s) where password has been cracked - written to /tmp/cracked_enabled.txt",'yellow')
	if len(filepath)!=0:
		fileoutput.append("[+]"+str(len(cracked_enabled))+" enabled account(s) where password has been cracked - written to /tmp/cracked_enabled.txt")

	#Write Cracked and Enabled Passwords to file
	fout=open("/tmp/cracked_enabled_passwords.txt",'w')
	#Write details
	for x in cracked_enabled_password:
		if len(x.split(":")[2].rstrip().lstrip())==0:
			fout.write("blankpw"+"\n")
			cracked_enabled_freq.append("blankpw")
		else:
			fout.write((x.split(":")[2]).rstrip()+"\n")
			cracked_enabled_freq.append((x.split(":")[2]).rstrip())
	#Close handle
	fout.close()

	print colored("[+]"+str(len(cracked_enabled_password))+" cracked enabled passwords written to /tmp/cracked_enabled_passwords.txt",'yellow')
	if len(filepath)!=0:
		fileoutput.append("[+]"+str(len(cracked_enabled_password))+" cracked enabled passwords written to /tmp/cracked_enabled_passwords.txt")

	#Check to see if da_list and cracked_enabled is greater than zero
	#Check to see which DA accounts have cracked passwords and write to file
	if len(da_list)>0 and len(cracked_enabled)>0:
		for da_name in da_list:
			for ce in cracked_enabled:
				if da_name in ce:
					cracked_enabled_da.append(da_name)

		fout=open("/tmp/cracked_enabled_da.txt",'w')
		#Write details
		for x in cracked_enabled_da:
			fout.write(x+"\n")
		#Close handle
		fout.close()

		print colored("[+]"+str(len(cracked_enabled_da))+" cracked and enabled DA account(s) - written to /tmp/cracked_enabled_da.txt",'yellow')
		if len(filepath)!=0:
			fileoutput.append("[+]"+str(len(cracked_enabled_da))+" cracked and enabled DA account(s)")

	#Let's figure out the top 20 most common enabled passwords
	a = Counter(cracked_enabled_freq)
	
	#print to file
	if len(filepath)!=0:
			fileoutput.append("\n[+]Most Common Enabled Passwords")
			fileoutput.append("Password\tInstances")

	#print to screen
	print colored ("\n[+]Most Common Enabled Passwords",'green')
	t = PrettyTable(['Password', 'Instances'])
	
	for letter, count in a.most_common(20):
		#print to screen
		t.add_row([letter, str(count)])
		
		#print to file
		if len(filepath)!=0:
			fileoutput.append(letter+"\t"+str(count))

	print t
	
	#Let's check complexity requirements
	#cracked_enabled_password
	print colored("\nChecking Windows Default Complexity Requirements against Cracked Enabled Passwords",'green')
	t = PrettyTable(['Issue', 'Username', 'Password'])
	
	#print to file
	if len(filepath)!=0:
		fileoutput.append("\nChecking Windows Default Complexity Requirements against Cracked Enabled Passwords")
		fileoutput.append("Issue, Username, Password")

	ccheck=0
	for password in cracked_enabled_password:
		count=0
		line=password.split(":")[2].rstrip()

		#Modify the 8 on the line below if the minimum has been changed.
		if len(line)<8:
			t.add_row(['Too Short', password.split(":")[0].rstrip(),line])
			ccheck+=1

			#print to file
			if len(filepath)!=0:
				fileoutput.append("Too Short, "+password.split(":")[0].rstrip()+", "+line)
		else:
			if re.search('([0-9])', line, flags=0):
				count+=1

			if re.search('([a-z])', line, flags=0):
				count+=1

			if re.search('([A-Z])', line, flags=0):
				count+=1

			if re.search('([\W_])', line, flags=0):
				count+=1

			if count<3:
				t.add_row(['Complexity requirements not met', password.split(":")[0].rstrip(),line])
				ccheck+=1

				#print to file
				if len(filepath)!=0:
					fileoutput.append("Complexity requirements not met, "+password.split(":")[0].rstrip()+", "+line)

	#Put check here to see if we have bad passwords?
	if ccheck>0:
		print t
	else:
		print colored ("No passwords found which don't meet complexity requirements",'yellow')
		#print to file
		if len(filepath)!=0:
			fileoutput.append("No passwords found which don't meet complexity requirements")

#Do some checks here for any passwords which are in the bad passwords list
if len(bad_list)>0:
	print colored("\nChecking for Passwords in Weak Password List",'green')
	z = PrettyTable(['Username', 'Password'])

	for u_hash in hash_list:
		for b_user in bad_list:
			if b_user.split(":")[1].rstrip()==u_hash.split(":")[3]:
				z.add_row([u_hash.split(":")[0].rstrip(),b_user.split(":")[0].rstrip()])			

	print z 

#Write Details to file
if len(filepath)!=0:
	#Open file
	fout=open(filepath,'w')
	#Write details
	for x in fileoutput:
		fout.write(x+"\n")
	#Close handle
	fout.close()
	#Check if file exists, if so print msg
	if os.path.exists(filepath):
		print colored ("\n[+]Details Successfully Written to "+filepath,'green')