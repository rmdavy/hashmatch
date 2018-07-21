#! /usr/bin/python
import os,sys

try:
	from termcolor import colored 
except ImportError:
	print ('termcolor appears to be missing - try: pip install termcolor')
	logging.error("termcolor missing")
	exit(1)

#Define stuff here
hash_list = []
unique_nt=[]
hash_match=[]
da_list=[]
dirty=""

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
print colored("                                                                                      Version 1.0",'yellow')
print colored("                                                                                      @rd_pentest",'yellow')
print "\n"                                                                                       
                                                                                                  
#Hashes="/root/Desktop/192.168.0.37/nt.txt"
Hashes=raw_input("[+]Please enter path to hash file: ")
#DA_Path="/root/Desktop/da.txt"
DA_Path=raw_input("[+](Optional)If you have a list of Domain Admins enter path or press Enter: ")
#second_hash_list="/root/Desktop/192.168.0.37/nt.txt"
second_hash_list=raw_input("[+](Optional)If you have a second set of hashes enter path or press Enter: ")

#Check if DA list exists and if so open and add it list
if os.path.exists(DA_Path):
	print colored ("[+]Found file "+DA_Path,'green')
	with open(DA_Path) as dafp:
		for da in dafp:
			da_list.append(da.rstrip())

#Check if hashfile exists and if so open and add to list
#any problems error out nicely
if os.path.exists(Hashes):
	print colored ("[+]Found file "+Hashes,'green')
	with open(Hashes) as fp:
		for line in fp:
			hash_list.append(line.rstrip())
else:
	print colored ("\n[-]Error File not found "+Hashes+"\n",'red')
	sys.exit()

#Check to see if second hashes can be loaded
if os.path.exists(second_hash_list):
	print colored ("[+]Found file "+second_hash_list,'green')
	with open(second_hash_list) as fp:
		for line in fp:
			hash_list.append(line.rstrip())


#Build a list of NT hashes and make unique
for nt in hash_list:
	unique_nt.append(nt.split(":")[3])

#Build Unique List of NT hashes
unique_nt=set(unique_nt)

#Give some hash stat information
print colored ("[+]Total Hashes "+str(len(hash_list)),'yellow')
print colored ("[+]Total Unique Hashes "+str(len(unique_nt)),'yellow')

if len(hash_list)>len(unique_nt):
	print colored ("[+]Total Duplicate Hashes "+str(len(hash_list)-len(unique_nt)),'yellow')

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
		#Print the string hash match with a new line at the beginning and end
		print colored ("\nHash Match",'yellow')
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
						#change the dirty flag
						dirty="da"
				#if dirty flag is empty print match
				if dirty!="da":
					print m
				#Clear dirty flag
				dirty=""
		else:
		#If the list of Domain Admins is 0 just print out matches
			for m in hash_match:
				print m

	#empty matching hash list
	hash_match=[]