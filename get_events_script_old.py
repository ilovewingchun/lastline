#!/usr/bin/python
'''
# Author: Tyler Chen
# Contact: alphaone.tw@gmail.com or tyler@lastline.com
'''

# Core Lastline values
# Please input all the core Lastline values over here:
lastline_host = "user.lastline.com" # Required. Your on-premise IP/FQDN.
key_id = "" # Required. Lastline Sensor key id(not license key). Please click on </> button on WEB GUI to get this id. (E.g., 123456789)
subkey_id = "" # Optional. Lastline Sensor subkey id. Leave it blank if you do not want to filter event based on certain Sensor. (E.g., 1234567890)
llusername = "" # Required. Lastline web portal username in email format. (E.g., your@username)
llpassword = "" # Required. Lastline web portal password. (E.g., mypassword)
timerange = "7" # Required. Last N days you want to search for. Normally you will search for past 7 days, so you can put a digit number 7 here.
out_file = "blacklist.txt" # Required. Save results to this file name.
out_file_ip = "blacklist_dst_ip.txt" # Required. Save results to this file name.
out_file_domain = "blacklist_dst_domain.txt" # Required. Save results to this file name.
whitelist_file = "" # Optional. If you wish the script to NOT save certain results, eg. 8.8.8.8, please put them in this file in new line delimited format.
timezone = "Asia/Taipei" # Required. Please change it to your local time zone. It has to match with what is on Lastline WEB UI,
sslverify = False # Set to False if you have SSL certifiation problems

##### Starting our codes from here #####
from datetime import datetime, timedelta
try:
    import requests
except ImportError:
    print "[-] Error! Please install requests python module\nhttp://www.python-requests.org/en/latest/user/install/#install"
    sys.exit()
import json
import csv
import sys
import os
#import logging

print "[+] Initializing %s..." %(sys.argv[0])

# Check if user has provided enough core Lastline values:
if not key_id or not llusername or not llpassword:
    print "[-] Error! Not enough core Lastline values!"
    print "[-] Please edit this script and provide the correct core Lastline values!"
    sys.exit()

# Defining time variables
timenow = datetime.today()
lastNDaysDateTime = datetime.today() - timedelta(days = int(timerange))

# Lastline Manager(Hosted or On-premise)
lastline_url = "https://%s/ll_api/ll_api.php" % lastline_host
post_data_auth = {'func' : 'is_authenticated', 'username':llusername, 'password':llpassword}
params_get_events = {'func' : 'events', 'start_datetime':lastNDaysDateTime.strftime('%Y-%m-%d+%H:%M:%S'), 'end_datetime':timenow.strftime('%Y-%m-%d+%H:%M:%S'), 'key_id':key_id, 'priority':'Infections', 'threat_class':'command%26control','time_zone':timezone, 'whitelisting':'true', 'show_false_positives':'false', 'format':'json'}
if subkey_id:
    params_get_events['subkey_id'] = subkey_id

string_params = ''.join(['%s=%s&' % (k,v) for k,v in params_get_events.iteritems()])

# Trying to authenticate itself.
print "[+] Trying to authenticate with Manager."
try:
    req_auth = requests.post(lastline_url, data = post_data_auth, verify=sslverify)
    print "[+] Contacting Manager."
except Exception, e:
    print "[-] Error = " +str(e)
    print "[-] Possible network(or firewall) issues. Please check if you have provided correct Lastline host URL."
    print "[-] Please also check if your host can reach to Lastline host URL."
    sys.exit()
print "[+] Trying to download events."
try:
    req_get_events = requests.get(lastline_url, params = str(string_params), cookies = req_auth.cookies, verify=sslverify)
except Exception, e:
    print "[-] Error = " +str(e)
    sys.exit()
# Check if we have whitelist option definied.
if whitelist_file:
    try:
        wl = open(whitelist_file, 'r').read().splitlines() # Open white list file and remove newline(\n) within it.
    except Exception, e:
        print "[-] Error = " +str(e)
        sys.exit()

# Load json file and change it to dictionary, store in a variable called data.
try:
    data = json.loads(req_get_events.content) 
except Exception, e:
        print "[-] Error = " +str(e)
        print "[-] Possible network(or firewall) issues. Please check if you have provided correct Lastline host URL."
        print "[-] Please also check if your host can reach to Lastline host URL."
        sys.exit()

# Retrieve value for key called "data" inside variable data, store in a, this is a list.
print "[+] Parsing data."
try:
    a = data["data"] 
except Exception, e:
    print "[-] Error = " +str(e)
    print "[-] Please check your core Lastline values in the beginning of this script again!"
    sys.exit()
if not len(a) > 0:
    print "[-] Error! There is no data!"
    print "[-] Hint: Use WEB UI, go to Events, set filter to both 'Priority=Infections' and 'Class=Command&Controls', see if there is anything there."
    sys.exit()

# Empty list
c = []  # c is our list for both dst ip and dst domain
list_dst_ip = []
list_dst_domain = []
for i in range(len(a)): # Iterate over first level list
    ip = a[i]["dst_host"] # Iterate retrieve IP value for key "dst_host" inside list a
    c.append(ip) # Write each IP into our emtpy list c
    list_dst_ip.append(ip)
    if whitelist_file:
        c = [x for x in c if x not in wl] # Remove those entries that are inside whitelist.
        list_dst_ip = [x for x in list_dst_ip if x not in wl]
        c = list(set(c)) # Retrieve each elements inside list c, using set function to remove duplicate entries and store in c.
        list_dst_ip = list(set(list_dst_ip))
    else:
        c = list(set(c)) # Retrieve each elements inside list c, using set function to remove duplicate entries and store in c.
        list_dst_ip = list(set(list_dst_ip))
    hostname = a[i]["hostname"] # Iterate retrieve IP value for key "dst_host" inside list a
    c.append(hostname) # Write each IP into our emtpy list c
    list_dst_domain.append(hostname)
    if whitelist_file:
        c = [x for x in c if x not in wl] # Remove those entries that are inside whitelist.
        list_dst_domain = [x for x in list_dst_domain if x not in wl]
        c = list(set(c)) # Retrieve each elements inside list c, using set function to remove duplicate entries and store in c.
        list_dst_domain = list(set(list_dst_domain))
    else:
        c = list(set(c)) # Retrieve each elements inside list c, using set function to remove duplicate entries and store in c.
        list_dst_domain = list(set(list_dst_domain))
# Remove empty strings
c = filter(len,c)
list_dst_ip = filter(len,list_dst_ip)
list_dst_domain = filter(len,list_dst_domain)

# Sorting
c.sort()
list_dst_ip.sort()
list_dst_domain.sort()

print "[+] Successfully extracted IP/Domain."
print "[+] Now writing IP/Domain to our file '%s'." %(out_file)
fo = open(out_file, 'w') # Open a file to store our parsed result.
for item in range(len(c)): # Iterate over our list c.
    e = c[item] # Store each elements inside a new variable e
    w = csv.writer(fo, lineterminator="\n") # Using csv function to write each value to a newly definied variable w, which actually writes to previously opened file fo.
    w.writerow([e]) # Write each IP/Domain from e to destination file.
fo.close()
print "[+] Now writing IP to our file '%s'." %(out_file_ip)
fo = open(out_file_ip, 'w') # Open a file to store our parsed result.
for item in range(len(list_dst_ip)): # Iterate over our list c.
    e_ip = list_dst_ip[item] # Store each elements inside a new variable e
    w = csv.writer(fo, lineterminator="\n") # Using csv function to write each value to a newly definied variable w, which actually writes to previously opened file fo.
    w.writerow([e_ip]) # Write each IP/Domain from e to destination file.
fo.close()
print "[+] Now writing Domain to our file '%s'." %(out_file_domain)
fo = open(out_file_domain, 'w') # Open a file to store our parsed result.
for item in range(len(list_dst_domain)): # Iterate over our list c.
    e_domain = list_dst_domain[item] # Store each elements inside a new variable e
    w = csv.writer(fo, lineterminator="\n") # Using csv function to write each value to a newly definied variable w, which actually writes to previously opened file fo.
    w.writerow([e_domain]) # Write each IP/Domain from e to destination file.
fo.close()
print "[+] Successfully downloaded IP/Domain list into our file '%s'." %(out_file)
print "[+] Have a nice day!"
print ""
