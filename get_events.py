#!/usr/bin/python
# -*- coding: UTF-8 -*-
# Author: Tyler Chen
# Contact: alphaone.tw@gmail.com or tyler@lastline.com
from datetime import datetime, timedelta
try:
	import requests
except ImportError:
	print "Please install requests python module\nhttp://www.python-requests.org/en/latest/user/install/#install"
	sys.exit()
import json
import csv
import argparse
from pprint import pprint
import sys
import os
import getpass
# Is there argparse to use?
try:
    import argparse
except ImportError:
    print "[-] Error! Please install the argparse python module\non Debian systems you can use:\napt-get install python-argparse"
    sys.exit()

parser = argparse.ArgumentParser(
                                 description = "This is a tool to extract IP addresses or domain names from an Lastline Enterprise exported event file in JSON format.",     # text displayed on top of --help
                                 epilog = 'Lastline does not support this script! Use it at your own risk!') # last text displayed
parser.add_argument('-o','--output_file',action="store",default='block.txt',dest='out_file',help='Optional. List of extracted bad remote IP addresses, default to "block.txt"')
parser.add_argument('-wl','--whitelist_file',action="store",dest='whitelist_file',help='Optional. If you want to whitelist certain bad remote IP, put them into a file and point the script to read. This file default to "whitelist.txt"')
parser.add_argument('-u','--username',dest='username', type=str, required=True, help='Required. Please enter your Lastline portal username.')
parser.add_argument('-host','--lastline_host',action="store",default='user.lastline.com',dest='lastline_host',help='Optional. Lastline Manager host(IP/FQDN). Default to "user.lastline.com.' )
parser.add_argument('-k','--key-id',action="store",type=str, required=True, dest='key_id',help='Required. Lastline Sensor licnese key id(not license key). Please click on </> button on WEB GUI to get this id. (E.g., 123456789)' )
parser.add_argument('-sk','--sub-key-id',action="store",type=str, dest='subkey_id',help='Optional. Sensor sub key id. Please check it in Manager web portal in exported event url.' )
parser.add_argument('-t','--timerange',dest='days_ago', type=int, default='7' ,help='Optional. Time Range. Enter how many days ago you want to search for. Default to 7 days ago from now on.\nIf you would like to search in hours, you will need to modify this script')
parser.add_argument('-m','--method',action="store", dest='method', type=str, required=False, default='ip',help='Optional. Extract IP or Domain name. Default to IP. Set it to "ip" or "domain".')
parser.add_argument('-tz','--timezone',action="store", dest='timezone', type=str, required=False, default='Asia/Taipei', help='Optional. Your local timezone. Default to "Asia/Taipei".')

arguments = parser.parse_args()

# Defining time variables
timerange = arguments.days_ago
timenow = datetime.today()
lastNDaysDateTime = datetime.today() - timedelta(days = int(timerange))

# Core Lastline values
lastline_host = arguments.lastline_host
key_id = arguments.key_id
subkey_id = arguments.subkey_id
llusername = arguments.username
llpassword = getpass.getpass()
timezone = arguments.timezone
method = arguments.method

lastline_url = "https://%s/ll_api/ll_api.php" % lastline_host
post_data_auth = {'func' : 'is_authenticated', 'username':llusername, 'password':llpassword}
params_get_events = {'func' : 'events', 'start_datetime':lastNDaysDateTime.strftime('%Y-%m-%d+%H:%M:%S'), 'end_datetime':timenow.strftime('%Y-%m-%d+%H:%M:%S'), 'key_id':key_id, 'priority':'Infections', 'threat_class':'command%26control','time_zone':timezone, 'whitelisting':'true', 'show_false_positives':'false', 'format':'json'}
if subkey_id:
	params_get_events['subkey_id'] = subkey_id
string_params = ''.join(['%s=%s&' % (k,v) for k,v in params_get_events.iteritems()])

# Check if user has provided enough core Lastline values:
if not key_id or not llusername or not llpassword:
    print "[-] Error! Not enough core Lastline values!"
    print "[-] Please edit this script and provide the correct core Lastline values!"
    sys.exit()

if method == "ip":
    print "[+] Trying to download bad destination 'IP' for past %s days." %(timerange)
    print "[+] Please wait..."
    print ""
elif method == "domain":
    print "[+] Trying to download bad destination 'Domain names' for past %s days." %(timerange)
    print "[+] Please wait..."
    print ""
else:
    print "[-] Error! Wrong method."
    print "[-] Please edit this script and provide the correct core Lastline values!"
    sys.exit()

# Trying to authenticate itself.
try:
    req_auth = requests.post(lastline_url, data = post_data_auth)
except Exception, e:
    print "[-] Error = " +str(e)
    print "[-] Please check your username and password, and Lastline host URL."
    sys.exit()
try:
    req_get_events = requests.get(lastline_url, params = str(string_params), cookies = req_auth.cookies)
except Exception, e:
    print "[-] Error = " +str(e)
    sys.exit()
# look at dest in the parser.add_argument lines
out_file = arguments.out_file
whitelist_file = arguments.whitelist_file
# Check if we have whitelist option definied.
if whitelist_file:
    try:
	   wl = open(whitelist_file, 'r').read().splitlines() # Open white list file and remove newline(\n) within it.
    except Exception, e:
        print "[-] Error = " +str(e)
        sys.exit()
try:
    data = json.loads(req_get_events.content) # Load json file and change it to dictionary, store in a variable called data.
except Exception, e:
    print "[-] Error = " +str(e)
    print "[-] Possible network(or firewall) issues. Please check if you have provided correct Lastline host URL."
    print "[-] Please also check if your host can reach to Lastline host URL."
    sys.exit()
try:
    a = data["data"] # Retrieve value for key called "data" inside variable data, store in a, this is a list.
except Exception:
    print "[-] Error = There is no data"
    print "[-] Do you have correct username and password?"
    sys.exit()
if not len(a) > 0:
    print "[-] Error! There is no data!"
    print "[-] Hint: Use WEB UI, go to Events, set filter to both 'Priority=Infections' and 'Class=Command&Controls', see if there is anything there."
    sys.exit()
fo = open(out_file, 'w') # Open a file to store our parsed result.
c = []  # Empty list
for i in range(len(a)): # Iterate over first level list
    if method == "ip":
        b = a[i]["dst_host"] # Iterate retrieve IP value for key "dst_host" inside list a
        c.append(b) # Write each IP into our emtpy list c
        if whitelist_file:
    	   c = [x for x in c if x not in wl] # Remove those entries that are inside whitelist.
           c = list(set(c)) # Retrieve each elements inside list c, using set function to remove duplicate entries and store in c.
        else:
    	   c = list(set(c)) # Retrieve each elements inside list c, using set function to remove duplicate entries and store in c.
    elif method == "domain":
        b = a[i]["hostname"] # Iterate retrieve IP value for key "dst_host" inside list a
        c.append(b) # Write each IP into our emtpy list c
        if whitelist_file:
           c = [x for x in c if x not in wl] # Remove those entries that are inside whitelist.
           c = list(set(c)) # Retrieve each elements inside list c, using set function to remove duplicate entries and store in c.
        else:
           c = list(set(c)) # Retrieve each elements inside list c, using set function to remove duplicate entries and store in c.
    else:
        print "[-] Error! Cannot iterate over the data."
        print "[-] Please check the method argument again."

# Remove empty strings in list c
c = filter(len,c)

print "[+] Successfully extracted data '%s'." %(method)
print "[+] Now writing data to our file '%s'." %(out_file)
for item in range(len(c)): # Iterate over our list c.
    e = c[item] # Store each elements inside a new variable e
    w = csv.writer(fo, lineterminator="\n") # Using csv function to write each value to a newly definied variable w, which actually writes to previously opened file fo.
    w.writerow([e]) # Write each IP from e to destination file.
fo.close()
print "[+] Successfully downloaded '%s' list into our file '%s'." %(method, out_file)
print "[+] Have a nice day!"
print ""