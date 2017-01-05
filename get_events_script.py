#!/usr/bin/python
# -*- coding: UTF-8 -*-
'''
Author: Tyler Chen ( tyler@lastline.com / alphaone.tw@gmail.com )
Date: 2016-08-16
This script will help you to download events from Lastline Manager, then output to blacklist files.
Please change the following paramaters before using.
'''
print "[+] Initializing..."
from datetime import datetime, timedelta
verbose_logging = 1  # Set this to 1 if you need to debug something.
lastline_host = "user.lastline.com" # Required. Your on-premise IP/FQDN.
key_id = "" # Required. Lastline Sensor licnese key id(not license key). Please click on </> button on WEB GUI to get this id. (E.g., 123456789)
subkey_id = "" # Optional. Lastline Sensor subkey id. Leave it blank if you do not want to filter event based on certain Sensor. (E.g., 1234567890)
llusername = "" # Required. Lastline web portal username in email format. (E.g., your@username)
llpassword = "" # Required. Lastline web portal password. (E.g., mypassword)
timerange = "7" # Required. Last N days you want to search for. Normally you will search for past 7 days, so you can put a digit number 7 here.
timezone = "Asia/Taipei" # Required. Please change it to your local time zone. It has to match with what is on Lastline WEB UI,
net_event_min_impact = 70 # Put a value between 0~100. Only export events with impact score higher than this value.
out_file_all                            = "/var/www/blacklist.txt"
out_file_ip                             = "/var/www/blacklist_dst_ip.txt"                              # Required. Save results to this file name.
out_file_domain                         = "/var/www/blacklist_dst_domain.txt"                          # Required. Save results to this file name.
whitelist_file = "/var/www/whitelist.txt"      # Optional. If you wish the script to NOT save certain results, eg. 8.8.8.8, please put them in this file in new line delimited format.
whitelist_file_src = ""                 # Optional. Use this file to exclude source IP for counting.
filter_src_ip = ""                      # Optional. Use this to skip for certain source IP.
sslverify = False # Set to False if you have SSL certifiation problems, otherwise you should set it to True.
headers = { "User-Agent": "Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/32.0.1667.0 Safari/537.36"}
bluecoat = 0 # Set this to 1 if you need blacklist.txt format to be Bluecoat compatitable 
# Create an empty list blacklist for later use...
blacklist = []
# Defining time variables
timenow = datetime.today()
lastNDaysDateTime = datetime.today() - timedelta(days = int(timerange))

##### Starting our codes from here #####
print "[+] Initialized, working on."
print "[+] Please wait..."

try:
    import requests
except ImportError:
    print "[!] Error! Please install requests python module\nhttp://www.python-requests.org/en/latest/user/install/#install"
    sys.exit()

# Turn off SSL verification warning
if sslverify == False:
    requests.packages.urllib3.disable_warnings()

import json
import csv
import sys
import os

# Check if user has provided enough core Lastline values:
if not key_id or not llusername or not llpassword:
    print "[!] Error! Not enough core Lastline values!"
    print "[!] Please edit this script and provide the correct core Lastline values!"
    sys.exit()

def authenticate_myself(username, password):
    lastline_url = "https://%s/papi/login.json" %lastline_host
    post_data_auth = {'username':username, 'password':password}
    if verbose_logging == 1: print "[+] Trying to authenticate with Manager."
    req_auth = requests.post(lastline_url, data = post_data_auth, verify=sslverify, headers=headers)
    if req_auth.json()["success"] == 0:
        print "-"*60
        print "[!] Error: Login to Manager failed. Please check Manager URL and your username/password."
        print "[!] Exiting."
        sys.exit()
    if verbose_logging == 1: print "[+] Authentication successful!"
    return req_auth

def tocsv(out_file, list_data):
    global bluecoat
    with open(out_file, 'wb') as fo:
        writer = csv.writer(fo, dialect='excel', delimiter=' ')
        if bluecoat == 1: writer.writerow( ( 'define', 'category', 'Lastline_Blacklist' ))
        for item in range(len(list_data)):
            temp = list_data[item]
            data = csv.writer(fo, lineterminator="\n")
            writer.writerow([temp])
    fo.close()    
    if bluecoat == 1: 
        fd = open(out_file, 'a')
        fd.write('end')
        fd.close()
    print "[+] Saving results into '%s'." %(out_file)
    return

# get_network_events('/event/list', 'dst_host', 1, '/var/www/html/bad_ip.txt', **kwargs )
def get_network_events(querytype, eventtype, verbose_logging, out_file, **kwargs):
    list_2d = []
    lastline_url = "https://%s/papi/net%s" % (lastline_host,querytype)
    params_get_events = {'start_datetime':lastNDaysDateTime.strftime('%Y-%m-%d+%H:%M:%S'), 'end_datetime':timenow.strftime('%Y-%m-%d+%H:%M:%S'), 'key_id':key_id, 'min_impact':net_event_min_impact, 'threat_class':'command%26control','time_zone':timezone, 'whitelisting':'true', 'show_false_positives':'false', 'format':'json', 'event_mode':'real', 'orderby': 'impact+DESC'}
    global subkey_id
    if subkey_id:
        params_get_events['subkey_id'] = subkey_id
    for name, value in kwargs.items():
        params_get_events.update({name:value})
    params_get_events = ''.join(['%s=%s&' % (k,v) for k,v in params_get_events.iteritems()])
    if verbose_logging == 1:
        print "[+] Trying to download %s." %(querytype)
        print "[+] Using '%s' as our paramters." %(str(params_get_events))
    req_get_events = requests.get(lastline_url, params = str(params_get_events), cookies = req_auth.cookies, verify=sslverify, headers=headers) 
    if len(req_get_events.json()["data"]) == 0:
        print "-"*60
        print "[!] Warning: No %s found!" %(querytype)
    elif verbose_logging == 1:
        print "[+] Download %s successful!" %(querytype)
    global whitelist_file
    if whitelist_file:
        wl = open(whitelist_file, 'r').read().splitlines()
    data = json.loads(req_get_events.content)["data"]
    if verbose_logging == 1: 
        print "[+] Now extracting %s from %s." %(eventtype, querytype)
    for i in range(len(data)):
        temp = data[i][eventtype]
        list_2d.append(temp)
        if whitelist_file:
            list_2d = [x for x in list_2d if x not in wl]
    if verbose_logging == 1: 
        print "[+] Successfully extracted %s from %s." %(eventtype, querytype)
    if verbose_logging == 1: 
        print "[+] Now encoding %s information" %(eventtype)
    list_2d = [s.encode('utf8') for s in list_2d] # Make sure we don't return unrecognizable characters
    list_2d = filter(len,list_2d) # Removing empty item in list
    list_2d = list(set(list_2d)) # Using set function to remove duplicate entries
    list_2d = sorted(list_2d)
    if verbose_logging == 1: 
        print "[+] Calling CSV function to save %s results." %(eventtype)
    tocsv(out_file, list_2d)
    global blacklist
    blacklist += list_2d
    return
try:
    req_auth = authenticate_myself(llusername, llpassword)
except Exception, e:
    print "[!] Error = " +str(e)
    print "[!] Cannot complete authenticate function!"
    sys.exit()

# Start the actual event downloading from here.
# Download network event
try:
    get_network_events('/event/list', 'dst_host', verbose_logging, out_file_ip, transport='TCP')
except Exception, e:
    print "[!] Error = " +str(e)
    print "[!] Cannot download bad C&C IP!"

# Download network event
try:
    get_network_events('/event/list', 'hostname', verbose_logging, out_file_domain, transport='UDP')
except Exception, e:
    print "[!] Error = " +str(e)
    print "[!] Cannot download bad C&C Domain!"

# Writing both IP and Domain into a single file
try:
    tocsv(out_file_all, blacklist) 
except Exception, e:
    print "[!] Error = " +str(e)
    print "[!] Cannot write full blacklist!"

# Wrapping up
print "-"*60
print "[+] All jobs done successfully."
print "[+] Exiting, have a nice day!"
print ""