#!/usr/bin/python
# -*- coding: UTF-8 -*-
'''
This script will help you to download events and count top-n values for you.
It will count top-n destination IP and Domain name and save the results to csv files.
Please change the following paramaters.
'''
print "[+] Initializing..."

lastline_host = "user.lastline.com" # Required. Your on-premise IP/FQDN.
key_id = "" # Required. Lastline Sensor licnese key id(not license key). Please click on </> button on WEB GUI to get this id. (E.g., 123456789)
subkey_id = "" # Optional. Lastline Sensor subkey id. Leave it blank if you do not want to filter event based on certain Sensor. (E.g., 1234567890)
llusername = "" # Required. Lastline web portal username in email format. (E.g., your@username)
llpassword = "" # Required. Lastline web portal password. (E.g., mypassword)
timerange = "7" # Required. Last N days you want to search for. Normally you will search for past 7 days, so you can put a digit number 7 here.
out_file_ip = "top_n_dst_ip.csv" # Required. Save results to this file name.
out_file_domain = "top_n_dst_domain.csv" # Required. Save results to this file name.
out_file_llfiletype = "top_n_mail_filetype.csv" # Required. Save results to this file name.
out_file_sender = "top_n_mail_sender.csv" # Required. Save results to this file name.
out_file_recipient = "top_n_mail_recipient.csv" # Required. Save results to this file name.
out_file_subject = "top_n_mail_subject.csv" # Required. Save results to this file name.
out_file_file_name = "top_n_mail_file_name.csv" # Required. Save results to this file name.
whitelist_file = "" # Optional. If you wish the script to NOT save certain results, eg. 8.8.8.8, please put them in this file in new line delimited format.
timezone = "Asia/Taipei" # Required. Please change it to your local time zone. It has to match with what is on Lastline WEB UI,
topn = 10
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
from collections import Counter
#import logging

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
params_query_mail_attachments = {'func' : 'query_mail_attachments', 'start_time':lastNDaysDateTime.strftime('%Y-%m-%d+%H:%M:%S'), 'end_time':timenow.strftime('%Y-%m-%d+%H:%M:%S'), 'key_id':key_id, 'min_score':'30', 'time_zone':timezone, 'whitelisting':'true', 'show_false_positives':'false', 'format':'json'}

if subkey_id:
    params_get_events['subkey_id'] = subkey_id
    params_query_mail_attachments['subkey_id'] = subkey_id

string_params = ''.join(['%s=%s&' % (k,v) for k,v in params_get_events.iteritems()])
string_params_mail_attachments = ''.join(['%s=%s&' % (k,v) for k,v in params_query_mail_attachments.iteritems()])

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
print "[+] Events downloaded."

# Check if we have whitelist option definied.
if whitelist_file:
    try:
        wl = open(whitelist_file, 'r').read().splitlines() # Open white list file and remove newline(\n) within it.
    except Exception, e:
        print "[-] Error = " +str(e)
        sys.exit()

print "[+] Trying to download EMAIL events."
try:
    req_query_mail_attachments = requests.get(lastline_url, params = str(string_params_mail_attachments), cookies = req_auth.cookies, verify=sslverify)
except Exception, e:
    print "[-] Error = " +str(e)
    sys.exit()
print "[+] EMAIL events downloaded."

# Load json file and change it to dictionary, store in a variable called data.
try:
    data = json.loads(req_get_events.content) 
except Exception, e:
        print "[-] Error = " +str(e)
        print "[-] Possible network(or firewall) issues. Please check if you have provided correct Lastline host URL."
        print "[-] Please also check if your host can reach to Lastline host URL."
        sys.exit()

try:
    data_mail_attachments = json.loads(req_query_mail_attachments.content) 
except Exception, e:
        print "[-] Error = " +str(e)
        print "[-] Possible network(or firewall) issues. Please check if you have provided correct Lastline host URL."
        print "[-] Please also check if your host can reach to Lastline host URL."
        sys.exit()

# Retrieve value for key called "data" inside variable data, store in a, this is a list.
print "[+] Checking data."
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

print "[+] Checking email event data."
try:
    mail_data = data_mail_attachments["data"] 
except Exception, e:
    print "[-] Error = " +str(e)
    print "[-] Please check your core Lastline values in the beginning of this script again!"
    sys.exit()
if not len(mail_data) > 0:
    print "[-] Error! There is no email data!"
    sys.exit()

# Empty list
list_dst_ip = []
list_dst_domain = []

# Empty list for email data
list_llfiletype = []
list_sender = []
list_recipient = []
list_subject = []
list_file_name = []

print "[+] Now extracting IP/Domain from data."
for i in range(len(a)): # Iterate over first level list
    ip = a[i]["dst_host"] # Iterate retrieve IP value for key "dst_host" inside list a
    list_dst_ip.append(ip)
    if whitelist_file:
        list_dst_ip = [x for x in list_dst_ip if x not in wl]
    hostname = a[i]["hostname"] # Iterate retrieve IP value for key "dst_host" inside list a
    list_dst_domain.append(hostname)
    if whitelist_file:
        list_dst_domain = [x for x in list_dst_domain if x not in wl]
print "[+] Successfully extracted IP/Domain from data."
print "[+] Now extracting EMAIL information from data."
for i in range(len(mail_data)): # Iterate over first level list
    list_llfiletype.append(mail_data[i]["llfiletype"])
    list_sender.append(mail_data[i]["sender"])
    list_recipient.append(mail_data[i]["recipient"])
    list_subject.append(mail_data[i]["subject"])
    list_file_name.append(mail_data[i]["file_name"])
print "[+] Successfully extracted EMAIL information from data."

print "[+] Encoding information"
list_dst_ip = [s.encode('utf8') for s in list_dst_ip]
list_dst_domain = [s.encode('utf8') for s in list_dst_domain]
list_llfiletype = [s.encode('utf8') for s in list_llfiletype]
list_sender = [s.encode('utf8') for s in list_sender]
list_recipient = [s.encode('utf8') for s in list_recipient]
list_subject = [s.encode('utf8') for s in list_subject]
list_file_name = [s.encode('utf8') for s in list_file_name]

print "[+] Couting TOP-N"
topn_result_dst_ip = Counter(list_dst_ip).most_common(topn)
topn_result_dst_domain = Counter(list_dst_domain).most_common(topn)
topn_result_llfiletype = Counter(list_llfiletype).most_common(topn)
topn_result_sender = Counter(list_sender).most_common(topn)
topn_result_recipient = Counter(list_recipient).most_common(topn)
topn_result_subject = Counter(list_subject).most_common(topn)
topn_result_file_name = Counter(list_file_name).most_common(topn)

def tocsv(out_file, topn_result):
    with open(out_file, 'wb') as fo:
        writer = csv.writer(fo, dialect='excel', delimiter=',')
        writer.writerow( ( 'ITEM', 'COUNT' ))
        writer.writerows(topn_result)
    fo.close()
    print "[+] Saving TOP-%s results into '%s'." %(topn, out_file)
    return

print "Start writing TOP-%s results into specified files." %topn
try:
    tocsv(out_file_ip, topn_result_dst_ip)
except Exception, e:
    print "[-] Error = " +str(e)
    print "[-] Failed to save TOP-%s results into '%s'." %(topn, out_file_ip)
    sys.exit()

try:
    tocsv(out_file_domain, topn_result_dst_domain)
except Exception, e:
    print "[-] Error = " +str(e)
    print "[-] Failed to save TOP-%s results into '%s'." %(topn, out_file_domain)
    sys.exit()

try:
    tocsv(out_file_llfiletype, topn_result_llfiletype)
except Exception, e:
    print "[-] Error = " +str(e)
    print "[-] Failed to save TOP-%s results into '%s'." %(topn, out_file_llfiletype)
    sys.exit()

try:
    tocsv(out_file_sender, topn_result_sender)
except Exception, e:
    print "[-] Error = " +str(e)
    print "[-] Failed to save TOP-%s results into '%s'." %(topn, out_file_sender)
    sys.exit()

try:
    tocsv(out_file_recipient, topn_result_recipient)
except Exception, e:
    print "[-] Error = " +str(e)
    print "[-] Failed to save TOP-%s results into '%s'." %(topn, out_file_recipient)
    sys.exit()

try:
    tocsv(out_file_subject, topn_result_subject)
except Exception, e:
    print "[-] Error = " +str(e)
    print "[-] Failed to save TOP-%s results into '%s'." %(topn, out_file_subject)
    sys.exit()

try:
    tocsv(out_file_subject, topn_result_subject)
except Exception, e:
    print "[-] Error = " +str(e)
    print "[-] Failed to save TOP-%s results into '%s'." %(topn, out_file_subject)
    sys.exit()
try:
    tocsv(out_file_file_name, topn_result_file_name)
except Exception, e:
    print "[-] Error = " +str(e)
    print "[-] Failed to save TOP-%s results into '%s'." %(topn, out_file_file_name)
    sys.exit()

print "[+] All jobs done successfully."
print "[+] Exiting, have a nice day!"
print ""