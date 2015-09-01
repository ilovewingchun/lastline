#!/usr/bin/python
# -*- coding: UTF-8 -*-
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
#http://stackoverflow.com/questions/27921629/python-using-getpass-with-argparse
class PasswordPromptAction(argparse.Action):
    def __init__(self,
             option_strings,
             dest=None,
             nargs=0,
             default=None,
             required=False,
             type=None,
             metavar=None,
             help=None):
        super(PasswordPromptAction, self).__init__(
             option_strings=option_strings,
             dest=dest,
             nargs=nargs,
             default=default,
             required=required,
             metavar=metavar,
             type=type,
             help=help)

    def __call__(self, parser, args, values, option_string=None):
        password = getpass.getpass()
        setattr(args, self.dest, password)
parser = argparse.ArgumentParser(
                                 description = "This is a tool to extract IP addresses from an Lastline Enterprise exported event file in JSON format.",     # text displayed on top of --help
                                 epilog = 'Use it at your own risk!') # last text displayed
parser.add_argument('-o','--output_file',action="store",default='block_ip.txt',dest='out_file',help='List of extracted bad remote IP addresses, default to "block_ip.txt"')
parser.add_argument('-wl','--whitelist_file',action="store",default='whitelist.txt',dest='whitelist_file',help='If you want to whitelist certain bad remote IP, put them into a file and point the script to read. This file default to "whitelist.txt"')
parser.add_argument('-u','--username',dest='username', type=str, required=True, help='Please enter your Lastline portal username.')
parser.add_argument('-p','--password',dest='password', action=PasswordPromptAction, type=str, required=True, help='Please enter your Lastline portal password.')
parser.add_argument('-host','--lastline_host',action="store",default='user.lastline.com',dest='lastline_host',help='Lastline Manager host(IP/FQDN). Default to "user.lastline.com.' )
parser.add_argument('-k','--key-id',action="store",type=str, required=True, dest='key_id',help='License key id. Please check it in Manager web portal in exported event url.' )
parser.add_argument('-sk','--sub-key-id',action="store",type=str, dest='subkey_id',help='Sensor sub key id. Please check it in Manager web portal in exported event url.' )
parser.add_argument('-t','--timerange',dest='days_ago', type=int, default='7' ,help='Time Range. Enter how many days ago you want to search for. Default to 7 days ago from now on.\nIf you would like to search in hours, you will need to modify this script')

arguments = parser.parse_args()
timenow = datetime.today()
last1HourDateTime = datetime.today() - timedelta(hours = 1)
last8HourDateTime = datetime.today() - timedelta(hours = 8)
last24HourDateTime = datetime.today() - timedelta(hours = 24)
last7DaysDateTime = datetime.today() - timedelta(days = 7)
last31DaysDateTime = datetime.today() - timedelta(days = 31)
lastNDaysDateTime = datetime.today() - timedelta(days = arguments.days_ago)

lastline_host = arguments.lastline_host
key_id = arguments.key_id
subkey_id = arguments.subkey_id
llusername = arguments.username
llpassword = arguments.password

lastline_url = "https://%s/ll_api/ll_api.php" % lastline_host
post_data_auth = {'func' : 'is_authenticated', 'username':llusername, 'password':llpassword}
params_get_events = {'func' : 'events', 'start_datetime':lastNDaysDateTime.strftime('%Y-%m-%d+%H:%M:%S'), 'end_datetime':timenow.strftime('%Y-%m-%d+%H:%M:%S'), 'key_id':key_id, 'priority':'Infections', 'threat_class':'command%26control','time_zone':'Asia/Taipei', 'whitelisting':'true', 'show_false_positives':'false', 'format':'json'}
if subkey_id:
	params_get_events['subkey_id'] = subkey_id
string_params = ''.join(['%s=%s&' % (k,v) for k,v in params_get_events.iteritems()])
req_auth = requests.post(lastline_url, data = post_data_auth)
req_get_events = requests.get(lastline_url, params = str(string_params), cookies = req_auth.cookies)
# look at dest in the parser.add_argument lines
out_file = arguments.out_file
whitelist_file = arguments.whitelist_file
if os.path.exists('whitelist'):
	wl = open('whitelist.txt', 'r').read().splitlines() # Open white list file and remove newline(\n) within it.
data = json.loads(req_get_events.content) # Load json file and change it to dictionary, store in a variable called data.
try:
    a = data["data"] # Retrieve value for key called "data" inside variable data, store in a, this is a list.
except KeyError:
    print "[-] Error! Cannot get data!\nPlease check your parameters such as username and password!"
    sys.exit()
if not len(a) > 0:
    print "[-] Error! There is no data!"
    print "[-] Hint: Use WEB UI, go to Events, set filter to both 'Priority=Infections' and 'Class=Command&Controls', see if there is anything there."
    sys.exit()
fo = open(out_file, 'w') # Open a file to store our parsed result.
c = []  # Empty list
for i in range(len(a)): # Iterate over first level list
    b = a[i]["dst_host"] # Iterate retrieve IP value for key "dst_host" inside list a
    c.append(b) # Write each IP into our emtpy list c
    if os.path.exists('whitelist'):
    	c = [x for x in c if x not in wl] # Remove those entries that are inside whitelist.
    else:
    	d = list(set(c)) # Retrieve each elements inside list c, using set function to remove duplicate entries and store in d.
for item in range(len(d)): # Iterate over our list d.
    e = d[item] # Store each elements inside a new variable e
    w = csv.writer(fo, lineterminator="\n") # Using csv function to write each value to a newly definied variable w, which actually writes to previously opened file fo.
    w.writerow([e]) # Write each IP from e to destination file.
fo.close()