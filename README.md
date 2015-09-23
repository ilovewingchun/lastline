This is a Python script that will help you to:<p>

1. Login to Lastline Manager web portal.
2. Download events that is Command&Control and with infection level priority(red).
3. Parse that events and extract bad destination IP addresses or Domain names and output to a file(default to block.txt)

By using this script, you will be able to automatically complete the above mentioned workflow. You can then publish that bad IP list and let products such as PaloAlto NGFW or Bluecoat ProxySG to come and get the list. So those inlince security devices and import and do blocking automatically.


There are two versions of this script:
#1. get_events.py:

This one takes inline arguments so you can do the job by running(testing) it and get results immediately.

Example usage:<p>
<pre><code>
$> python get_events.py -u abc@abc.com -k 123456789
Password: 

$> cat block.txt

156.154.103.3
202.46.190.131
178.19.108.142

$> python get_events.py -u abc@abc.com -k 123456789 -m domain
Password: 

$> cat block.txt

bad1.domain.com
bad2.domain.com
bad3.domain.com
</pre></code>
For more information about what inline arguments, please use -h to find out:<p>
<pre><code>
$> python get_events.py -h
usage: get_events.py [-h] [-o OUT_FILE] [-wl WHITELIST_FILE] -u USERNAME
                     [-host LASTLINE_HOST] -k KEY_ID [-sk SUBKEY_ID]
                     [-t DAYS_AGO] [-m METHOD] [-tz TIMEZONE]

This is a tool to extract IP addresses or domain names from an Lastline
Enterprise exported event file in JSON format.

optional arguments:
  -h, --help            show this help message and exit
  -o OUT_FILE, --output_file OUT_FILE
                        Optional. List of extracted bad remote IP addresses,
                        default to "block.txt"
  -wl WHITELIST_FILE, --whitelist_file WHITELIST_FILE
                        Optional. If you want to whitelist certain bad remote
                        IP, put them into a file and point the script to read.
                        This file default to "whitelist.txt"
  -u USERNAME, --username USERNAME
                        Required. Please enter your Lastline portal username.
  -host LASTLINE_HOST, --lastline_host LASTLINE_HOST
                        Optional. Lastline Manager host(IP/FQDN). Default to
                        "user.lastline.com.
  -k KEY_ID, --key-id KEY_ID
                        Required. Lastline Sensor licnese key id(not license
                        key). Please click on </> button on WEB GUI to get
                        this id. (E.g., 123456789)
  -sk SUBKEY_ID, --sub-key-id SUBKEY_ID
                        Optional. Sensor sub key id. Please check it in
                        Manager web portal in exported event url.
  -t DAYS_AGO, --timerange DAYS_AGO
                        Optional. Time Range. Enter how many days ago you want
                        to search for. Default to 7 days ago from now on. If
                        you would like to search in hours, you will need to
                        modify this script
  -m METHOD, --method METHOD
                        Optional. Extract IP or Domain name. Default to IP.
                        Set it to "ip" or "domain".
  -tz TIMEZONE, --timezone TIMEZONE
                        Optional. Your local timezone. Default to
                        "Asia/Taipei".

Lastline does not support this script! Use it at your own risk!
</pre></code>

#2. get_events_script.py

This one hard codes all core Lastline values so you can use a crontab to automatically run it in the background without user intervention. 

Example usage:<p>
<pre><code>
$> python get_events_script.py
$> cat block.txt 
156.154.103.3
202.46.190.131
178.19.108.142
</pre></code>
For bugs and feedback please report back to me:<p>
alphaone.tw@gmail.com or tyler@lastline.com
