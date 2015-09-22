This is a Python script that will help you to:

1. Login to Lastline Manager web portal.
2. Download events that is Command&Control and with infection level priority(red).
3. Parse that events and extract bad destination IP addresses or Domain names and output to a file(default to block.txt)

By using this script, you will be able to automatically complete the above mentioned workflow. You can then publish that bad IP list and let products such as PaloAlto NGFW or Bluecoat ProxySG to come and get the list. So those inlince security devices and import and do blocking automatically.


There are two version of this script.

get_events.py:

This one takes inline arguments so you can do the job by running it once.

Example usage:

$> python get_events.py -host user.lastline.com -u abc@abc.com -p -k 123456789

Password: 

$> cat block_ip.txt

156.154.103.3
202.46.190.131
178.19.108.142

For more information about what inline arguments, please use -h to find out:

$> python get_events.py -h

usage: get_events.py [-h] [-o OUT_FILE] [-wl WHITELIST_FILE] -u USERNAME -p [-host LASTLINE_HOST] -k KEY_ID [-sk SUBKEY_ID]

This is a tool to extract IP addresses from an Lastline Enterprise exported event file in JSON format.

optional arguments:


-h, --help show this help message and exit

-o OUT_FILE, --output_file OUT_FILE List of extracted bad remote IP addresses, default to "block_ip.txt"

-wl WHITELIST_FILE, --whitelist_file WHITELIST_FILE If you want to whitelist certain bad remote IP, put them into a file and point the script to read. This file default to "whitelist.txt"

-u USERNAME, --username USERNAME Please enter your Lastline portal username.

-p, --password Please enter your Lastline portal password.

-host LASTLINE_HOST, --lastline_host LASTLINE_HOST Lastline Manager host(IP/FQDN). Default to "user.lastline.com.

-k KEY_ID, --key-id KEY_ID License key id. Please check it in Manager web portal in exported event url.

-sk SUBKEY_ID, --sub-key-id SUBKEY_ID Sensor sub key id. Please check it in Manager web portal in exported event url.

Use it at your own risk!

get_events_script.py

This one hard codes all core Lastline values so you can use a crontab to automatically run it in the background without user intervention. 

Example usage:

$> python get_events_script.py
$> cat block_ip.txt 
156.154.103.3
202.46.190.131
178.19.108.142

For bugs and feedback please report back to me:
alphaone.tw@gmail.com or tyler@lastline.com
