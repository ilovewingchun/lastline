1. Use "get_events.sh" to download events from Lastline Manager and save it to "events.json". Be sure to read the code itself and modify several parameters before using it. You can change the time window of how long you want your latest detected events being exported out from Manager.

2. The "extract_ip.py" is used to parse downloaded event file and extract ip information out and save it to another file default to "block_ip.txt". The "extract_ip.py" will look for entries in "whitelist.txt" file and not write them to "block_ip.txt", so put your white list entries in "whitelist.txt" file by yourself. Be sure you have "whitelist.txt" file in place or this script will fail to run.
3. "extract_dns.py" is trying to do the exact thing as "extract_ip.py" does. The difference between them is this one only extract bad domain names from "events.json" and save it to "block_dns.txt".
4. Make a shell script to first run "get_events.sh" then "extract_ip.py". Put this script in cron table so it can work by schedule. For example you should have something like this in your /etc/crontab file:

45 * * * * root sh /home/tyler/lastline.sh

And the content of lastline.sh should look something like this:

#!/bin/bash
/bin/bash /root/get_events.sh
/usr/bin/python /root/extract_ip.py -o /var/www/block_ip.txt
exit 0

Notice you can use -o option to tell extract_ip.py to save output file to another location.

5. Use a Apache server to host your latest "block_ip.txt" or "block_dns.txt" and let PaloAlto to retrieve it using Dynamic Block List. The same idea applies to Bluecoat SG Proxy.

All my scripts and my files are look like this:

shell> ls -al /root/get_events.sh /root/extract_ip.py /root/events.json /var/www/block_ip.txt 
-rw-r--r-- 1 root root 592725 Nov  4 10:45 /root/events.json
-rwxr-xr-x 1 root root   3171 Mar 25  2014 /root/extract_ip.py
-rwxr-xr-x 1 root root   1849 Mar 25  2014 /root/get_events.sh
-rw-r--r-- 1 root root    128 Nov  4 10:45 /var/www/block_ip.txt
