1. Use "get_events.sh" to download events from Lastline Manager and save it to "events.json". Be sure to read the code itself and modify several parameters before using it. You can change the time window of how long you want your latest detected events being exported out from Manager.

2. The "extract_ip.py" is used to parse downloaded event file and extract ip information out and save it to another file default to "block_ip.txt". The "extract_ip.py" will look for entries in "whitelist.txt" file and not write them to "block_ip.txt", so put your white list entries in "whitelist.txt" file by yourself. Be sure you have "whitelist.txt" file in place or this script will fail to run.
3. "extract_dns.py" is trying to do the exact thing as "extract_ip.py" does. The difference between them is this one only extract bad domain names from "events.json".
4. Make a shell script to first run "get_events.sh" then "extract_ip.py". Put this script in cron table so it can work by schedule. 
