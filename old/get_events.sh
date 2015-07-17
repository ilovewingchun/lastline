#!/bin/bash
# This script is tested under CentOS 6/Ubuntu 12.04
# Author: Tyler Chen
# Date: 2014 May 7
# Version: 1.4
# Let's define some time variables first:
time_now=$(date +"%Y-%m-%d+%H:%M:%S")
time_last6hours=$(date --date='-6 hours' +"%Y-%m-%d+%H:%M:%S")
time_last24hours=$(date --date='-24 hours' +"%Y-%m-%d+%H:%M:%S")
time_last7days=$(date --date='-7 days' +"%Y-%m-%d+%H:%M:%S")
time_last14days=$(date --date='-14 days' +"%Y-%m-%d+%H:%M:%S")
time_last31days=$(date --date='-31 days' +"%Y-%m-%d+%H:%M:%S")
# Here are two lastline variables. If you are going to pull data from a local manager, change lastline_url to your local manager ip/fqdn.
# Sensor key_id will not change after it is determined by Manager. Just log in to Manager web portal to see what your sensor id is.
# Change these values to fit your requirement
time_start=$time_last7days
lastline_url="user.lastline.com"
key_id="" # Something like 441385527
username=""
password=""

# Here we start our dirty work...
# First we will need to be authenticated. Web account / password is hard-coded here.
curl -k -s -b curl.cookie -c curl.cookie -d "username=$username&password=$password&func=is_authenticated" https://$lastline_url/ll_api/ll_api.php > /dev/null

# After successfully authenticated to Manager, we start download our event with filter infection(score above 70) and class command&control and save it to "events.json"
curl -k -s -b curl.cookie -c curl.cookie "https://$lastline_url/ll_api/ll_api.php?func=events&start_datetime=$time_start&end_datetime=$time_now&key_id=$key_id&priority=Infections&threat_class=command%26control&time_zone=Asia%2FTaipei&whitelisting=true&show_false_positives=false&format=json" -o "events.json"
# After successfully authenticated to Manager, we start download our event with filter infection(score above 70) and class command&control and save it to "events.xml"
#curl -k -s -b curl.cookie -c curl.cookie "https://$lastline_url/ll_api/ll_api.php?func=events&start_datetime=$time_start&end_datetime=$time_now&key_id=$key_id&priority=Infections&threat_class=command%26control&time_zone=Asia%2FTaipei&whitelisting=true&show_false_positives=false&format=xml" -o "events.xml"
exit 0