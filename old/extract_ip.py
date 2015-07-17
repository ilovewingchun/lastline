#!/usr/bin/python
# -*- coding: UTF-8 -*-

'''
    Author: Tyler Chen ( tyler@lastline.com / alphaone.tw@gmail.com )
    Date: 2014 March 22
    Version: 1.2
    
    This script uses command line arguments to extract destination ip from Lastline exported event(default to events.json), make a list and store it to a txt file(default to block_ip.txt).
    The event file format must be in JSON format and it must be exported from Lastline Enterprise. Events exported from other product or not in JSON format is current not supported.
    There must be at least one input file for this script to run, output file will be created automatically.
    
    Use -i to set input file, use -o to set output file.
    For example: extract.py -i events.json -o list.txt
    
    '''

import json
import csv
import argparse
from pprint import pprint
import sys

# Is there argparse to use?
try:
    import argparse
except ImportError:
    print "Please install the argparse python module\non Debian systems you can use:\napt-get install python-argparse"
    sys.exit()

parser = argparse.ArgumentParser(
                                 description = "This is a tool to extract IP addresses from an Lastline Enterprise exported event file in JSON format.",     # text displayed on top of --help
                                 epilog = 'Use it at your own risk!') # last text displayed
parser.add_argument('-i','--input_file',action="store",default='events.json',dest='in_file',help='Lastline event file')
parser.add_argument('-o','--output_file',action="store",default='block_ip.txt',dest='out_file',help='Extracted ip list')
parser.add_argument('-wl','--whitelist_file',action="store",default='whitelist.txt',dest='whitelist_file',help='White list IP/FQDN')
arguments = parser.parse_args()

in_file = arguments.in_file  # look at dest  in the parser.add_argument lines
out_file = arguments.out_file
whitelist_file = arguments.whitelist_file

wl = open('whitelist.txt', 'r').read().splitlines() # Open white list file and remove newline(\n) within it.
json_data = open(in_file, 'r') # Open our json file.
data = json.load(json_data) # Load json file and change it to dictionary, store in a variable called data.
a = data["data"] # Retrieve value for key called "data" inside variable data, store in a, this is a list.
fo = open(out_file, 'w') # Open a file to store our parsed result.
c = []  # Empty list

for i in range(len(a)): # Iterate over first level list
    b = a[i]["dst_host"] # Iterate retrieve IP value for key "dst_host" inside list a
    c.append(b) # Write each IP into our emtpy list c
    c = [x for x in c if x not in wl] # Remove those entries that are inside whitelist.
    d = list(set(c)) # Retrieve each elements inside list c, using set function to remove duplicate entries and store in d.


for item in range(len(d)): # Iterate over our list d.
    e = d[item] # Store each elements inside a new variable e
    w = csv.writer(fo, lineterminator="\n") # Using csv function to write each value to a newly definied variable w, which actually writes to previously opened file fo.
    w.writerow([e]) # Write each IP from e to destination file.


fo.close()
