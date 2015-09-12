#!/usr/bin/python
'''
	Author: Tyler Chen (tyler@lastline.com / alphaone.tw@gmail.com)
	Version: 1.0
	Description: This program is designed to extract password protected Zip file from Zeroday Coverage Report.
	Usage: python lastline_extract_samples.py <zip file>
	Example: python lastline_extract_samples.py *.zip
'''
import sys
from zipfile import ZipFile
file_fullname_list = sys.argv[1:]
file_basename_list = []
password_list = []
for i in file_fullname_list:
	file_basename_list.append(i.split(".")[-2])
for i in file_basename_list:
    password_list.append(i[-4:])
password_list = ["infected" + s for s in password_list ]
for i in range(len(password_list)):
	print "[+] Extracting malware sample"
	ZipFile(file_fullname_list[i]).extractall(pwd=password_list[i])
	print "[+] Malware sample %s extracted, moving on to next one...\n" % file_basename_list[i]
print "[+] All files extracted, good bye!\n"