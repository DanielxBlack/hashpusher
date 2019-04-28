
# Import required modules
from __future__ import print_function
import time
import glob2
import hashlib
import requests
import json
from virus_total_apis import PublicApi as VirusTotalPublicApi
from bs4 import BeautifulSoup
# API info - https://pypi.org/project/virustotal-api/

# This is the API Key we are using.
API_KEY = "Your API Key Goes Here. Leave the quotes."

# Define vt variable with our VirusTotalAPIModule
virusTotal = VirusTotalPublicApi(API_KEY)


print("")
print("    ´´´´´´´¶¶¶¶´´´´´´´´´´´´´´´´´´ ")
print("    ´´´´´´¶¶´´´´¶¶¶¶¶´´¶¶¶¶´¶¶¶¶´´")
print("    ´´´´´´¶´´´´´´´´´´¶¶¶¶´¶¶´´´´¶´")
print("    ´´´´´´¶´´´´´´´´´´¶´¶¶¶¶¶¶´´´¶´")
print("    ´´´´´¶´´´´´´´´´´¶¶¶¶¶´´´¶¶¶¶¶´")
print("    ´´´´¶´´´´´´´´´´´´´´´´¶¶¶¶¶¶¶¶´")
print("    ´´´¶´´´´´´´´´´´´´´´´´´´¶¶¶¶¶´´")
print("    ´¶¶¶´´´´´¶´´´´´´´´´´´´´´´´´¶´´")
print("    ´´´¶´´´´¶¶´´´´´´´´´´´´´´´´´¶´´")
print("    ´´´¶¶´´´´´´´´´´´´´´´´¶¶´´´´¶´´")
print("    ´´´´´¶¶´´´´´´´´´´´´´´´´´´¶¶¶´´")
print("    ´´´´´´´¶¶¶´´´´´´´´´´´´´¶¶¶´´´´")
print("    ´´´¶¶¶¶¶´¶¶¶¶¶¶¶¶¶¶¶¶¶¶¶´´´´´´")
print("    ´´´¶´´´´¶¶¶¶¶´´´´¶¶¶¶´´´¶´´´´´")
print("    ´´´¶´´´´¶¶¶´¶¶¶¶¶¶¶¶´´´¶¶¶´´´´")
print("    ´´´¶¶¶¶¶¶¶¶¶¶¶¶¶´´¶¶¶¶¶´´´¶¶´´")
print("    ´´¶´´´´´´¶¶¶¶¶¶¶¶¶¶¶´´´´´´´¶´´")
print("    ´¶´´´´´´´´´¶¶¶¶¶¶¶¶´´´´´´´´¶´´")
print("    ´´¶´´´´´´´´¶¶¶¶¶¶¶¶´´´´´´´´¶´´")
print("    ´´¶¶´´´´´´´¶¶´´´´¶¶´´´´´´¶¶´´´")
print("    ´´´´¶¶¶¶¶¶¶´´´´´´´´¶¶¶¶¶¶´´´´´")
print("")
print(" _   _           _                ")
print("| | | |         | |               ")
print("| |_| | __ _ ___| |__             ")
print("|  _  |/ _` / __| '_ \            ")
print("| | | | (_| \__ \ | | |           ")
print("\_| |_/\__,_|___/_| |_|           ")
print("______          _                 ")
print("| ___ \        | |                ")
print("| |_/ /   _ ___| |__   ___ _ __   ")
print("|  __/ | | / __| '_ \ / _ \ '__|  ")
print("| |  | |_| \__ \ | | |  __/ |     ")
print("\_|   \__,_|___/_| |_|\___|_|     ")


# print space
print("")

# Ask user for input -- directory path
files = input("Test directory: ")
files = glob2.glob(files + "/*")
for file in files:
    with open(file, 'rb') as inputfile:
        data = inputfile.read()

        # print a space and then print out names of files and hash values
        # as they are seen and calculated by the local machine.
        print("")
        print(f"[+] Your File:        {str(file)}" )
        print(f"[+] Calculated Hash:  {str(hashlib.sha256(data).hexdigest())}")

        # Sent our hashes to VirusTotal
        sha256Hash = hashlib.sha256(data).hexdigest()
        virusTotal = VirusTotalPublicApi(API_KEY)

        # Check response from VirusTotal for our hash
        VTresponse = virusTotal.get_file_report(sha256Hash)
        returnValue = (json.dumps(VTresponse, sort_keys=True, indent=4))
        daJson = json.loads(returnValue)

        # The variable getDaJson will show
        try:
            getDaJson = (daJson['results']['permalink'])
            print(f"[+] VT Link:          {getDaJson}")
            reqsGet = requests.get(getDaJson).text
            # let's jump to beautifulSoup
            bSoupGet = BeautifulSoup(reqsGet,'html.parser')
            htmlRezultz = bSoupGet.find_all("tr", limit=2)[1].text
            htmlRezultz = htmlRezultz.replace("File name:","")
            htmlRezultz = htmlRezultz.strip()
            print(f"[+] VT Filename:      {htmlRezultz}")

            # Detections Test
            htmlRezultzToo = bSoupGet.find_all("tr", limit=4)[2].text
            htmlRezultzToo = htmlRezultzToo.replace("Detection ratio:","")
            htmlRezultzToo = htmlRezultzToo.strip()
            print(f"[+] Detections:       {htmlRezultzToo}")
            print("")

            # sleep for 16 seconds to rate-limit (< 4 requests per minute)
            time.sleep(16)

            # Exception if no results found on VT
        except KeyError as permalink:
            print("[+] No Result:        No Results Found on VirusTotal.")
            print("")

            # sleep for 16 seconds to rate-limit (< 4 requests per minute)
            time.sleep(16)

            
