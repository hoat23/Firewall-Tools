#coding: UTF-8 
#########################################################################################
# Developer: Deiner Zapata Silva.
# Date: 19/11/2018
# Description: Downloading BD Information Security and uploading to elastic.
# sys.setdefaultencoding('utf-8') #reload(sys)
#########################################################################################
"""
Malware Domain List: http://www.malwaredomainlist.com/mdlcsv.php
Zeus Domain: https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist
Zeus Malware IP: https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist
Malware IP: http://www.ipspamlist.com/public_feeds.csv
Hail-TAAXI-Malware URL: http://hailataxii.com/taxii-discovery-service
"""
#https://media.readthedocs.org/pdf/libtaxii/latest/libtaxii.pdf
#Code base: https://stackoverflow.com/questions/46654721/stix-taxii-python3-cabby-api-getting-data-into-a-format-i-can-use

import pprint
from cabby import create_client
import sys, requests, json
from datetime import datetime, timedelta
from time import time
from utils import *
###############################################################################################################
def req_get(URL_API,data="",timeout=None):
    rpt = requests.get( url=URL_API , timeout=timeout)
    
    #if not( (rpt.status_code)==200 or (rpt.status_code)==201 ):
    print("[GET]: "+ str(rpt.status_code) +" | "+ str(rpt.reason))
    #print("print text")
    #print(rpt.text)
    #print("print json")
    #print(str(rpt.json))
    return rpt.text
###############################################################################################################
def convert_data(data_txt):
    num=0
    list_lines = data_txt.split('\n')
    for line in list_lines:
        if len(line):
            if (line[1]=='#' or line[1]==' '):
                num = 0
            else:
                num=num+1
                print(str(num) + ". " + line)
###############################################################################################################
def download_HahilTAAXI():
    HailATaxiiFeedList=[
        'guest.Abuse_ch',
        'guest.CyberCrime_Tracker',
        'guest.EmergingThreats_rules',
        'guest.Lehigh_edu',
        'guest.MalwareDomainList_Hostlist',
        'guest.blutmagie_de_torExits',
        'guest.dataForLast_7daysOnly',
        'guest.dshield_BlockList',
        'guest.phishtank_com'
    ]

    client = create_client('hailataxii.com', use_https=False, discovery_path='/taxii-discovery-service')
    print (": Discover_Collections:")
    services = client.discover_services()
    for service in services:
        print('Service type= {s.type} , address= {s.address}' .format(s=service))

    print (": Get_Collections:")
    collections = client.get_collections(uri='http://hailataxii.com/taxii-data')

    for collection_name in HailATaxiiFeedList:
        print ("Polling :", collection_name, ".. could take a while, please be patient..")
        file = open( (collection_name + ".xml"), "w")
        content_blocks = client.poll(collection_name=collection_name)

        count =1
        for block in content_blocks:
            taxii_message=block.content.decode('utf-8')
            file.write(taxii_message)
            count+=1
            if count > 20: # just getting the 20 top objects because the lists are huge
                break
        file.close()
    return
###############################################################################################################
def download_Zeus_IP():
    print("############################## Zeus   IP   ##############################")
    URL = "https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist"
    data_txt = req_get(URL)
    data_parsed = convert_data(data_txt)
    return
###############################################################################################################
def download_Zeus_Domain():
    print("############################## Zeus Domain ##############################")
    URL = "https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist"
    data_txt = req_get(URL)
    data_parsed = convert_data(data_txt)
    return
###############################################################################################################
def download_MalwareDomainList():
    print("############################## Malware Domain ##############################")
    URL = "http://www.malwaredomainlist.com/mdlcsv.php"
    data_txt = req_get(URL)
    data_parsed = convert_data(data_txt)
    return
###############################################################################################################
def download_IPSpamList():
    print("############################## IP spam list ##############################")
    URL = "http://www.ipspamlist.com/public_feeds.csv"
    data_txt = req_get(URL)
    data_parsed = convert_data(data_txt)
    return
###############################################################################################################
if __name__ == "__main__":
    download_Zeus_Domain()
    #download_Zeus_IP()
    #download_MalwareDomainList()
    #download_IPSpamList()
