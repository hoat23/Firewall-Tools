#coding: UTF-8 
#########################################################################################
# Developer: Deiner Zapata Silva.
# Date: 17/01/2019
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
###############################################################################################################
import pprint
#from cabby import create_client
import sys, requests, json
from datetime import datetime, timedelta
from time import time
from utils import *
###############################################################################################################
def req_get(URL_API,data="",timeout=None):
    rpt = requests.get( url=URL_API , timeout=timeout)
    print("[GET]: "+ str(rpt.status_code) +" | "+ str(rpt.reason)+ " | url: "+URL_API)
    return rpt.text
###############################################################################################################
def convert_data(data_txt,list_field=None,aditional_data={},split_char=','):
    num=0
    #data_txt = data_txt.replace("\"","")
    data_txt = data_txt.replace("\r","")
    list_lines = data_txt.split('\n')
    for line in list_lines:
        if len(line):
            if (line[0]=='#' or line[0]==' '):
                num = 0
            else:
                num=num+1
                if(num==1 and list_field==None):
                    list_field = line.split(split_char)
                else:
                    list_value = line.split(split_char)
                    line_json = list2json(list_field,list_value,remove_char="\"")
                    aditional_data.update({"source_id":num})
                    line_json.update(aditional_data)
                    send_json(line_json,IP="127.0.0.0",PORT=5959)
                    #print_json(line_json)
                    #time.sleep(0.200)
            #print("{0:03d}. {1}".format(num,line))
###############################################################################################################
if __name__ == "__main__":
    #Fuentes de IOC
    list_sources_IOC=[
    {
        "list_field" : ["ip"],
        "url" : "https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist",
        "aditional_data": {"source_ioc":"zeustracker_ip"},
        "split_char": ","
    },
    {
        "list_field" : ["domain"],
        "url" : "https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist",
        "aditional_data" : {"source_ioc":"zeustracker_domain"},
        "split_char": ","
    },
    {
        "list_field" : ["date_UTC","domain","ip","reverse_lookup","description","","ASN","no_defined2","country_code","no_defined3"],
        "url" : "http://www.malwaredomainlist.com/mdlcsv.php",
        "aditional_data" : {"source_ioc":"malwaredomainlist"},
        "split_char": "\","
    },
    {
        "list_field" : [],
        "url" : "http://www.ipspamlist.com/public_feeds.csv",
        "aditional_data" : {"source_ioc":"ipspamlist"},
        "split_char": ","
    }
    ]
    
    for source_IOC in list_sources_IOC:
        URL = source_IOC['url']
        aditional_data = source_IOC['aditional_data']
        list_field = source_IOC['list_field']
        split_char = source_IOC['split_char']
        data_txt = req_get(URL)
        if(len(list_field)>0):
            data_parsed = convert_data(data_txt,list_field=list_field,aditional_data=aditional_data,split_char=split_char)
        else:
            data_parsed = convert_data(data_txt,aditional_data=aditional_data,split_char=split_char)
