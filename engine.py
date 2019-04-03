# coding: utf-8
# Developer: Deiner Zapata Silva.
# Date: 02/14/2019
# Description: Procesar las alertas generadas
#######################################################################################
from utils import *
from utils_elk import *
from elastic import *
#######################################################################################
def sendAlert2ELK(list_data_to_up_bulk,elk=None):
    index = "alertas"
    header_json={"index":{"_index":index,"_type":"_doc"}}
    if elk==None: elk = elasticsearch()
    elk.post_bulk(list_data_to_up_bulk,header_json=header_json)
    return
#######################################################################################
def getStatusAlert(ip):
    status_alert_json = {}
    return status_alert_json
#######################################################################################
def build_alert_by_IP(ip_list, description_alert_json):
    elk = elasticsearch()
    #dict_client_by_ip = download_configuration_from_elk(elk)
    dict_IP = loadYMLtoJSON('dict_IP.yml')
    list_data_json = []
    for ip in ip_list:
        if ip in dict_IP:
            data_json = { "ip" : ip }
            columns = ["client", "sede", "type_device", "name_device", "function_ip"]
            aditional_data = dict_IP[ip].split(";")
            for n in range(0,len(columns)):
                data_json.update( {columns[n] : aditional_data[n]} )
            data_json.update( description_alert_json)
            data_json.update( get_status_alert_by_ip(ip) )
            list_data_json.append(data_json)
        else:
            print("[ERROR] build_alert_by_IP | IP:{0} don't save in ELK. ".format(ip))
    sendAlert2ELK(list_data_json,elk=elk)
    return 
#######################################################################################
def get_description(data_json,list_key_to_extract = ["watch_id","execution_time"]):
    alert_description = {}
    for key in list_key_to_extract:
        if key in data_json:
            alert_description[key] = data_json[key]
        else:
            print("[ERROR] get_description | Dont' found <key:{0}>".format(key))
    return alert_description
#######################################################################################
def processAlert(data_json):
    rpt = "OK"
    #print_json(data_json)
    if 'path_element' in data_json:
        path_element = data_json['path_element']
        rpt_list = getelementfromjson(data_json,path_element)
        build_alert_by_IP(rpt_list, get_description(data_json))
    else:
        print("[ERROR] processAlert | Key not found in data_json <path_element>")
        rpt = "ERROR"
    
    return rpt
#######################################################################################
if __name__ == "__main__":
    print("[INICIO] Testing engine")


#"192.168.21.3" tasa