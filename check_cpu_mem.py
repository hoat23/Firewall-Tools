#!/usr/bin/env python
#coding: utf-8
#########################################################################################
# Developer: Deiner Zapata Silva.
# Date: 17/01/2019
# Description: Daemon to execute every time to check status of cpu and memory of a firewall
# sys.setdefaultencoding('utf-8') #reload(sys)
#########################################################################################
from time import sleep
from fortiOS_API import *
import multiprocessing
#########################################################################################

#########################################################################################
def execute_get(ip,client,ip_logstash,port_logstash,username = "user",password = "password"):
    num=0
    if (len(ip.split(":"))==2):
        aux = ip.split(":")
        ip = aux[0]
        port = aux[1]
    else:
        port = 9443
    
    command = '/api/v2/monitor/system/vdom-resource/select/'
    vdom = 'root'
    urlprefix = 'https://' + str(ip) + ":" + str(port)
    fgt = FGT(urlprefix,vdom)  #FGT(urlprefix,vdom) #vdom=None
    
    enlapsed_time = 0
    if(isAliveIP(ip)):
        try:
            start_time = time.time()
            fgt.login(username, password)
            date = time.strftime("%c")
            res = fgt.get(command)
            fgt.logout()
            enlapsed_time = time.time() - start_time
            time_enlapsed_time = 30 - enlapsed_time
            sleep(time_enlapsed_time)
            status = "OK"
        except:
            status = "ERR"
            pass
    else:
        status = "DOWN"
    
    print("--> [%04s|%04d|%02.4f|%016s] | %s " %(status, num, enlapsed_time, client,urlprefix))#pprint(res)
    
    if(status=="OK"):
        data_aditional = {
            'url_api' : command , 
            "host" : ip, 
            "enlapsed_time" : enlapsed_time,
            "date" : date
        }
        res.update(data_aditional)
        send_json( res , IP=ip_logstash, PORT=port_logstash)
    
    return enlapsed_time,status,urlprefix
#########################################################################################
def exec_daemon(list_client, dict_client_ip,ip_logstash,port_logstash):
    jobs = []
    cont = 0
    #multiprocessing.log_to_stderr(logging.DEBUG)
    for client in list_client:
        #if client=="alianza":
            list_ip = dict_client_ip[client]
            for ip in list_ip:
                # Init by one IP:PORT
                p = multiprocessing.Process(name=client+"_"+str(cont),target=execute_get,args=(ip,client,ip_logstash,port_logstash)) #execute_get(ip)
                #p.daemon=True
                p.start()
                jobs.append(p)
                cont = cont + 1
                #execute_get(ip,client)
    print("--> [  END] daemons are running.")
    return
#########################################################################################
if __name__ == "__main__":
    print("--> [START] check_cpu_mem.py")
    ip_logstash = "8.8.8.8" 
    port_logstash = 2323
    list_client=["firewall_1","firewall_2","firewall_3"]
    dict_client_ip = {
        "firewall_1" : ["8.8.8.8"],
        "firewall_2" : ["9.9.9.9","10.10.10.10:443"],
        "firewall_3" : []
    }
    for i in range(0,10):
        exec_daemon(list_client, dict_client_ip,ip_logstash,port_logstash) 
    pass
#########################################################################################
