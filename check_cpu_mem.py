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
import multiprocessing as mp
import os
#########################################################################################
def lauch_get_to_firewall(ip,port,username,password,command):
    res = {}
    try:
        vdom = 'root'
        urlprefix = 'https://' + str(ip) + ":" + str(port)
        fgt = FGT(urlprefix,vdom)  #FGT(urlprefix,vdom) #vdom=None
        start_time = time.time()
        fgt.login(username, password)
        date = time.strftime("%c")
        res = fgt.get(command)
        fgt.logout()
        enlapsed_time = time.time() - start_time 
    except:
        enlapsed_time = 0 
        date = time.strftime("%c")
        res.update({'status': "error"})
        pass
    finally:
        data_aditional = {
            'url_api' : command , 
            "host" : ip, 
            "enlapsed_time" : enlapsed_time,
            "date" : date
        }
        res.update(data_aditional)
    #print("--> [%04s|%04d|%02.4f|%016s] | %s " %(status, num, enlapsed_time, client,urlprefix))#pprint(res)
    return res
#########################################################################################
def execute_get(ip,ip_logstash,port_logstash,username = "backup.supra",password = "5upporT@",command = '/api/v2/monitor/system/vdom-resource/select/',num_int=4):
    num=0
    if (len(ip.split(":"))==2):
        aux = ip.split(":")
        ip = aux[0]
        port = aux[1]
    else:
        port = 9443
    #if(isAliveIP(ip,timeout=1500)):
    #    enlapsed_time,status,date = lauch_get_to_firewall(ip,port,username,password,command)
    for i in range(1,num_int+1):
        res = lauch_get_to_firewall(ip,port,username,password,command)
        if res['status']!="error" :
            break
    res.update({'num_intent':i})
    send_json( res , IP=ip_logstash, PORT=port_logstash)
    sleep(28)
    return
#########################################################################################
def launch_watchdog(list_process,dict_pid_ip,ip_logstash,port_logstash):
    while(True):
        cont = 0
        os.system('cls')
        print("Proccess running . . . ")
        print("Nª \t\t  IP \t\t  PID  \t\t  RUN")
        for p in list_process:
            ip = dict_pid_ip[p.pid]
            if(not p.is_alive()):
                #print("relaunch"+ip)
                del dict_pid_ip[p.pid]
                p = mp.Process(name=ip,target=execute_get,args=(ip,ip_logstash,port_logstash))
                p.start()
                dict_pid_ip.update({p.pid:ip})
                list_process[cont]=p
            print( '%02d \t %015s \t %06s \t %06s' % (cont , ip , p.pid , p.is_alive()) )
            cont = cont +1
        sleep(1)
#########################################################################################
def init_multiprocessing(list_client, dict_client_ip,ip_logstash,port_logstash):
    list_process = []
    dict_pid_ip = {}
    #mp.log_to_stderr(logging.DEBUG)
    for client in list_client:
        list_ip = dict_client_ip[client]
        for ip in list_ip:
            # Init by one IP:PORT
            p = mp.Process(name=client+"_"+ip,target=execute_get,args=(ip,ip_logstash,port_logstash)) #execute_get(ip)
            p.start()
            dict_pid_ip.update({p.pid:ip})
            list_process.append(p)
    print("--> [  END] process are launched.")
    launch_watchdog(list_process,dict_pid_ip,ip_logstash,port_logstash)
    return
#########################################################################################
if __name__ == "__main__":
    print("--> [START] check_cpu_mem.py")
    ip_logstash = "8.8.8.8" 
    port_logstash = 2323
    list_client_to_execute=["firewall_1","firewall_2","firewall_3"]
    dict_client_ip = {
        "firewall_1" : ["8.8.8.8"],
        "firewall_2" : ["9.9.9.9","10.10.10.10:443"],
        "firewall_3" : []
    }
    
    init_multiprocessing(list_client_to_execute, dict_client_ip,ip_logstash,port_logstash)
#########################################################################################
