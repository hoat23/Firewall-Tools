#!/usr/bin/env python
#coding: utf-8
#########################################################################################
# Developer: Deiner Zapata Silva.
# Date: 01/02/2019
# Description: Daemon to execute every time to check status of firewalls
# sys.setdefaultencoding('utf-8') #reload(sys)
#########################################################################################
from time import sleep
from fortiOS_API import *
import multiprocessing as mp
import os, signal, sys
from monitor_firewall_SSH import *
#########################################################################################
def execute_get(ip, port, ip_logstash, port_logstash, return_dict, username = "user", password = "password", num_int=4):
    command = "check_process,sysinfo_shm,sysinfo_memory,sysinfo_conserve"
    for i in range(1,num_int+1):
        res = get_data_firewall_ssh(command, ip, port, username, password, ip_logstash, port_logstash)
        if res['status']!="error" :
            break
        sleep(1)
    return_dict.update( {ip : {'status': res['status']}} )
    res.update({'num_intent':i})
    sleep(28)
    return
#########################################################################################
def launch_watchdog(list_process,dict_pid_ip,ip_logstash,port_logstash,return_dict):
    while(True):
        cont = 0
        #os.system('cls')
        print("Proccess running . . . ")
        print("Nª \t  IP             PID  \t  RUN  \t  STATUS   CLIENT")
        for p in list_process:
            ip = dict_pid_ip[p.pid]['ip']
            port = dict_pid_ip[p.pid]['port']
            client = dict_pid_ip[p.pid]['client']
            if(not p.is_alive()):
                del dict_pid_ip[p.pid]
                p = mp.Process(name=client+"_"+ip+":"+str(port),target=execute_get,args=(ip, port, ip_logstash, port_logstash, return_dict))
                p.daemon=True
                p.start()
                dict_pid_ip.update({ p.pid: {"ip":ip, "port":port, "client":client} })
                list_process[cont]=p
            print( '%02d     %015s:%05s    %06s    %06s   %010s   %010s' % (cont , ip , port , p.pid , p.is_alive(), return_dict[ip]['status'], client) )
            cont = cont +1
        sleep(2)
#########################################################################################
def init_multiprocessing(list_client, dict_client_ip,ip_logstash,port_logstash):
    list_process_running = []
    manager = mp.Manager()
    return_dict = manager.dict()
    dict_pid_ip = {}
    #mp.log_to_stderr(logging.DEBUG)
    for client in list_client:
        list_ip = dict_client_ip[client]
        for ip_json in list_ip:
            print(str(ip_json))
            ip = ip_json['ip']
            port = ip_json['port']['ssh']
            # Init by process by IP:PORT
            p = mp.Process(name=client+"_"+ip+":"+str(port),target=execute_get,args=(ip, port, ip_logstash, port_logstash, return_dict))
            return_dict.update( {ip : {'status': 'lauched'}} )
            p.daemon = True
            p.start()
            dict_pid_ip.update({ p.pid: {"ip":ip, "port":port, "client":client} })
            list_process_running.append(p)
    print("--> [  END] process are launched.")
    launch_watchdog(list_process_running,dict_pid_ip,ip_logstash,port_logstash,return_dict)
    return
#########################################################################################
if __name__ == "__main__":
    print("--> [START] check_cpu_mem.py")
    ip_logstash = "8.8.8.8" 
    port_logstash = 2323
    list_client_to_execute=["cliente01","cliente02"]
    dict_client_ip = {
        "cliente" : 
            [{
            "ip" : "0.0.0.0",
            "port": {
                "ssh": 22222,
                "http": 9443
                }
            }],
        "cliente02" : 
            [{
            "ip" : "1.1.1.1",
            "port": {
                "ssh": 1337,
                "http": 9443
                }
            },
            {
            "ip" : "181.176.188.202",
            "port": {
                "ssh": 1337,
                "http": 9443
                }
            }]
    }

    init_multiprocessing(list_client_to_execute, dict_client_ip,ip_logstash,port_logstash)
#########################################################################################