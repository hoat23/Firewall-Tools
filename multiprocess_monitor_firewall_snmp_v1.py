#!/usr/bin/env python
#coding: utf-8
#########################################################################################
# Developer: Deiner Zapata Silva.
# Date: 06/02/2019
# Description: Daemon to execute every time to check status of firewalls using snmp protocol
# By watchdog matter PID (ip,port,client) for relaunched if a proccess dead, 
# but execute_process matter status, old_time, num_intent.
# sys.setdefaultencoding('utf-8') #reload(sys)
#########################################################################################
from time import sleep
from fortiOS_API import *
import multiprocessing as mp
import os, signal, sys
#from monitor_firewall_SSH import *
from monitor_firewall_snmp_v1 import *
#########################################################################################
def execute_process(ip, port, ip_logstash, port_logstash, return_dict, community, num_int=4):
    command = "check_process,sysinfo_shm,sysinfo_memory,sysinfo_conserve"
    old_time = return_dict[ip]['old_time']
    intent = 1
    while (intent <= num_int):
        res={'status': "error"} #Evitar error por timeout
        res = get_data_firewall_snmp(ip, community, port=161, sample_time = 32.0, old_time=old_time, data_to_monitoring="bandwidth,cpu_mem")
        if res['status']!="error" :
            break   
        sleep(1)
        intent = intent + 1
    
    old_time = res['old_time'] 
    if(res['status']=="error" and intent>=num_int):
        sleep(5)
    
    data_json = {
        ip : {
            'status': res['status'], 
            'old_time': old_time, 
            'num_int': intent
            }
        }

    return_dict.update( data_json )
    return
#########################################################################################
def launch_watchdog(list_process, dict_pid_ip, ip_logstash, port_logstash, return_dict, community):
    while(True):
        cont = 0
        #os.system('cls')
        #print("Proccess running . . . ")
        sleep(2)
        print("Nª           IP                 PID       RUN\tINT\tSTATUS\t\tCLIENT")
        for p in list_process:
            ip = dict_pid_ip[p.pid]['ip']
            port = dict_pid_ip[p.pid]['port']
            client = dict_pid_ip[p.pid]['client']
            if(not p.is_alive()):
                del dict_pid_ip[p.pid]
                p = mp.Process(name=client+"_"+ip+":"+str(port),target=execute_process,args=(ip, port, ip_logstash, port_logstash, return_dict,community))
                p.daemon=True
                p.start()
                dict_pid_ip.update({ p.pid: {"ip":ip, "port":port, "client":client} })
                list_process[cont]=p
            print( '%02d  %015s:%05s    %06s    %06s   %02s  %010s    \t%010s ' % 
                   (cont , ip , port , p.pid , p.is_alive(), return_dict[ip]['num_int'], return_dict[ip]['status'], client) )
            cont = cont +1
    return
#########################################################################################
def init_multiprocessing(list_client, dict_client_ip, ip_logstash, port_logstash, community):
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
            data_json = {
                ip : {
                    'status': 'launched',
                    'num_int': -1,
                    'old_time': 0
                    }
                }
            return_dict.update( data_json )
            # Init by process by IP:PORT
            p = mp.Process(name=client+"_"+ip+":"+str(port),target=execute_process,args=(ip, port, ip_logstash, port_logstash, return_dict,community))
            p.daemon = True
            p.start()
            dict_pid_ip.update({ p.pid: {"ip":ip, "port":port, "client":client} })
            list_process_running.append(p)
    print("--> [  END] process are launched.")
    launch_watchdog(list_process_running,dict_pid_ip,ip_logstash,port_logstash,return_dict,community)
    return
#########################################################################################
if __name__ == "__main__":
    print("--> [START] multiprocess_snmp.py")
    ip_logstash = "8.8.8.8" 
    port_logstash = 22
    community = "comunidad"
    list_client_to_execute=["cliente01"]
    dict_client_ip = {
        "cliente01" : 
            [{
            "ip" : "1.1.1.1",
            "port": {
                "ssh": 22,
                "http": 93,
                "snmp": 161
                }
            }],
        "cliente02" : 
            [{
            "ip" : "2.2.2.2",
            "port": {
                "ssh": 133,
                "http": 944,
                "snmp": 161
                }
            },
            {
            "ip" : "4.4.4.4",
            "port": {
                "ssh": 67,
                "http": 988,
                "snmp": 161
                }
            }],
        "cliente03" : []
    }

    init_multiprocessing(list_client_to_execute, dict_client_ip,ip_logstash,port_logstash,community)
#########################################################################################