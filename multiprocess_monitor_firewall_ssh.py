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
from monitor_firewall_ssh import *
from dictionary import *
#########################################################################################
def execute_process(ip, port, logstash, list_vdom, return_dict, username, password, num_int=4):
    command = "check_process,sysinfo_shm,sysinfo_memory,sysinfo_conserve"
    intent = 1
    while (intent <= num_int):
        res = get_data_firewall_ssh(command, ip, port, username, password, logstash=logstash, vdom=list_vdom)
        if res['status']!="error" :
            break
        #sleep(1)
        intent = intent + 1
    
    if 'old_time' in res:
        old_time = res['old_time'] 
    else:
        old_time = -1

    if 'enlapsed_time' in res:    
        enlapsed_time = res['enlapsed_time']
    else:
        enlapsed_time = -1

    if(res['status']=="error" and intent>=num_int):
        sleep(5)

    data_json = {
        ip : {
            'status': res['status'],
            'old_time': old_time,
            'num_int': intent,
            'enlapsed_time': enlapsed_time
            }
        }
    if (float(enlapsed_time)>0 and 30 - float(enlapsed_time)>0):
        sleep(30.0-float(enlapsed_time))
    else:
        sleep(28)
    
    return_dict.update( data_json )
    return
#########################################################################################
def launch_watchdog(list_process, dict_pid_ip, logstash, return_dict, username, password):
    while(True):
        cont = 0
        #os.system('cls')
        #print("Proccess running . . . ")
        sleep(2)
        print("Nª           IP                 PID       RUN\tINT\tSTATUS\t ENL_TIME\t\tCLIENT")
        for p in list_process:
            list_vdom=None
            ip = dict_pid_ip[p.pid]['ip']
            port = dict_pid_ip[p.pid]['port']
            client = dict_pid_ip[p.pid]['client']
            if('vdom' in dict_pid_ip[p.pid]): list_vdom = dict_pid_ip[p.pid]['vdom']
            if(not p.is_alive()):
                del dict_pid_ip[p.pid]
                p = mp.Process(name=client+"_"+ip+":"+str(port),target=execute_process,args=(ip, port, logstash, list_vdom, return_dict, username, password))
                p.daemon=True
                p.start()
                if( list_vdom!=None):
                    dict_pid_ip.update({ p.pid: {"ip":ip, "port":port, "client":client, "vdom":list_vdom} })
                else:
                    dict_pid_ip.update({ p.pid: {"ip":ip, "port":port, "client":client} })
                list_process[cont]=p
            print( '%02d  %015s:%05s    %06s    %06s   %02s  %010s %010s\t    %010s ' % 
                   (cont , ip , port , p.pid , p.is_alive(), return_dict[ip]['num_int'], return_dict[ip]['status'], return_dict[ip]['enlapsed_time'], client) )
            cont = cont +1
    return
#########################################################################################
def init_multiprocessing(list_client, dict_client_ip, logstash, username, password, enabled_watchdog=True):
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
            list_vdom = None
            if 'vdom' in ip_json: list_vdom = ip_json['vdom']
            data_json = {
                ip : {
                    'status': 'lauched',
                    'num_int': -1,
                    'old_time': 0,
                    'enlapsed_time': -1
                    }
                }
            return_dict.update( data_json )
            # Init by process by IP:PORT
            p = mp.Process(name=client+"_"+ip+":"+str(port),target=execute_process,args=(ip, port, logstash, list_vdom, return_dict, username, password))
            p.daemon = True
            p.start()
            if list_vdom!=None:
                dict_pid_ip.update({ p.pid: {"ip":ip, "port":port, "client":client, "vdom": list_vdom} })
            else:
                dict_pid_ip.update({ p.pid: {"ip":ip, "port":port, "client":client} })
            list_process_running.append(p)
    print("--> [  END] process are launched.")
    if (enabled_watchdog):
        launch_watchdog(list_process_running, dict_pid_ip, logstash, return_dict, username, password)
    else:
        for p in list_process_running:
            p.join()
        print("--> [END] all process finished.")
    return
#########################################################################################
if __name__ == "__main__":
    print("--> [START] check_cpu_mem.py")
    #list_client_to_execute=["alianza","aje","alexim","babyclubchic","bdo","brexia","crp","ohsjdd","comexa","continental","cosapi","cpal","disal","dispercol","divemotors","egemsa","enapu","famesa","fibertel","filasur","gomelst","happyland","imm","ind_marique","ifreserve","ingenyo","itochu","la_llave","lab_hofarm","labocer","mastercol","movilmax","orval","proinversion","san_silvestre","santo_domingo","socios_en_salud","supra","thomas_greg","trofeos_castro","uladech","univ_per_union","valle_alto","zinsa","upch","tasa","prompe","engie","cdtel"]
    list_client_to_execute=["yanbal"]
    #list_client_to_execute=["alianza","aje","alexim","babyclubchic","bdo","brexia","crp","ohsjdd","comexa","continental","cosapi","cpal","disal","dispercol","divemotors","egemsa","enapu","famesa","fibertel","filasur","gomelst","happyland","imm","ind_marique","ifreserve","la_llave","lab_hofarm","labocer","mastercol","movilmax","proinversion","san_silvestre","santo_domingo","socios_en_salud","supra","thomas_greg","trofeos_castro","univ_per_union","zinsa","upch","tasa","prompe","engie","cdtel"]
    init_multiprocessing(list_client_to_execute, dict_client_ip, logstash, username, password)
#########################################################################################