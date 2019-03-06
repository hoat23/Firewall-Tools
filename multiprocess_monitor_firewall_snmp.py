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
from monitor_firewall_snmp import *
from dictionary import *
from elastic import *
import argparse
#########################################################################################
def execute_process(ip, port, logstash, return_dict, community, command, num_int=4):
    #command = "check_process,sysinfo_shm,sysinfo_memory,sysinfo_conserve,bandwidth"
    old_time = return_dict[ip]['old_time']
    cont = return_dict[ip]['cont'] + 1       

    intent = 1
    while (intent <= num_int):
        res={'status': "error"} #Evitar error por timeout
        res = get_data_firewall_snmp(ip, community, port=port, sample_time = 15.0, old_time=old_time, data_to_monitoring=command, logstash=logstash, cont = cont)#interfaces
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
            'enlapsed_time': enlapsed_time,
            'cont' : cont
            }
        }

    return_dict.update( data_json )
    return
#########################################################################################
def launch_watchdog(list_process, dict_pid_ip, logstash, return_dict, community, command):
    while(True):
        cont = 0
        #os.system('cls')
        #print("Proccess running . . . ")
        sleep(2)
        print("Nª           IP                 PID       RUN\tINT\tSTATUS\t ENL_TIME\t\tCLIENT")
        for p in list_process:
            ip = dict_pid_ip[p.pid]['ip']
            port = dict_pid_ip[p.pid]['port']
            client = dict_pid_ip[p.pid]['client']
            if(not p.is_alive()):
                del dict_pid_ip[p.pid]
                p = mp.Process(name=client+"_"+ip+":"+str(port),target=execute_process,args=(ip, port, logstash, return_dict, community, command))
                p.daemon=True
                p.start()
                dict_pid_ip.update({ p.pid: {"ip":ip, "port":port, "client":client} })
                list_process[cont]=p
            print( '%02d  %015s:%05s    %06s    %06s   %02s  %010s %010s\t    %010s ' % 
                   (cont , ip , port , p.pid , p.is_alive(), return_dict[ip]['num_int'], return_dict[ip]['status'], return_dict[ip]['enlapsed_time'], client) )
            cont = cont +1
    return
#########################################################################################
def init_multiprocessing(list_client, dict_client_ip, logstash, community, command="bandwidth", enabled_watchdog=True):
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
            port = ip_json['port']['snmp']
            data_json = {
                ip : {
                    'status': 'lauched',
                    'num_int': -1,
                    'old_time': 0,
                    'enlapsed_time': -1,
                    'cont': -1
                    }
                }
            return_dict.update( data_json )
            # Init by process by IP:PORT
            p = mp.Process(name=client+"_"+ip+":"+str(port),target=execute_process,args=(ip, port, logstash, return_dict, community, command))
            p.daemon = True
            p.start()
            dict_pid_ip.update({ p.pid: {"ip":ip, "port":port, "client":client} })
            list_process_running.append(p)
    print("--> [  END] process are launched.")
    if (enabled_watchdog):
        launch_watchdog(list_process_running, dict_pid_ip, logstash, return_dict, community, command)
    else:
        for p in list_process_running:
            p.join()
        print("--> [END] all process finished.")
    return
#########################################################################################
def get_parametersCMD_multiprocessing(list_client_to_execute):
    ip_logstash = port_logstash = None
    community = command = None
    watchdog = None

    parser = argparse.ArgumentParser()

    parser.add_argument("-m","--community",help="Comunidad snmp")
    parser.add_argument("-c","--command",help="Comando a ejecutar en la terminal [ ]")
    parser.add_argument("-ip_out","--ip_out",help="IP del logstash")
    parser.add_argument("-pp_out","--pp_out",help="Puerto del logstash")
    parser.add_argument("-dog","--dog",help="Enabled watchdog True or False")

    args = parser.parse_args()

    if args.community: community = str(args.community)
    if args.command: command = str(args.command)
    if args.ip_out: ip_logstash = str(args.ip_out)
    if args.pp_out: port_logstash = int(args.pp_out)
    if args.dog: watchdog = args.dog
    
    if( community==None or command==None):
        print("\nERROR: Faltan parametros.")
        print("community\t= ["+str(community)+"] \ncommand\t=["+str(command)+"]")
        sys.exit(0)
    
    if( ip_logstash==None or port_logstash==None):
        print("\nERROR: Faltan parametros.")
        print("ip_out\t= ["+str(ip_logstash)+"]\npp_out\t= ["+str(port_logstash)+"]")
        sys.exit(0)
    if (watchdog=="True"):
        dog = True
    else:
        dog = False
    
    logstash =  {
        "send" : True,
        "ip" : ip_logstash,
        "port" : port_logstash
    }
    #python multiprocess_monitor_firewall_snmp.py -m prueba -c "bandwidth" -ip_out 8.8.8.8 -pp_out 5959 -dog False
    if command=="build_dict":
        dict_ip_label = build_yml_label_interfaces(list_client_to_execute, dict_client_ip,community=community, dict_ip_label={})
    else:
        init_multiprocessing(list_client_to_execute, dict_client_ip, logstash, community, command=command, enabled_watchdog=dog)

#########################################################################################
if __name__ == "__main__":
    print("--> [START] multiprocess_snmp.py")
    community = "prueba"
    #list_client_to_execute_snmp = ["client_01","cliente_02"]
    #dict_client_ip = { "client_01": [{"ip":"1.1.1.1", "port": {"ssh":22222,"http":9344,"snmp":161}}] }
    #init_multiprocessing(list_client_to_execute_snmp, dict_client_ip, logstash, community)
    get_parametersCMD_multiprocessing(list_client_to_execute_snmp)
#########################################################################################
