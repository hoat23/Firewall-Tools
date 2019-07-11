#!/usr/bin/env python
#coding: utf-8
#########################################################################################
# Developer: Deiner Zapata Silva.
# Date: 17/01/2019
# Last update: 09/07/2019
# Description: 
# sys.setdefaultencoding('utf-8') #reload(sys)
#########################################################################################
import os
import signal
import sys
import multiprocessing as mp
from time import sleep
from datetime import datetime
from fortiOS_API import *
from dictionary import *
from elastic import *
#########################################################################################
global dict_ip_fgt
dict_ip_fgt = {}
#########################################################################################
def signal_handler(signal, frame):
    global dict_ip_fgt
    print("signal_handler")
    list_ip = list(dict_ip_fgt)
    for ip in list_ip:
        obj_fgt = dict_ip_fgt[ip]
        res = obj_fgt.logout()
        print("logout -> ")
        print(str(res))
    
    sys.exit(0)
#########################################################################################
def lauch_get_to_firewall(ip, port, username, password, command, local_save=True, path="/etc/backup"):
    global dict_ip_fgt
    res = {}
    urlprefix = 'https://' + str(ip) + ":" + str(port)
    try:
        vdom = 'root'
        fgt = FGT(urlprefix,vdom)  #FGT(urlprefix,vdom) #vdom=None
        start_time = time.time()
        fgt.login(username, password)
        date = time.strftime("%c")
        if(command.find('/api/v2/monitor/system/config/backup')>=0):
            backup_file = fgt.get(command,get_text=True)
            length_backup = len(backup_file)
            if local_save:
                os.system("cd")
                os.system("cd "+ path)
                fecha = datetime.now().strftime("%Y%m%d")
                nameFile="backupForti_{0}_{1}.conf".format(fecha,ip)
                res = {
                    "file": {
                        "length": length_backup,
                        "path": "{0}".format( path ) ,
                        "name":  nameFile
                        }
                    }
                fileTXT_save( path +"/"+ backup_file, nameFile = nameFile)
            else:
                res = {
                    "file": {
                        "length": length_backup,
                        "bytes": backup_file
                    }
                }
            if length_backup>0:
                res.update({'status': "success"})
            else:
                res.update({'status': "error"})
        else:
            res = fgt.get(command)
        fgt.logout()
        enlapsed_time = time.time() - start_time
        dict_ip_fgt.update({ip:fgt})
        if not 'status' in res:
            res.update({'status': "unknow"})
    except:
        enlapsed_time = 0 
        #date = time.strftime("%c")
        res.update({'status': "error"})
        pass
    finally:
        data_aditional = {
            'url_api' : urlprefix , 
            "host" : ip, 
            "enlapsed_time" : enlapsed_time,
            "@timestamp" : "{0}".format(datetime.utcnow().isoformat())
        }
        res.update(data_aditional)
        #print("--> [%04s|%04d|%02.4f|%016s] | %s " %(status, num, enlapsed_time, client,urlprefix))#pprint(res)
        return res
#########################################################################################
def send_elk(data2send, server_config):
    #print_json(data2send)
    if server_config['credentials']['type']=='default':
        elk = elasticsearch()
    elif server_config['credentials']['type']=='explicit':
        ip_server = server_config['credentials']['ip']
        user_server = server_config['credentials']['user']
        pass_server = server_config['credentials']['pass']
        elk = elasticsearch( url=ip_server, user=user_server, pas=pass_server)
    else:
        print("{0} [WARN ] : send_elk() Error creating elasticsearch object.".format(datetime.datetime.utcnow().isoformat()))
        return
    headers = data2send['headers']['index']
    URL_API =  "{0}/{1}/{2}".format(elk.get_url_elk(), headers['_index'], headers['_type'])
    rpt = elk.req_post(URL_API, data2send['data'])
    if 'error' in rpt:
        print_json(rpt)
    return
#########################################################################################
def execute_get(ip, port, server_listen, return_dict, command, username, password,num_int=2):
    num=0
    #if(isAliveIP(ip,timeout=1500)):
    #    enlapsed_time,status,date = lauch_get_to_firewall(ip,port,username,password,command)
    intent = 1
    while (intent <= num_int):
        res = lauch_get_to_firewall(ip,port,username,password,command)
        if res['status']!="error" :
            break
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
    
    """
    if (float(enlapsed_time)>0 and 30 - float(enlapsed_time)>0):
        sleep(30.0-float(enlapsed_time))
    else:
        sleep(28)
    """
    return_dict.update( data_json )

    try:
        type_server_listen = server_listen['type']
        send = server_listen['send']
        if send:
            if type_server_listen == "logstash" or type_server_listen == "default":
                ip_server = server_listen['ip']
                port_server = server_listen['port']
                send_json( res , IP=ip_server, PORT=port_server)
            elif type_server_listen == "elasticsearch":
                data_json  = {
                    "data": res,
                    "headers": {
                        "index":{
                            "_index":"backup-group01-write",
                            "_type":"_doc"
                        }
                    }
                }
                send_elk(data_json, server_listen)
    except:
        print("-->{0}|ERROR|execute_get({1}:{2}) | Don't send data to server.".format( datetime.utcnow().isoformat(), ip, port) )
    
    #sleep(28)
    return
#########################################################################################
def launch_watchdog(list_process,dict_pid_ip,server_listen, return_dict, command, username, password):
    while(True):
        cont = 0
        #os.system('cls')
        #print("Proccess running . . . ")
        sleep(2)
        print("Nª           IP                 PID       RUN\tINT\tSTATUS\t ENL_TIME\t\tCLIENT")
        for p in list_process:
            ip = dict_pid_ip[p.pid]
            port = dict_pid_ip[p.pid]['port']
            client = dict_pid_ip[p.pid]['client']
            if(not p.is_alive()):
                #print("relaunch"+ip)
                del dict_pid_ip[p.pid]
                p = mp.Process(name=ip,target=execute_get,args=(ip,port,server_listen, return_dict, command, username, password))
                p.daemon=True
                p.start()
                #p.join()
                dict_pid_ip.update({p.pid:ip})
                list_process[cont]=p
            print( '%02d  %015s:%05s    %06s    %06s   %02s  %010s %010s\t    %010s ' % 
                   (cont , ip , port , p.pid , p.is_alive(), return_dict[ip]['num_int'], return_dict[ip]['status'], return_dict[ip]['enlapsed_time'], client) )
            cont = cont +1
        sleep(1)
#########################################################################################
def init_multiprocessing(list_client, dict_client_ip, server_listen, command, username, password, enabled_watchdog=True):
    list_process_running = []
    manager = mp.Manager()
    return_dict = manager.dict()
    dict_pid_ip = {}
    #mp.log_to_stderr(logging.DEBUG)
    for client in list_client:
        list_ip_json = dict_client_ip[client]
        for ip_json in list_ip_json:
            ip = ip_json['ip']
            port = ip_json['port']['http']
            data_json = {
                ip : {
                    'status': 'lauched',
                    'num_int': -1,
                    'old_time': 0,
                    'enlapsed_time': -1
                    }
                }
            return_dict.update( data_json )
            # Init by one IP:PORT
            p = mp.Process(name=client+"_"+ip,target=execute_get,args=(ip, port, server_listen, return_dict, command, username, password)) #execute_get(ip)
            p.daemon=True
            p.start()
            #p.join()
            dict_pid_ip.update({p.pid:ip})
            list_process_running.append(p)
    print("--> [  END] process are launched.")
    if (enabled_watchdog):
        launch_watchdog(list_process_running, dict_pid_ip, server_listen, return_dict, command, username, password)
    else:
        for p in list_process_running:
            p.join()
        print("--> [END] all process finished.")
    return
#########################################################################################
if __name__ == "__main__":
    print("--> [START] multiprocess_monitor_firewall_http.py")
    signal.signal(signal.SIGINT, signal_handler)
    list_client_to_execute=["yanbal"]
    #list_client_to_execute=["alianza","aje","alexim","babyclubchic","bdo","brexia","crp","ohsjdd","comexa","cosapi","cpal","disal","dispercol","divemotors","egemsa","enapu","famesa","fibertel","filasur","gomelst","happyland","imm","ind_marique","ifreserve","la_llave","lab_hofarm","labocer","mastercol","movilmax","proinversion","san_silvestre","santo_domingo","socios_en_salud","supra","thomas_greg","trofeos_castro","univ_per_union","zinsa","upch","tasa","prompe","engie","cdtel"]
    server_listen = server_elk #logstash #elasticsearch  
    enabled_watchdog=False
    #command = '/api/v2/monitor/system/vdom-resource/select/'
    command = '/api/v2/monitor/system/config/backup?scope=global'
    dict_client_ip = dict_client_ip_http
    init_multiprocessing(list_client_to_execute, dict_client_ip, server_listen, command, username, password, enabled_watchdog=enabled_watchdog)
#########################################################################################