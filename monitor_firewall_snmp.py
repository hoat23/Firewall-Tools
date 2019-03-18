#!/usr/bin/env python
#coding: utf-8
#########################################################################################
# Developer: Deiner Zapata Silva.
# Date: 25/01/2019
# Description: Daemon to execute every time to check status of cpu and memory of a firewall using snmp.
# MIB: http://mibs.snmplabs.com/asn1/
#########################################################################################
from pysnmp.hlapi import *
from pysnmp.entity.rfc3413.oneliner import cmdgen
import time, os, threading, queue, argparse, sys
from datetime import datetime
from utils import send_json, print_json, print_list, save_yml, loadYMLtoJSON, build_table_json, string2hex
from dictionary import *
#########################################################################################
cmdGen = cmdgen.CommandGenerator()
#########################################################################################
def snmp_walk(host, community, oid, port=161, column=False, num_int=4, time_sleep=0.4):
    #from testlib.custom_exceptions import CustomException
    for i in range(1,num_int+1):
        try:
            error_indication, error_status, error_index, var_binds = cmdGen.nextCmd(
                cmdgen.CommunityData(community),
                cmdgen.UdpTransportTarget((host, port)), 
                oid
            )
            break
        except:
            time.sleep(time_sleep)
            error_indication = "snmp_walk Can't execute. Number of intent {0}x0.5 seg".format(i)
            print("|{0}|{1}".format(host, error_indication))
            pass
    
    messages=""
    data_json = {}
    list_name = []
    list_value = []
    # Check for errors and print out results
    if error_indication:
        print("{0} [ERROR] {1} | {2}".format(datetime.utcnow().isoformat(), host, error_indication))#raise CustomException(error_indication)
        data_json.update( {'status' : 'error', "msg_err" : error_indication} )
    else:
        if error_status:
            messages = ('%s at %s' % (
                error_status.prettyPrint(),  # pylint: disable=no-member
                error_index and var_binds[int(error_index) - 1] or '?'))
            #print(messages) #raise CustomException(messages)
            data_json.update( {'status' : 'error', "msg_err" : messages} )
        else:
            if var_binds:
                for data in var_binds:
                    name , value = data[0]
                    #print( str(name) + " = " + str(value))
                    if (column) :
                        list_name.append( str(name) )
                        list_value.append( str(value) )
                    else:
                        data_json.update( { str(name) : str(value)} )
                if(column):
                    data_json.update( {'list_name' : list_name} )
                    data_json.update( {'list_value' : list_value} )
                data_json.update( {'status' : "success"} )
            else:
                messages = 'Empty Replay'
                data_json.update( {'status' : 'error', "msg_err" : messages} )
    return data_json
#########################################################################################
def thread_snmp_walk(host, community, oid, port, column, cola):
    data_json = snmp_walk(host, community, oid, port=port, column=column)
    cola.put( {oid : data_json} ) 
    return
########################################################################################
def multithread_snmp_walk(host, list_oids, community, port=161, column=True, window_delay=0.2):
    cola = queue.Queue()
    list_response = []
    list_threads = []
    for oid in list_oids:
        thread = threading.Thread( target =thread_snmp_walk , args = (host,community,oid, port, column, cola))
        thread.setDaemon(True)
        thread.start()
        time.sleep(window_delay)
        list_threads.append(thread)
    
    for process in list_threads:
        process.join()
    
    time.sleep(0.1)
    while len(list_response) < len(list_oids):
        try:
            data = cola.get_nowait()
            list_response.append(data)
        except queue.Empty: #Ejecuta hasta que la cola este vacia
            break
    
    #Ordenamos segun list_oids, porque nada me asegura que terminen de ejecutarse en el mismo orden
    list_sorted = []
    for oid in list_oids:
        for data in list_response:
            if oid in data:
                list_sorted.append( data[oid] )

    return list_sorted
#########################################################################################
def snmp_get_by_oid(host, community, oid, port=161):
    errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
        cmdgen.CommunityData(community),
        cmdgen.UdpTransportTarget((host, port)),
        oid
    )
    if errorIndication:
        print(errorIndication)
    else:
        if errorStatus:
            print('%s at %s' % (
                errorStatus.prettyPrint(),
                errorIndex and varBinds[int(errorIndex)-1] or '?'
                )
            )
        else:
            for name, val in varBinds:
                return(str(val))
#########################################################################################
def monitor_sys_info(host, community, port=161):
    oid = "iso.org.dod.internet.mgmt.mib-2.system" # 1.3.6.1.2.1.1`
    # Serial, Version, Model
    list_labels = [
                "sysDescr",
                "sysObjectID",
                "sysUpTime",
                "sysContact",
                "sysName",
                "sysLocation",
                "sysServices"]
    
    data_json = snmp_walk(host,community,oid, port=port, column=True)
    if 'list_value' in data_json :
        list_values = data_json['list_value']
    
        if(len(list_labels) != len(list_values) - 5):
            print( "[WARN ] monitor_sys_info {0} |{1}:{2}".format(host , len(list_labels), len(list_values)) )
        
        data_json = {}
        for i in range(0, len(list_labels)):
            data_json.update( {list_labels[i] : list_values[i]} )
        data_json.update( {'status' : 'success'} )
        #print_json(data_json)
        return data_json
    else:
        return {'status' : 'error'}
#########################################################################################    
def monitor_cpu_mem(host, community, port=161):    
    oid = "iso.org.dod.internet.private.enterprises.12356.101.4.1"
    list_labels = [
                "fgSysVersion",
                "fgSysMgmVdom",
                "fgSysCpuUsage",
                "fgSysMemUsage",
                "fgSysMemCapacity",
                "fgSysDiskUSage",
                "fgSysDiskCapacity",
                "fgSysSesCount",
                "fgSysLowMemUsage",
                "fgSysLowMemCapacity",
                "fgSysSesRate1",
                "fgSysSesRate10",
                "fgSysSesRate30",
                "fgSysSesRate60",
                "fgSysSes6Count",
                "fgSysSes6Rate1",
                "fgSysSes6Rate10",
                "fgSysSes6Rate30",
                "fgSysSes6Rate60",
                "fgSysUpTime"]
    
    data_json = snmp_walk(host, community, oid, port=port, column=True)
    if 'list_value' in data_json:    
        list_values = data_json['list_value']
        if(len(list_labels) != len(list_values)):
            print( "[WARN ] monitor_cpu_mem {0}".format(host) )
    
        data_json = {}
        for i in range(0, len(list_labels)):
            data_json.update( {list_labels[i] : list_values[i]} )
        data_json.update( {'status' : 'success'} )
        #print_json(data_json)
        return data_json
    else:
        return {'status' : 'error'}
#########################################################################################
def decoded_value(oid,value_to_decoded):
    dict_status = {
        "1" : "up",
        "2" : "down"
    }
    
    try:
        #Decoding MAC
        if (oid=="1.3.6.1.2.1.2.2.1.6"): 
            value_decoded = string2hex(value_to_decoded).upper()
        #Decoding IP_MASK
        elif (oid=="1.3.6.1.2.1.4.20.1.3"):
            value_decoded = string2hex(value_to_decoded).upper()
        #Decodign STATUS
        elif (oid == "1.3.6.1.2.1.2.2.1.7" or oid =="1.3.6.1.2.1.2.2.1.8"):
            value_decoded = dict_status[value_to_decoded]
        #Decoding TYPE
        elif (oid == "1.3.6.1.2.1.2.2.1.3"):
            value_decoded = dict_type[value_to_decoded]
        #No decoding
        else:
            value_decoded = value_to_decoded
    except:
        print("[ERROR]  decoded_value : oid [{0}] | key [{1}] not found in dict.".format(oid, value_to_decoded))
        value_decoded = value_to_decoded
    finally:
        return value_decoded
#########################################################################################
def monitor_interfaces(host, community, port=161, list_oids="label,mac,alias,type,ip_mask,status"):
    dict_oid = {
        "status" : {
            "admin" : "1.3.6.1.2.1.2.2.1.7",
            "opert" : "1.3.6.1.2.1.2.2.1.8"
        },
        "label" : "1.3.6.1.2.1.31.1.1.1.1",
        "mac" : "1.3.6.1.2.1.2.2.1.6",
        "alias" : "1.3.6.1.2.1.31.1.1.1.18",
        "type" : "1.3.6.1.2.1.2.2.1.3",
        "ip_mask" : "1.3.6.1.2.1.4.20.1.3"
    }

    list_oids = list_oids.split(",")
    list_aux_oid = []
    list_of_oids = []
    for label_oid in list_oids:
        if label_oid=='status':
            list_of_oids.append( dict_oid[label_oid]['admin'] )
            list_of_oids.append( dict_oid[label_oid]['opert'] )
            list_aux_oid.append('status_admin')
            list_aux_oid.append('status_opert')
        else:
            list_of_oids.append( dict_oid[label_oid] )
            list_aux_oid.append( label_oid )
    
    list_response = multithread_snmp_walk(host, list_of_oids, community, port=port, column=True)
    
    data_json = {}
    cont = 0
    for d_json in list_response: 
        if 'list_value' in d_json :
            num_ports = len(d_json['list_value'])
            field = list(range(1, num_ports + 1))
            value = d_json['list_value']
            partial_json = {}
            for i in range(0,num_ports):
                partial_json.update( { "{0}".format(  field[i]  ) : decoded_value(list_of_oids[cont],value[i]) } )
            data_json.update( {list_aux_oid[cont] : partial_json} )
            cont = cont +1
        else:
            pass

    if(len(list_response)>=len(list_oids) and len(data_json)>0):
        data_json.update({'status':'success'})
        #print_json(data_json)
        return data_json
    else:
        print( "{0} [ERROR] monitor_interfaces {1}".format(datetime.utcnow().isoformat(), host) )
        return {'status' : 'error'}
    
    return data_json
#########################################################################################
def monitor_bandwidth(host, community, port=161):
    # Alias, Type, MacAddres, AdminStatus Operation Status
    oid_bandwidth = {
        "bytes_in" : "1.3.6.1.2.1.2.2.1.10",
        "bytes_out" : "1.3.6.1.2.1.2.2.1.16"
    }
    list_in = []
    list_out = []
    list_oids = [oid_bandwidth['bytes_in'], oid_bandwidth['bytes_out']] #[oid_bandwidth['status'], oid_bandwidth['label_port']
    #[data_status, data_labels, data_in, data_out]
    list_response = multithread_snmp_walk(host, list_oids, community, port=port, column=True)# H23
    data_json = {}
    cont=0
    if(len(list_response)==2):
        list_aux_oid = ["in","out"]
        for d_json in list_response:
            if 'list_value' in d_json:
                num_ports = len(d_json['list_value'])
                field = list(range(1, num_ports + 1))
                value = d_json['list_value']
                partial_json = {}
                for i in range(0,num_ports):
                    try:
                        partial_json.update( { "{0}".format( field[i] ) : int(value[i]) } )
                    except:
                        print("[ERROR] monitor_bandwidth - Convert  value to int ({0})".format(value[i]))
                data_json.update( {list_aux_oid[cont] : partial_json} )
                cont = cont +1
        if len(data_json)<=0 :
            data_json.update({'status':'error'})
        else:
            data_json.update({'status':'success'})
        #print_json(data_json)
        return data_json
        """
        # Por si algun día necesite modificar el formato de envio de la data
        data_in = list_response[0]
        data_out = list_response[1]
        #print_json(data_in)
        #print_json(data_out)
        if( len(data_in)>0 and len(data_out)>0 ):
            data_json = {
                "in": data_in,
                "out": data_out,
                'status':'success'
            }
        else:
            data_json = {
                'status':'error'
            }
            print( "{0} [ERROR] monitor_bandwidth {1} length(in/out)=>0 ".format(datetime.utcnow().isoformat(), host) )
        print_json(data_json)
        """
        return data_json
        
    else:
        print( "{0} [ERROR] monitor_bandwidth {1}".format(datetime.utcnow().isoformat(), host) )
        return {'status' : 'error'}
#########################################################################################
def build_yml_label_interfaces(list_client_to_execute, dict_client_ip, community="prueba", dict_ip_label={}, nameFile="label_interfaces.yml"):
    print("{0} [INFO ] build_yml_label_interfaces Updating.".format( datetime.utcnow().isoformat()) )
    data_json = {}
    for client in list_client_to_execute:
        list_ip = dict_client_ip[client]
        for ip_json in list_ip:
            ip = ip_json['ip']
            port = ip_json['port']['snmp']
            aux_json = monitor_interfaces(ip, community, port=port, list_oids="label")
            #aux_json = get_data_firewall_snmp(ip, community, port=161, data_to_monitoring="label")
            if len(aux_json)>0 :
                if (aux_json['status']=="success" and 'label' in aux_json):
                    data_json.update( {ip : aux_json['label']})
                else:
                    print("{0} [WARN ] build_yml_label_interfaces({1}:{2})".format( datetime.utcnow().isoformat(), ip, str(aux_json) ))
            else:
                print("{0} [ERROR] build_yml_label_interfaces({1})".format( datetime.utcnow().isoformat(), ip))
    
    if len(data_json)>0 :
        dict_ip_label.clear()
        dict_ip_label = dict(data_json)
        print("{0} [INFO ] build_yml_label_interfaces OK.".format( datetime.utcnow().isoformat()) )
        data_json.update( {"datetime": "{0}".format(datetime.utcnow().isoformat()) } )
        save_yml(data_json,nameFile=nameFile)
    else:
        print("{0} [WARN ] build_yml_label_interfaces file don't create.".format( datetime.utcnow().isoformat()) )
    return dict_ip_label
#########################################################################################
def add_label_to_bandwidth(data_json, host,path_of_multi_dict='label_interfaces.yml'):
    #print_json(data_json)
    dict_yml = loadYMLtoJSON(path_of_multi_dict)
    if host in dict_yml:
        dict_interfaces = dict_yml[host] #Cargamos el dicionario para el host especificado
        list_data_json = [dict_interfaces]
        list_keys = ['interface','in','out']
        for key  in list_keys:
            if key in data_json:
                d_json = data_json[key]
                list_data_json.append(d_json)
        #print_json(list_data_json)
        table_json =  build_table_json(list_keys, list_data_json)
        new_data_json = {
            "table" : table_json,
            "status" : data_json['status']
        }
        return new_data_json
    else:
        print("[ERROR] add_label_to_bandwidth {0} not found in dict_yml".format(host))
        return data_json
#########################################################################################
def get_data_firewall_snmp(host, community, port=161, sample_time = 15.0, old_time=0, data_to_monitoring="sys_info,bandwidth,cpu_mem", logstash={}, cont=-2):
    start_time = time.time()
    list_monitoring = data_to_monitoring.split(",")
    data_json = {"status" : "error"}
    for index in list_monitoring:
        if index == "sys_info":
            data_json_sys_info = monitor_sys_info(host, community, port=port)
            if len(data_json_sys_info)>0 :
                data_json.update( {index: data_json_sys_info} )
            else:
                print("{0} [ERROR] get_data_firewall_snmp({1}) -> {2}".format( datetime.utcnow().isoformat(), host, index))
        if index == "bandwidth":
            data_json_bandwidth = monitor_bandwidth(host, community, port=port)
            #Se modifico a una tabla tipo json para facilitar la creacion de graficas en Vega
            data_json_bandwidth = add_label_to_bandwidth(data_json_bandwidth,host)
            if len(data_json_bandwidth)>0 :
                data_json.update( {index: data_json_bandwidth} )
            else:
                print("{0} [ERROR] get_data_firewall_snmp({1}) -> {2}".format( datetime.utcnow().isoformat(), host, index))
        if index == "cpu_mem":
            data_json_cpu_mem = monitor_cpu_mem(host,community, port=port)
            if len(data_json_cpu_mem)>0 :
                data_json.update( {index : data_json_cpu_mem} )
            else:
                print("{0} [ERROR] get_data_firewall_snmp({1}) -> {2}".format( datetime.utcnow().isoformat(), host, index))
        if  index.find("-")>=0 or index == "label" or index=="mac" or index=="alias" or index=="type" or index=="ip_mask" or index=="status" :
            aux_index = index.replace("-",",") # Solo para el caso de interfaces reemplazamos "-" con ","
            aux_json = monitor_interfaces(host, community, port=161, list_oids=aux_index)
            if len(aux_json)>0 :
                data_json.update( {"interfaces" : aux_json})
            else:
                print("{0} [ERROR] get_data_firewall_snmp({1}) -> {2}".format( datetime.utcnow().isoformat(), host, index))
    
    enlapsed_time = time.time() - start_time
    if( (enlapsed_time-sample_time-2>0) and (sample_time!=0.0) ):
        data_aditional = {
            "devip" : host,
            "rename_index" : "snmp",
            "enlapsed_time" : "{0:4f}".format(enlapsed_time),
            "old_time" : (start_time), #old_time = start_time
            'datetime': "{0}".format(datetime.utcnow().isoformat()),
            "status" : "error",
            "cont" : cont
        }
        print("{0} [ERROR] get_data_firewall_snmp({1}) timeout - elapsed_time:{2:2f}".format( datetime.utcnow().isoformat() , host, enlapsed_time))
    else:
        data_aditional = {
            "sample_time" : "{0:5f}".format(start_time - old_time) ,
            "devip" : host,
            "rename_index" : "snmp",
            "enlapsed_time" : "{0:4f}".format(enlapsed_time),
            "old_time" : (start_time), #old_time = start_time
            'datetime': "{0}".format(datetime.utcnow().isoformat()),
            "status": "success",
            "cont" : cont
        }
        data_json.update(data_aditional)

        for index in list_monitoring:
            if index in data_json :
                if 'status' in data_json[index] :
                    if data_json[index]['status']=="error" :
                        data_json.update({"status": "error"})
                        break
        
        if (sample_time-enlapsed_time>0 and sample_time>0): time.sleep(sample_time-enlapsed_time)
    #print_json(data_json)
    try:
        flag_send = logstash["send"]
        if(flag_send):
            ip_logstah = logstash["ip"]
            port_logstash = logstash["port"]
            send_json(data_json, IP=ip_logstah, PORT=port_logstash, emulate=(not flag_send) )#, dictionary={"path_of_multi_dict":"label_interfaces.yml", "dict_to_load": host})# dictionary={"multi_dict" : dict_ip_label, "dict_to_load": host})
    except:
        pass
    #print_json(data_json)
    return data_json
#########################################################################################
def get_parametersCMD():
    ip_logstash = port_logstash = typeDevice = ip = port = community = None
    
    parser = argparse.ArgumentParser()

    parser.add_argument("-i","--ip",help="Direccion ip del firewall.")
    parser.add_argument("-pp","--port",help="Puerto del firewall.")
    parser.add_argument("-m","--community",help="Comunidad snmp")
    parser.add_argument("-c","--command",help="Comando a ejecutar en la terminal [ ]")
    parser.add_argument("-ip_out","--ip_out",help="IP del logstash")
    parser.add_argument("-pp_out","--pp_out",help="Puerto del logstash")

    args = parser.parse_args()

    if args.ip: ip = str(args.ip)
    if args.port: port = int(args.port)
    if args.community: community = str(args.community)
    if args.command: command = str(args.command)
    if args.ip_out: ip_logstash = str(args.ip_out)
    if args.pp_out: port_logstash = int(args.pp_out)
    
    if( ip==None or port==None or community==None or command==None):
        print("\nERROR: Faltan parametros.")
        print("ip\t\t= ["+str(ip)+"] \nport\t\t= ["+str(port)+"] \ncommunity\t= ["+str(community)+"] \n")
        sys.exit(0)
    
    if( ip_logstash==None or port_logstash==None):
        print("\nERROR: Faltan parametros.")
        print("ip_out\t= ["+str(ip_logstash)+"]\npp_out\t= ["+str(port_logstash)+"]")
        sys.exit(0)
    
    logstash = {
        "send": True,
        "ip": ip_logstash,
        "port": port_logstash
    }
    get_data_firewall_snmp(ip, community, port=port, data_to_monitoring=command, logstash=logstash)
    return
#########################################################################################
if __name__ == "__main__":
    get_parametersCMD()
    """
    # Configuration of device
    host = '1.1.1.1'
    community = 'prueba'
    logstash = {"send":False,"ip": "8.8.8.8","port": 5959}
    data_json = get_data_firewall_snmp(host, community, port=161,data_to_monitoring="bandwidth",logstash=logstash) #cpu_mem
    print_json(data_json)
    """


