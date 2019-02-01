#!/usr/bin/env python
#coding: utf-8
########################################################################
#Programmer: Deiner Zapata Silva
#e-mail: deinerzapata@gmail.com
#Date: 13/11/2018
#https://cpiekarski.com/2011/05/09/super-easy-python-json-client-server/
#http://46.101.4.154/Art�culos%20t�cnicos/Python/Paramiko%20-%20Conexiones%20SSH%$
#
import paramiko as pmk
import sys, json, socket, time, argparse, datetime
from utils import *
###############################################################################
def get_lista(lineTxt,char_split=" "):
    Lista = lineTxt.split(char_split)
    levelAux = flagMore = flagOne = 0
    newLista = []
    level = flagCommandFound = -1

    for item in Lista:
        levelAux = levelAux + 1
        if(len(item)>=2 and flagCommandFound==-1 and item!="--More--"):
            flagCommandFound = 1
        if(len(item)>0 and item!="--More--" and flagCommandFound==1):
            newLista.append(item)
            if(level==-1 or item=="\r"):
                level = levelAux
        if(flagOne==2 and flagMore==1):
            levelAux = 2
            flagMore=2
        if(1==len(item)):
            flagOne=flagOne+1
        if(item=="--More--"):
            flagMore=1    
        #print str(levelAux) +":"+str(len(item)) +">" + str(item)
    
    #print str(level) +" : "+str(newLista)
    #print str(level) +":"+str(len(item)) +">" + str(item)
    return level , newLista
###############################################################################
def process_line(lineTxt):
    command =  field = value =""
    idx_ini_01 = lineTxt.find("$ #")        # linea inicial
    idx_ini_02 = lineTxt.find("Run Time")   # linea inicial
    idx_equal = lineTxt.find("=")
    idx_michi = lineTxt.find("#")
    idx_jumpLine = lineTxt.find("\n")
    lista = []
    level = -1
    # Procesando caso especial "Backslash"
    if (len(lineTxt)!=idx_jumpLine+1):
        print("[WARNING]: proccess_line: New line : "+str(lineTxt))
        return level, lista
    # Eliminando el salto de linea al final.
    if(idx_jumpLine>=0):
        lineTxt = lineTxt[:idx_jumpLine]
    # Procesando caso especial "Primera Linea" -> "Alianza_Lima $ #config-version=FG100E-6.0.2-FW-build0163-3-180725:opmode=1:vdom=0:user=fortisiem"
    if (idx_ini_01>0):
        lista.append(lineTxt[idx_ini_01+3:idx_equal])
        lista.append(lineTxt[idx_equal+1:])
        return 1,lista
    # Procesando caso especial "Primera Linea" -> "[JRun Time"
    if (idx_ini_02>0):
        lista.append(lineTxt[idx_ini_02:])
        return 1,lista
    # Procesando caso general "Texto separado por espacios"-> "text1 text2 text3 ..."
    level, lista = get_lista(lineTxt)
    return level,lista
###############################################################################
def fileTXT_save(text, nameFile = "FortiConfBackup23.txt", typeProcess=None):
    nameTempFile = nameFile[:nameFile.find(".")] + ".temp"
    ftemp = open(nameTempFile,"wb")
    ftemp.write( text )
    ftemp.close()

    # Procesando cada linea
    ftemp = open(nameTempFile,"r")
    fnew  = open(nameFile,"w")
    cont = 0
    if(typeProcess==None):
        lista_total = ""
    else:
        lista_total = []
    for line in ftemp :
        if(typeProcess==None):
            line = line.replace("--More-- \n","")
            line = line.replace("--More-- \r","")
            line = line.replace("         \r","")
            if(len(line)==len("         \n")):
                line = line.replace("         \n","")
            if(len(line)>0):
                fnew.write(line) # str(aux=[line])+'\n'
                lista_total = lista_total + line
        else:
            level, lista = process_line(line)
            cont = cont + 1
            if(lista.__len__()>0):
                #print(">0:"+str( lista.__len__() )
                lista_total.append([lista,level])
                fnew.write(str(level)+":"+str(lista)+"\n")
        
    ftemp.close()
    fnew.close()
    # 
    return lista_total
###############################################################################
def process_header(lista):
    lista_json = {}
    for i in range(0,len(lista)):
        val = lista[i]
        val = val.replace(",","")
        val = val.replace(";","")
        lista[i]=val
    
    val = lista[0].replace("U","")
    lista_json.update({'cpu_usage_app': int(val)})

    val = lista[1].replace("N","")
    lista_json.update({'cpu_usage_low_priority': int(val)})

    val = lista[2].replace("S","")
    lista_json.update({'cpu_usage_kernel': int(val)})

    val = lista[3].replace("I","")
    lista_json.update({'cpu_usage_app_inactive': int(val)})
        
    val = lista[4].replace("WA","")
    lista_json.update({'cpu_time_wait_IO': int(val)})

    val = lista[5].replace("HI","")
    lista_json.update({'cpu_time_wait_hardware_interruption': int(val)})

    val = lista[6].replace("SI","")
    lista_json.update({'cpu_time_wait_software_interruption': int(val)})

    val = lista[7].replace("ST","")
    lista_json.update({'cpu_time_wait_cpu_virtual': int(val)})

    val = lista[8].replace("T","")
    lista_json.update({'total_memory': int(val)})

    val = lista[9].replace("F","")
    lista_json.update({'free_memory': int(val)})

    #val = lista[].replace("KF","")
    #lista_json.update({'kernel_free_memory': (val)})
    return lista_json
###############################################################################
def conserve_sysinfo_to_list_json(simple_lista):
    simple_lista = simple_lista.replace(" MB","")
    simple_lista = simple_lista.replace(" RAM","")
    simple_lista = simple_lista.replace("memory used:","used")
    simple_lista = simple_lista.replace("memory used ","")
    simple_lista = simple_lista.replace("threshold ","thr_")
    simple_lista = simple_lista.replace(": ","")
    simple_lista = simple_lista.replace("of total","")
    list_lines = simple_lista.split('\n')
    cont = 1
    list_shm = []
    data_json = {}
    for line in list_lines:
        if(line.find("#")>0):
            pass
        else:
            level, lista = get_lista(line)
            if(len(line)>0 and len(lista)>0):
                if(len(lista)==3):
                    aux = lista[2][:len(lista[2])-1]
                    data = { lista[0] : {"megabytes":int(lista[1]) ,"percentage" : int(aux) } }
                    data_json.update( data )
                else:
                    data_json.update( { lista[0]+"_MB" :int(lista[1]) } )
        cont = cont + 1
        #print("{0:02d} [{1}]".format(cont,line))
    return data_json
###############################################################################
def memory_sysinfo_to_list_json(simple_lista):
    simple_lista = simple_lista.lower()
    simple_lista = simple_lista.replace("(","_")
    simple_lista = simple_lista.replace("):","")
    simple_lista = simple_lista.replace(" kb","")
    simple_lista = simple_lista.replace(": ","_kb")
    list_lines = simple_lista.split('\n')
    cont = 1
    list_shm = []
    data_json = {}
    for line in list_lines:
        if(line.find("#")>0):
            pass
        else:
            level, lista = get_lista(line)
            if(len(line)>0 and len(lista)>0):
                data_json.update( { lista[0] : int(lista[1]) } )
        cont = cont + 1
        #print("{0:02d} [{1}]".format(cont,line))
    return data_json
###############################################################################
def shm_table_to_json(simple_lista):
    simple_lista = simple_lista.replace(" MB","MB")
    simple_lista = simple_lista.replace("SHM ","shm_")
    simple_lista = simple_lista.replace("FS ","fs_")
    simple_lista = simple_lista.replace(": ","")
    list_lines = simple_lista.split('\n')
    cont = 1
    list_shm = []
    data_json = {}
    for line in list_lines:
        if(line.find("#")>0):
            pass
        else:
            level, lista = get_lista(line)
            if(len(line)>0 and len(lista)>0):
                data_json.update( { lista[0] : int(lista[1]) } )
        cont = cont + 1
        #print("{0:02d} [{1}]".format(cont,line))
    return data_json
###############################################################################
def process_table_to_json(simple_lista):
    simple_lista = simple_lista.replace(" <","<")
    list_lines = simple_lista.split('\n')
    list_header = ["process_name","pid","process_status","cpu_usage","mem_usage"]
    cont = cont_proc = 1
    list_process = []
    header_json = {}
    for line in list_lines:
        lista_json = {}
        if(len(line)>0 and cont>1):
            level, lista = get_lista(line)
            if cont==2 :
                header_json = process_header(lista)
            elif cont>2 :
                lista_json = list2json(list_header, lista,type_data=['str','int','str','float','float'])
                lista_json.update({"pos":cont_proc})
                cont_proc = cont_proc + 1
            
            if(len(lista_json)>0):
                list_process.append(lista_json)
                #print(lista_json)
        #print("{0:02d} [{1}]".format(cont,line))
        cont = cont + 1
    data_json = { 'sys_summary': header_json , 'table_process': list_process}
    return data_json
###############################################################################
def ssh_connect(IP="0.0.0.0",USER="user",PASS="pass",PORT=2233):
    ssh = pmk.SSHClient()
    try:
        ssh.set_missing_host_key_policy(pmk.AutoAddPolicy())
        ssh_stdin = ssh_stdout = ssh_sterr = None
        ssh.connect(IP , port=PORT ,username=USER , password=PASS,look_for_keys=False,allow_agent=False)
        print("[INFO] : ssh_connect() -> Conected {0}@{1}".format(USER,IP))
    except:
        print("[ERROR] : ssh_connect() {0}@{1} :{2}".format(USER,IP,sys.exc_info()[0]) )
    finally:
        return ssh
    return
###############################################################################
def ssh_exec_command(command,ssh_obj=None,IP='0.0.0.0',USER='user',PASS='password',PORT=2233):
    ssh_stdin = ssh_stdout = ssh_sterr = None
    obj_extern = False
    if(ssh_obj==None):
        ssh_obj = ssh_connect(IP=IP,USER=USER,PASS=PASS,PORT=PORT)
        obj_extern = True
    in_, out_, error = ssh_obj.exec_command(command)
    if(obj_extern):
        ssh_obj.close()
    #print(str(error.read()))
    output_txt = out_.read()
    error_txt = error.read()
    return output_txt,error_txt
###############################################################################
def ssh_download_config(ssh_obj, device="forti"):
    #http://www.unixfu.ch/diag-sys-top-2/
    print(str(device))
    if(device=="forti"):
        print("forti")
        outtxt,errortxt = ssh_exec_command(ssh_obj, "show full-configuration")#command by forti device
    if(device=="paloalto"):
        print("paloalto")
        outtxt,errortxt = ssh_exec_command(ssh_obj, "configure\n") #command by paloalto device
        print(str(outtxt))
        print(str(errortxt))
        
        outtxt,errortxt = ssh_exec_command(ssh_obj, "show")
        print(str(outtxt))
        print(str(errortxt))
        
    file_down = fileTXT_save(outtxt,nameFile= time.strftime("%Y%m%d")+".txt" )
    data_json.update({'backup_file':outtxt})
    return
###############################################################################
def ssh_get_sysinfo_shm(ssh_obj):
    outtxt,errortxt = ssh_exec_command('diagnose hardware sysinfo shm',ssh_obj=ssh_obj)
    data_json = shm_table_to_json(outtxt.decode('utf-8'))
    return data_json
###############################################################################
def ssh_get_sysinfo_conserve(ssh_obj):
    outtxt,errortxt = ssh_exec_command('diagnose hardware sysinfo conserve',ssh_obj=ssh_obj)
    data_json = conserve_sysinfo_to_list_json(outtxt.decode('utf-8'))
    return data_json
###############################################################################
def ssh_get_sysinfo_memory(ssh_obj):
    outtxt,errortxt = ssh_exec_command('diagnose hardware sysinfo memory',ssh_obj=ssh_obj)
    data_json = memory_sysinfo_to_list_json(outtxt.decode('utf-8'))
    return data_json
###############################################################################
def ssh_get_process_runing(ssh_obj):
    outtxt,errortxt = ssh_exec_command('diag sys top 5 25 \x0fm',ssh_obj=ssh_obj)# --sort=name #ERROR: diag sys top-summary
    data_json = process_table_to_json(errortxt.decode('utf-8'))
    return data_json
###############################################################################
def test_logstash_conection(IP_LOGSTASH="0.0.0.0", PORT_LOGSTASH=2233):
    lista_json = {
        '@message' : 'python test message logtash',
        '@tags' : ['python', 'test']
    }
    send_json(lista_json, IP=IP_LOGSTASH, PORT = PORT_LOGSTASH)
    return
###############################################################################
def execute_by_command(command_input, ip , port , user , passw, typeDevice='forti'):
    ssh_obj = ssh_connect(IP=ip,USER=user,PASS=passw,PORT=port)
    data_json = {}
    list_command = command_input.split(",")
    for command in list_command:
        if (command=="sysinfo_shm"):
            data_json.update( { 'sysinfo_shm' : ssh_get_sysinfo_shm(ssh_obj)} )

        if (command=="sysinfo_conserve"):
            data_json.update( { 'sysinfo_conserve' : ssh_get_sysinfo_conserve(ssh_obj)} )
        
        if (command=="sysinfo_memory"):
            data_json.update( { 'sysinfo_memory' : ssh_get_sysinfo_memory(ssh_obj)} )

        if(command=="check_process"):
            data_json.update( { 'check_process' : ssh_get_process_runing(ssh_obj)} )

        if(command=="down_config"):
            data_json.update( { 'down_config' : ssh_download_config(ssh_obj,device=typeDevice)} )

        if(command=="test_logstash_conection"):
            test_logstash_conection(IP_LOGSTASH=ip_logstash,PORT_LOGSTASH=port_logstash)
    ssh_obj.close()
    return data_json
###############################################################################
def ping_test(IP="0.0.0.0"):
    rpt_ping="DOWN"
    rpt = os.sytem("ping "+ip)#os.system("ping -c 1"+ip)#Superuser
    if(rpt==0): rpt_ping="UP"
    return rpt_ping
###############################################################################
def get_data_firewall_ssh(command, ip, port, user, passw, ip_logstash='0.0.0.0', port_logstash=2323):
    data_json = execute_by_command(command, ip , port , user , passw, typeDevice='forti')
    data_json.update({'rename_index':'heartbeat' , 'datetime' : datetime.utcnow().isoformat() , "devip" : ip})
    if( isAliveIP(ip_logstash) ):
        send_json(data_json,IP=ip_logstash,PORT=port_logstash)
        #print_json(data_json)
    return
###############################################################################
def get_parametersCMD():
    ip_logstash = port_logstash = typeDevice = None
    parser = argparse.ArgumentParser()

    parser.add_argument("-i","--ip",help="Direccion ip del host")
    parser.add_argument("-pp","--port",help="Puerto del host")
    parser.add_argument("-u","--user",help="Usuario SSH")
    parser.add_argument("-p","--password",help="Password SSH")
    parser.add_argument("-c","--command",help="Comando a ejecutar en la terminal [down_config,check_process,test_logstash_conection]")
    parser.add_argument("-ip_out","--ip_out",help="IP del logstash")
    parser.add_argument("-pp_out","--pp_out",help="Puerto del logstash")
    parser.add_argument("-d","--device",help="Type of device [forti=default,paloalto]")

    args = parser.parse_args()

    if args.ip: ip = str(args.ip)
    if args.port: port = int(args.port)
    if args.user: user = str(args.user)
    if args.password: passw = str(args.password)
    if args.command: command = str(args.command)
    if args.ip_out: ip_logstash = str(args.ip_out)
    if args.pp_out: port_logstash = int(args.pp_out)
    if args.device: typeDevice = str(args.device)
    
    if( ip==None or port==None or user==None or command==None):
        print("\nERROR: Faltan parametros.")
        print("ip\t= ["+str(ip)+"] \nport\t= ["+str(port)+"] \nuser\t= ["+str(user)+"] \n"+"passw\t= ["+str(passw)+"]")
        sys.exit(0)
    
    if( ip_logstash==None or port_logstash==None):
        print("\nERROR: Faltan parametros.")
        print("ip_out\t= ["+str(ip_logstash)+"]\npp_out\t= ["+str(port_logstash)+"]")
        sys.exit(0)
    print("iplogstash:"+ip_logstash)
    get_data_firewall_ssh(command, ip, port, user, passw, ip_logstash=ip_logstash, port_logstash=port_logstash)
    return
###############################################################################
if __name__=="__main__":
    get_parametersCMD()
    sys.exit(0)
###############################################################################
