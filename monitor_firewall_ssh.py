#!/usr/bin/env python
#coding: utf-8
########################################################################
#Programmer: Deiner Zapata Silva
#e-mail: deinerzapata@gmail.com
#Date: 13/11/2018
#https://cpiekarski.com/2011/05/09/super-easy-python-json-client-server/
#http://46.101.4.154/Art�culos%20t�cnicos/Python/Paramiko%20-%20Conexiones%20SSH%$
#
import sys, json, socket, argparse, time, os
import paramiko as pmk
import datetime
from utils import send_json, list2json, print_json, print_list
###############################################################################
def validate_result(data_to_validate_json,add_status_field=True,flag_error=False):
    data_json = {}
    data_json.update(data_to_validate_json)
    if len(data_to_validate_json)>0:
        data_json.update( {'status':'success'} )
        flag_error = False or flag_error
    else:
        data_json.update( {'status':'error'}  )
        flag_error = True or flag_error
    return data_json,flag_error
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
    
    if (len(lista)==10):
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
    elif (len(lista)==6):  
        val = lista[4].replace("T","")
        lista_json.update({'total_memory': int(val)})

        val = lista[5].replace("F","")
        lista_json.update({'free_memory': int(val)})
    else:
        print("[WARN] lista=["+str(lista)+"]")
    

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
                    try:
                        data_json.update( { lista[0]+"_MB" :int(lista[1]) } )
                    except:
                        data_json.update( { lista[0]+"_MB" : (lista[1]) } )
        cont = cont + 1
        #print("{0:02d} [{1}]".format(cont,line))
    return data_json
###############################################################################
def memory_sysinfo_to_list_json(simple_lista):
    michi = simple_lista.find("#")
    simple_lista = simple_lista[michi+1:]
    simple_lista = simple_lista.lower()
    simple_lista = simple_lista.replace("(","_")
    simple_lista = simple_lista.replace("):","")
    simple_lista = simple_lista.replace(" kb","")
    simple_lista = simple_lista.replace(":","_kb ")
    list_lines = simple_lista.split('\n')
    cont = 1
    list_shm = []
    data_json = {}
    body = header = None
    for line in list_lines:
        if(line.find("#")>0):
            pass
        else:
            level, lista = get_lista(line)
            if(len(line)>0 and len(lista)>0):
                if(len(lista)>2):
                    if(header==None):
                        header = lista
                    if(body==None):
                        body = lista
                    if(header!=None and body!=None):
                        data_json = {
                            body[0] : {
                                header[0]: body[1], 
                                header[0]: body[2], 
                                header[0]: body[3],
                                header[0]: body[4],
                                header[0]: body[5],
                                header[0]: body[6]
                            }
                        }
                else:
                    data_json.update( { lista[0] : int(lista[1]) } )
        cont = cont + 1
        #print("{0:02d} [{1}]".format(cont,line))
    return data_json
###############################################################################
def shm_table_to_json(simple_lista):
    michi = simple_lista.find("#")
    simple_lista = simple_lista[michi+1:]
    simple_lista = simple_lista.replace(" MB","MB")
    simple_lista = simple_lista.replace("SHM ","shm_")
    simple_lista = simple_lista.replace("FS ","fs_")
    simple_lista = simple_lista.replace(": ","")
    simple_lista = simple_lista.replace("conserve mode","conserve_mode")
    simple_lista = simple_lista.replace("system last entered","sys_last_entered")
    simple_lista = simple_lista.replace("sys fd last entered","sys_fd_last_entered")

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
                if(lista[0]=="conserve_mode" or lista[0]=="sys_last_entered" or lista[0]=="sys_fd_last_entered"):
                    data_json.update( { lista[0] : (lista[1]) } )
                else:
                    try:
                        data_json.update( { lista[0] : int(lista[1]) } )
                    except:
                        print("[ERROR] shm_table_to_json")
                        print(simple_lista)
        cont = cont + 1
        #print("{0:02d} [{1}]".format(cont,line))
    return data_json
###############################################################################
def process_table_to_json(simple_lista):
    #print(simple_lista)#H23
    simple_lista = simple_lista.replace(" <","<")
    simple_lista = simple_lista.replace(" N","N")
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
                lista_json = list2json(list_header, lista)#,type_data=['str','int','str','float','float'])
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
def sys_status_to_json(simple_lista):
    simple_lista = simple_lista.replace("--More-- \r","")
    simple_lista = simple_lista.replace("         \r","")
    michi = simple_lista.find("#")
    simple_lista = simple_lista[michi+2:]
    list_lines = simple_lista.split('\n')
    
    data_json = {}
    for line in list_lines:
        pos = line.find(':')
        if(pos>0):
            field = line[:pos]
            value = line[pos+2:len(line)]
            #print(" ->" + field+ ":"+value)
            data_json.update( {field:value} )
    
    return data_json
###############################################################################
def ssh_connect(IP="0.0.0.0",USER="user",PASS="pass",PORT=2233,timeout=1000,retry_interval=1, num_intent=10):
    #https://netdevops.me/2017/waiting-for-ssh-service-to-be-ready-with-paramiko/
    ssh = pmk.SSHClient()
    ssh.set_missing_host_key_policy(pmk.AutoAddPolicy())
    timeout_start = time.time()
    cont_intent = 0
    while (time.time() < timeout_start+timeout) and (cont_intent < num_intent):
        try:
            ssh_stdin = ssh_stdout = ssh_sterr = None
            ssh.connect(IP , port=PORT ,username=USER , password=PASS,look_for_keys=False,allow_agent=False)#timeout=1
            #print("[INFO] : ssh_connect() -> Conected {0}@{1}".format(USER,IP))
            return ssh
        except pmk.ssh_exception.SSHException as e:
            #Socket is open, but not SSH service responded
            if e:
                print(str(e))
                continue
            #print("[INFO] : ssh_conect() {0}@{1} SSH transport is available!.")
            break
        except pmk.ssh_exception.NoValidConnectionsError as e:
            #print("[INFO] : ssh_conect() {0}@{1} SSH transport is not ready.".format(USER,IP))
            continue
        except:
            print("{3} [ERROR] : ssh_connect() {0}@{1} :{2}".format(USER,IP,sys.exc_info()[0], datetime.datetime.utcnow().isoformat()))
            return ""
        finally:
            print("{2} [WARN ] : ssh_connect() Trying to connect {0}@{1}".format(USER,IP, datetime.datetime.utcnow().isoformat()))
            cont_intent = cont_intent + 1
            time.sleep(retry_interval)
    return ""
###############################################################################
def ssh_exec_command(command,ssh_obj=None,IP='0.0.0.0',USER='user',PASS='password',PORT=2233, obj_extern = False):
    ssh_stdin = ssh_stdout = ssh_sterr = None
    
    try:
        if(ssh_obj==None):
            ssh_obj = ssh_connect(IP=IP,USER=USER,PASS=PASS,PORT=PORT)
            obj_extern = True
        in_, out_, error = ssh_obj.exec_command(command)
        if(obj_extern):
            print("[INFO] ssh_exec_command - close conection.")
            ssh_obj.close()
        #print(str(error.read()))
        output_txt = out_.read()
        error_txt = error.read()
    except:
        output_txt = error_txt = ""
    return output_txt,error_txt
###############################################################################
def ssh_download_config(ssh_obj, device="forti"):
    #http://www.unixfu.ch/diag-sys-top-2/
    data_json={}
    #print(str(device))
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
    return data_json
###############################################################################
def ssh_get_sys_status(ssh_obj, command='get system status'):# No necesita especificar vdom es igual en todos los ambientes
    outtxt,errortxt = ssh_exec_command(command,ssh_obj=ssh_obj)
    data_json = sys_status_to_json(outtxt.decode('utf-8'))
    data_json.update({'command' : command})
    return data_json
###############################################################################
def ssh_get_sysinfo_shm(ssh_obj, command='diagnose hardware sysinfo shm'):# solo soporta global
    outtxt,errortxt = ssh_exec_command(command,ssh_obj=ssh_obj)
    if errortxt.decode('utf-8').find("Command fail")>=0:
        outtxt,errortxt = ssh_exec_command("config global\n{0}\n".format(command),ssh_obj=ssh_obj)
    
    if errortxt.decode('utf-8').find("Command fail")>=0:
        print("[ERROR] ssh_get_sysinfo_shm : Command fail. Maybe you need add 'vdom'.")
        data_json={}
    else:
        data_json = shm_table_to_json(outtxt.decode('utf-8'))
        data_json.update({'command' : command})
    
    return data_json
###############################################################################
def ssh_get_sysinfo_conserve(ssh_obj, command='diagnose hardware sysinfo conserve'):# solo soporta global

    outtxt,errortxt = ssh_exec_command(command,ssh_obj=ssh_obj)
    if errortxt.decode('utf-8').find("Command fail")>=0:
        outtxt,errortxt = ssh_exec_command("config global\n{0}\n".format(command),ssh_obj=ssh_obj)
    
    data_json = conserve_sysinfo_to_list_json(outtxt.decode('utf-8'))
    data_json.update({'command' : command})
    #print_json(data_json)
    return data_json
###############################################################################
def ssh_get_sysinfo_memory(ssh_obj, command='diagnose hardware sysinfo memory'):# solo soport global
    
    outtxt,errortxt = ssh_exec_command(command,ssh_obj=ssh_obj)
    if errortxt.decode('utf-8').find("Command fail")>=0:
        outtxt,errortxt = ssh_exec_command("config global\n{0}\n".format(command),ssh_obj=ssh_obj)
    
    if errortxt.decode('utf-8').find("Command fail")>=0:
        print("[ERROR] ssh_get_process_runing : Command fail. Maybe you need add 'vdom'.")
        data_json= {}
    else:
        data_json = memory_sysinfo_to_list_json(outtxt.decode('utf-8'))
        data_json.update({'command' : command})
    #H23print_json(data_json)
    
    return data_json
###############################################################################
def ssh_get_process_runing(ssh_obj, command='diag sys top 5 25 \x0fm',vdom=None): # UTM_FG , root
    if(vdom!=None):
        if vdom=="global":
            command_vdom = "config global\n{0}\n".format(command)
        else:
            command_vdom = "config vdom\n edit {0}\n {1}\n".format(vdom,command)
        outtxt,errortxt = ssh_exec_command(command_vdom,ssh_obj=ssh_obj)# --sort=name #ERROR: diag sys top-summary
    else:
        outtxt,errortxt = ssh_exec_command(command,ssh_obj=ssh_obj)# --sort=name #ERROR: diag sys top-summary

    if errortxt.decode('utf-8').find("Command fail")>=0:
        print("[ERROR] ssh_get_process_runing : Command fail. Maybe you need add 'vdom'.")
        data_json= {}
    else:
        data_json = process_table_to_json(errortxt.decode('utf-8'))
        data_json.update({'command' : command})
    return data_json
###############################################################################
def test_logstash_conection(IP_LOGSTASH="0.0.0.0", PORT_LOGSTASH=2233):
    lista_json = {
        '@message' : 'python test message logtash',
        '@tags' : ['python', 'test'],
        'datetime': "{0}".format(datetime.datetime.utcnow().isoformat())
    }
    send_json(lista_json, IP=IP_LOGSTASH, PORT = PORT_LOGSTASH)
    return
###############################################################################
def ssh_execute_by_command(command_input, ip , port , user , passw, typeDevice='forti', logstash={}, vdom=None):#Vdom puede ser una lista o solo un parametro
    ssh_obj = ssh_connect(IP=ip,USER=user,PASS=passw,PORT=port)
    data_json = {}
    flag_error = False

    if vdom!=None and type(vdom)!=list: vdom = [vdom] #Si vdom!None, entonces (es un string) y lo convertimos en list

    if ssh_obj=="" or ssh_obj==None :
        print("[ERROR] ssh_execute_by_command | ssh_obj:{0}".format(ssh_obj))
        flag_error = True
    else:
        list_command = command_input.split(",")
        for command in list_command:
            list_vdom_rpt_json=[]
            if (command=="sys_status"):
                rpt_json = ssh_get_sys_status(ssh_obj)
            if (command=="sysinfo_conserve"):
                rpt_json = ssh_get_sysinfo_conserve(ssh_obj)#Si da error accede a la configuración global -> solo acepta global
            if (command=="sysinfo_memory"):
                rpt_json = ssh_get_sysinfo_memory(ssh_obj)#Si da error accede a la configuración global -> solo acepta global
            if (command=="sysinfo_shm"):#Si da error accede a la configuración global -> solo acepta global
                rpt_json = ssh_get_sysinfo_shm(ssh_obj)
            #----------COMANNDOS VDOM--------------------------------------------------------------------------
            if(command=="check_process"):
                if vdom!=None :
                    for one_vdom in vdom:
                        rpt_json = ssh_get_process_runing(ssh_obj,vdom=one_vdom)
                        rpt_json.update( {'vdom_name': one_vdom} )
                        list_vdom_rpt_json.append(rpt_json)
                else:
                    rpt_json = ssh_get_process_runing(ssh_obj)
            #----------INI DEPRECADE------------------------------------------------------------------------------
            if(command=="down_config"):
                rpt_json = ssh_download_config(ssh_obj,device=typeDevice)
            if(command=="test_logstash_conection"):
                try:
                    ip_logstash = logstash['ip']
                    port_logstash = logstash['port']
                    test_logstash_conection(IP_LOGSTASH=ip_logstash,PORT_LOGSTASH=port_logstash)
                    rpt_json.update( {command : { 'status' : 'success'} })
                except:
                    rpt_json.update( {command : { 'status' : 'error'} })
            #----------END DEPRECADE------------------------------------------------------------------------------
            if len(list_vdom_rpt_json)>0:
                vdom_json={'vdom':{}}
                for rpt_json in list_vdom_rpt_json:
                    vdom_name = rpt_json['vdom_name']
                    del rpt_json['vdom_name']
                    rpt_json,flag_error = validate_result(rpt_json,add_status_field=True,flag_error=flag_error)
                    vdom_json['vdom'].update( { vdom_name: { "check_process":rpt_json } } )
                data_json.update( vdom_json )
                list_vdom_rpt_json=[]
            else:
                rpt_json,flag_error = validate_result(rpt_json,add_status_field=True,flag_error=flag_error)
                data_json.update( { command : rpt_json } )
        try: #H23 - mejorar el manejo de errores y parseo para multiprocesos
            ssh_obj.close()
        except:
            pass
    if (flag_error):
        data_json.update( {'status': 'error'} )
    else:
        data_json.update( {'status': 'success'} )
    return data_json
###############################################################################
def ping_test(IP="0.0.0.0"):
    rpt_ping="DOWN"
    rpt = os.sytem("ping :"+IP)#os.system("ping -c 1"+ip)#Superuser
    if(rpt==0): rpt_ping="UP"
    return rpt_ping
###############################################################################
def send_data_by_one_process( data_only_for_one_process_json, name_proccess, data_aditional, logstash={}):
    data_json_by_command = {}
    data_json_by_command = { name_proccess :  data_only_for_one_process_json }
    data_json_by_command.update( data_aditional )
    
    try:
        flag_send = logstash["send"]
        if(flag_send):
            ip_logstah = logstash['ip']
            port_logstash = logstash['port']
            send_json(data_json_by_command, IP=ip_logstah, PORT=port_logstash)
    except:
        print("[INFO] send_data_by_one_process() | No se envio la data_json al logstash.")
        pass
    return
###############################################################################
def get_data_firewall_ssh(command, ip, port, user, passw, old_time=0, logstash={}, vdom=None): #Para el caso de ser ejecutado por "multiprocess", la variable "vdom", debe ser una lista.
    data_json = {}
    start_time = time.time()
    data_json = ssh_execute_by_command(command, ip , port , user , passw,typeDevice='forti', logstash={}, vdom=vdom)
    enlapsed_time = time.time() - start_time
    status_general = data_json['status']
    del data_json['status']
    #Todos los procesos (ejecutados en un solo commando separados por comas) tienen la misma data adicional
    data_aditional = {
        "devip" : ip,
        'rename_index':'health',
        "enlapsed_time": "{0:4f}".format(enlapsed_time),
        'old_time' : (start_time),
        'datetime' : "{0}".format(datetime.datetime.utcnow().isoformat())
    }
    for name_proccess in list(data_json):
        if (name_proccess=='vdom'):
            """
            'vdom' : {
                'name_vdom_01' : {
                    'command01': {...}
                },
                'name_vdom_02' : {
                    'command02': {...}
                }
            }
            """
            #bucle for para cada processo
            temp_json = data_json['vdom']
            for name_vdom in list( temp_json ):
                data_json_by_one_vdom = temp_json[name_vdom]
                vdom_name_proccess='check_process'
                if vdom_name_proccess in data_json_by_one_vdom: #for vdom_name_proccess in list(data_json_by_one_vdom):
                    data_add = {}
                    data_add.update( data_aditional )
                    data_add.update( {'vdom': name_vdom} )
                    send_data_by_one_process( data_json_by_one_vdom[vdom_name_proccess] , vdom_name_proccess, data_add, logstash=logstash )
                else:
                    print("[ERROR] get_data_firewall_ssh() - Key not found : {0}".format(vdom_name_proccess))
                    print_json(temp_json)
            #send_data_by_one_process( data_only_for_one_process_json , name_proccess, data_aditional, logstash=logstash)
        else:
            send_data_by_one_process( data_json[name_proccess] , name_proccess, data_aditional, logstash=logstash )
    data_json.update(data_aditional)
    data_json.update({'status': status_general})
    return data_json
###############################################################################
def get_parametersCMD():
    ip = port = user = passw = command = vdom = None
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
    parser.add_argument("-vdom","--vdom",help="Especify the vdom where to execute command.")
    
    args = parser.parse_args()

    if args.ip: ip = str(args.ip)
    if args.port: port = int(args.port)
    if args.user: user = str(args.user)
    if args.password: passw = str(args.password)
    if args.command: command = str(args.command)
    if args.ip_out: ip_logstash = str(args.ip_out)
    if args.pp_out: port_logstash = int(args.pp_out)
    if args.device: typeDevice = str(args.device)
    if args.vdom: vdom = str(args.vdom)
    
    if( ip==None or port==None or user==None or command==None):
        print("\nERROR: Faltan parametros.")
        print("ip\t= ["+str(ip)+"] \nport\t= ["+str(port)+"] \t= ["+str(user)+"] \n"+"passw\t= ["+str(passw)+"]")
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

    get_data_firewall_ssh(command, ip, port, user, passw, logstash=logstash, vdom=vdom)
    return
###############################################################################
if __name__=="__main__":
    get_parametersCMD()
    sys.exit(0)
###############################################################################
#get system status