#!/usr/bin/env python
#coding: utf-8
#########################################################################################
# Developer: Deiner Zapata Silva.
# Date: 17/01/2020
# Last update: 06/03/2020
# Description: Extract backup from firewall using api request.
# sys.setdefaultencoding('utf-8') #reload(sys)
#########################################################################################
from utils import *
from jinja2 import Template 
#########################################################################################
def build_lists_hosts_pipeline( list_ips):
    tmplt_snmp_hosts = "{ host => \"udp:{{host.ip}}/{{host.port}}\" community => \"{{host.community}}\" version => \"{{host.version}}\" retries => {{host.retries}} }"
    obj_tmplt = Template(tmplt_snmp_hosts)
    lists_devices = []
    for ip in list_ips:
        host = {
            "ip": ip,
            "port": 161,
            "community": "logstash",
            "version": "2c",
            "retries": 3
        }
        host_str = obj_tmplt.render(host=host)
        lists_devices.append(host_str)
        
    str_lists_devices =  "[\n                  "\
                        +',\n                  '.join(lists_devices)\
                        + "\n                 ]"
    
    return str_lists_devices

def split_list_by_num_elements(list_to_split, num_elemts_by_group):
    total_elem = len(list_to_split)
    list_group_by_n = []
    idx_ini = 0 
    idx_end = 0
    while idx_end <= total_elem:
        idx_end +=  num_elemts_by_group
        part_of_list = list_to_split[idx_ini : idx_end]
        idx_ini = idx_end
        if len(part_of_list)>0:
            list_group_by_n.append( part_of_list )
    return list_group_by_n

def build_snmp_walk ( list_ips, tmplt_snmp_walk, group_ip = 2):
    list_snmp_input_str = []
    # Spliting list_ips in groups of 2 items
    list_group_by_2 = split_list_by_num_elements(list_ips, group_ip)
    #print_list(list_group_by_2)
    for one_group in list_group_by_2:
        str_lists_hosts = build_lists_hosts_pipeline(one_group)
        # Building snmp input for each group
        snmp_input = {
            "hosts" : str_lists_hosts
        }
        obj_tmplt = Template(tmplt_snmp_walk)
        snmp_input_str = obj_tmplt.render( snmp_input = snmp_input)
        print(snmp_input_str)
    return snmp_input_str

# serial_number : 1.3.6.1.4.1.12356.101.13.2.1.1.2.1
tmplt_snmp_table_vpnssl = """
##################################### TABLE SSL #########################################################
    snmp {
        hosts => {{snmp_input.hosts}}
        tables => [
            {
                "name" => "fgVpnSsl"
                "columns" => [
                    "1.3.6.1.4.1.12356.101.12.2.4.1.1","1.3.6.1.4.1.12356.101.12.2.4.1.2","1.3.6.1.4.1.12356.101.12.2.4.1.3",
                    "1.3.6.1.4.1.12356.101.12.2.4.1.4","1.3.6.1.4.1.12356.101.12.2.4.1.5","1.3.6.1.4.1.12356.101.12.2.4.1.6",
                    "1.3.6.1.4.1.12356.101.12.2.4.1.7","1.3.6.1.4.1.12356.101.12.2.4.1.8",
                    "1.3.6.1.4.1.12356.101.12.2.3.1.1","1.3.6.1.4.1.12356.101.12.2.3.1.2","1.3.6.1.4.1.12356.101.12.2.3.1.3",
                    "1.3.6.1.4.1.12356.101.12.2.3.1.4","1.3.6.1.4.1.12356.101.12.2.3.1.5","1.3.6.1.4.1.12356.101.12.2.3.1.6",
                    "1.3.6.1.4.1.12356.101.12.2.3.1.7"
                ]
            }
        ]
        get  => ["1.3.6.1.4.1.12356.100.1.1.1.0","1.3.6.1.2.1.1.5.0"]
        oid_root_skip => 7
        tags => ["vpn","ssl"]
        add_field => { "[host][ip]" => "%{[@metadata][host_address]}"}
        interval => 60
    }

"""

tmplt_snmp_walk_firewall = """
    ##################################### SNMPWALK #########################################################
    snmp {
        hosts => {{snmp_input.hosts}}
        walk => ["1.3.6.1.2.1.1","1.3.6.1.4.1.12356.101.4.1"]
        get  => ["1.3.6.1.4.1.12356.100.1.1.1.0"]
        tags => ["snmp","cpu","mem","systeminfo"]
        oid_root_skip => 7
        mib_paths => ["/etc/logstash/FORTINET-FORTIGATE-MIB.dic"]
        add_field => { "[host][ip]" => "%{[@metadata][host_address]}"}
        interval => 30
    }
    ##################################### TABLES ###########################################################
    snmp {
        hosts => {{snmp_input.hosts}}
        tables => [
            {
                "name" => "interfaces"
                "columns" => [
                    "1.3.6.1.2.1.2.2.1.7","1.3.6.1.2.1.2.2.1.8","1.3.6.1.2.1.2.2.1.9","1.3.6.1.2.1.2.2.1.10",
                    "1.3.6.1.2.1.2.2.1.14","1.3.6.1.2.1.2.2.1.16","1.3.6.1.2.1.2.2.1.20","1.3.6.1.2.1.31.1.1.1.1"
                ]
            }
        ]
        get  => ["1.3.6.1.4.1.12356.100.1.1.1.0","1.3.6.1.2.1.1.5.0"]
        oid_root_skip => 7
        tags => ["snmp","interface"]
        add_field => { "[host][ip]" => "%{[@metadata][host_address]}"}
        interval => 30
    }
        """

tmplt_snmp_walk_switch = """
    ##################### WALK   - TEMPERATURA ###########################################
    snmp {
        hosts => {{snmp_input.hosts}}
        walk => ["1.3.6.1.4.1.9.9.13.1.3.1"]
        get => ["1.3.6.1.4.1.9.5.1.2.19.0"]
        tags => ["snmp","temperature","systeminfo"]
        mib_paths => ["/etc/logstash/CISCO-STACK-MIB.dic"]
        add_field => { "[host][ip]" => "%{[@metadata][host_address]}"}
        interval => 60
    }
    ##################### TABLES - BANDWIDTH##############################################
    snmp {
        hosts => {{snmp_input.hosts}}
        tables => [
            {
                "name" => "interfaces" 
                "columns" => [
                    "1.3.6.1.2.1.2.2.1.10","1.3.6.1.2.1.2.2.1.16","1.3.6.1.2.1.31.1.1.1.1"
                ]
            }
        ]
        oid_root_skip => 7
        tags => ["snmp","interface"]
        add_field => { "[host][ip]" => "%{[@metadata][host_address]}"}
        interval => 60
    }

"""

list_ips = [
"8.8.8.8",
"9.9.9.9"

]

tmplt_snmp_walk = tmplt_snmp_walk_firewall
snmp_str = build_snmp_walk( list_ips , tmplt_snmp_walk)



