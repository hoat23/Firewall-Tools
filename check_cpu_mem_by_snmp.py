#!/usr/bin/env python
#coding: utf-8
#########################################################################################
# Developer: Deiner Zapata Silva.
# Date: 25/01/2019
# Description: Daemon to execute every time to check status of cpu and memory of a firewall using snmp.
# MIB: http://mibs.snmplabs.com/asn1/
#########################################################################################
#!/usr/bin/python3
from pysnmp.hlapi import *
from pysnmp.entity.rfc3413.oneliner import cmdgen

import datetime

host = '190.116.76.4'
community = 'prueba'
oid = "1.3.6.1.4.1.12356.101.4.1"
value=(1,3,6,1,4,1,12356,101,4,1)
# Hostname OID
system_name = '1.3.6.1.2.1.1.5.0'


# ONLY TEST WALK OID
"""oid_obj = ObjectIdentity(oid)
oid_type = ObjectType(oid_obj)
errorIndication, errorStatus, errorIndex, varBinds = next( getCmd(
    SnmpEngine()
))"""







# Interface OID
#1.3.6.1.4.1.12356.101.7.5.2.1.2
#1.3.6.1.4.1.12356.101.14.5.1.16
#1.3.6.1.4.1.12356.101.14.4.4.1.18
#1.3.6.1.4.1.12356.101.14.4.6.1.5
gig0_0_in_oct = "1.3.6.1.2.1.2.2.1.10.4" #"iso.org.dod.internet.private.enterprises.12356.101.14.4.6.1.5" #"iso.org.dod.internet.private.enterprises.12356.101.4.1.5.0"  #'1.3.6.1.2.1.2.2.1.10.1'
gig0_0_in_uPackets = oid #'1.3.6.1.2.1.2.2.1.11.1'
gig0_0_out_oct = oid #'1.3.6.1.2.1.2.2.1.16.1'
gig0_0_out_uPackets = oid #'1.3.6.1.2.1.2.2.1.17.1'
oid_walk = ".1.3.6.1.2.1.1.1.0"

cmdGen = cmdgen.CommandGenerator()

#  walk => ["1.3.6.1.2.1.1","1.3.6.1.4.1.12356.101.4.1","1.3.6.1.4.1.12356.101.13.2.1.1"]
def snmp_walk(community, host, oid):
    """Perform SNMP walk for submitted oid.
    Args:
        community(str):  SNMP community to read.
        host(str):  SNMP host.
        oid(str):  SNMP OID.
    Raises:
        CustomException
    """
    #from testlib.custom_exceptions import CustomException
    """error_indication, error_status, error_index, var_binds = cmdGen.nextCmd(
        cmdgen.CommunityData(community),
        cmdgen.UdpTransportTarget((host, 161)), 
        oid
    )"""

    print("snmp_walk --->")
    messages=""
    """
    # Check for errors and print out results
    if error_indication:
        print(error_indication) #raise CustomException(error_indication)
    else:
        if error_status:
            messages = ('%s at %s' % (
                error_status.prettyPrint(),  # pylint: disable=no-member
                error_index and var_binds[int(error_index) - 1] or '?'))
            print(messages) #raise CustomException(messages)
        else:
            if var_binds:
                messages ="test"
                #for name, val in var_binds[0]:
                #    messages = '%s = %s' % (name.prettyPrint(), val.prettyPrint())
            else:
                messages = 'Empty Replay'
    """
    return messages

def snmp_query(host, community, oid):
    errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
        cmdgen.CommunityData(community),
        cmdgen.UdpTransportTarget((host, 161)),
        oid
    )
    
    # Check for errors and print out results
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

result = {}
result['Time'] = datetime.datetime.utcnow().isoformat()
#result['hostname'] = 
#import time

#((positive(delta(IF_MIB.ifHCInOctets))/ duration(IF_MIB.ifHCInOctets)*800)/value (IF_MIB.ifHighSpeed))/10000
import time
oid_4 = "1.3.6.1.2.1.2.2.1.10.25"
delay = 5
for i in range(0,100):
    v1 = float(snmp_query(host, community, oid_4)) 
    time.sleep(delay)
    v2 = float(snmp_query(host, community, oid_4)) 
    dV = v2 - v1
    vel = (( dV * 8.0 ) / (delay) )/1024
    print("Vel :"+str(vel))

#time.sleep(1)

#snmp_walk(host,community, oid_walk)

"""
result['Gig0-0_In_Octet'] = snmp_query(host, community, gig0_0_in_oct)
result['Gig0-0_In_uPackets'] = snmp_query(host, community, gig0_0_in_uPackets)
result['Gig0-0_Out_Octet'] = snmp_query(host, community, gig0_0_out_oct)
result['Gig0-0_Out_uPackets'] = snmp_query(host, community, gig0_0_out_uPackets)
"""
print(str(result))
"""
with open('/results.txt', 'a') as f:
    f.write(str(result))
    f.write('\n')
"""

"""
import os, sys
import socket
import random
from struct import pack, unpack
from datetime import datetime as dt

from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.proto.rfc1902 import Integer, IpAddress, OctetString
import pysnmp

#ObjectIdentifier
#from pysnmp.hlapi import * 

obj_oid = ObjectIdentifier(oid)

se = SnmpEngine()
cv = CommunityData(community, mpModel=1)# 1 means version SNMP v2c
t1 = UdpTransportTarget( (ip,161) , timeout=1, retries=5)

g = nextCmd( SnmpEngine(), CommunityData(community,mpModel=1), UdpTransportTarget( (ip,161) ) , ContextData() , ObjectIdentifier(oid) )
"""

"""for (errorIndication,errorStatus,errorIndex,varBinds) in g:
        print(str(errorIndication))
        print(str(errorStatus))
        for varBind in varBinds:
            print(varBind)
"""


"""
generator = cmdgen.CommandGenerator()
comm_data = cmdgen.CommunityData('logstash', mpModel=1) # 1 means version SNMP v2c
transport = cmdgen.UdpTransportTarget((ip, 161), timeout=1, retries=5)
value = cmdgen.ObjectIdentifier(oid)

real_fun = getattr(generator, 'nextCmd')
res = (errorIndication, errorStatus, errorIndex, varBinds) = real_fun(comm_data, transport, value)

if not errorIndication is None  or errorStatus is True:
       print("Error: %s %s %s %s" % res)
else:
       print("%s" % varBinds)

host=ip
"""


"""
def walk(host, oid):
        for (errorIndication,errorStatus,errorIndex,varBinds) in nextCmd( SnmpEngine(),CommunityData('logstash'), UdpTransportTarget((host, 161)), ContextData(), ObjectType(ObjectIdentity(oid)) ):
            if errorIndication:
                print(errorIndication, file=sys.stderr)
                break
            elif errorStatus:
                print('%s at %s' % (errorStatus.prettyPrint(),
                                    errorIndex and varBinds[int(errorIndex) - 1][0] or '?'), 
                                    file=sys.stderr)             
                break
            else:
                for varBind in varBinds:
                    print(varBind)

walk(ip,oid)
"""
