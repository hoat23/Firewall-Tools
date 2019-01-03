#!/usr/bin/env python
# coding: utf-8 
# Developer: Deiner Zapata Silva.
# Date: 31/12/2018
# Description: Server to conect to FireWall using API
# Code Base: https://github.com/sheltont/fortiapi/blob/master/fgt.py
#########################################################################################
import logging,sys,time
from pprint import pprint
import requests
import sys, json, socket, argparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
###############################################################################
def send_json(msg, IP="0.0.0.0", PORT = 2233):
    """
        #Configuracion en /etc/logstash/conf.d/logstash-syslog.conf
        input{
            tcp{
                port => [PORT_NUMBER]
                codec => json
            }
        }
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect( (IP,PORT) )
        #print "sending message: "+str(msg)
        datajs = json.dumps(msg)
        sock.sendall( datajs.encode() )
    except:
        print("Error inesperado: "+sys.exc_info()[0])
        #sys.exit(1)
        return
    finally:
        sock.close()
        return
###############################################################################
def fileTXT_save(text, nameFile = "backupForti.txt"):
    fnew  = open(nameFile,"wb")
    fnew.write(text.encode('utf-8')) # str(aux=[line])+'\n'
    fnew.close() 
    return
###############################################################################
class AuthenticationError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)
###############################################################################
class BadResponse(Exception):
    def __init__(self, value, body=''):
        self.value = value
        self.body = body

    def get_body(self):
        return self.body

    def __str__(self):
        return repr(self.value)
###############################################################################
# API class to access FOS REST API
class FGT(object):
    """
    Base class to provide access to FGT APIs:
        . Monitor API
        . CMDB API
    Script will start a session by login into the FGT
    All subsequent calls will use the session's cookies and CSRF token
    """
    def __init__(self, url_prefix, vdom, verbose=False):#H23
        self.url_prefix = url_prefix
        self.session = requests.session()  # use single session for all requests
        self.vdom = vdom
        self.logger = logging.getLogger('FGT')
        ch = logging.StreamHandler(sys.stderr)
        ch.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(ch)
        if verbose:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.ERROR)

    def update_csrf(self):
        # Retrieve server csrf and update session's headers
        for cookie in self.session.cookies:
            if cookie.name == 'ccsrftoken':
                csrftoken = cookie.value[1:-1] # token stored as a list
                self.session.headers.update({'X-CSRFTOKEN': csrftoken})

    def login(self, name, key):
        url = self.url_prefix + '/logincheck'
        res = self.session.post(url,
                                data='username=' + name + '&secretkey=' + key,
                                verify=False)
        
        if res.status_code != 200 or res.text.find('error') != -1:
            # Found some error in the response, consider login failed
            raise AuthenticationError('Authentication error [' + str(url) + "]")

        # Update session's csrftoken
        self.update_csrf()

    def logout(self):
        url = self.url_prefix + '/logout'
        res = self.session.post(url)

    def get(self, url_postfix, params=None, data=None, verbose=True, get_text=False):
        url = self.url_prefix + url_postfix
        res = self.session.get(url, params=self.append_vdom_params(params), data=data)
        self.update_csrf()  # update session's csrf
        return self.check_response(res, verbose, get_text)

    def post(self, url_postfix, params=None, data=None, verbose=True):
        url = self.url_prefix + url_postfix
        res = self.session.post(url, params=self.append_vdom_params(params), data=data)
        self.update_csrf() # update session's csrf
        return self.check_response(res, verbose)

    def put(self, url_postfix, params=None, data=None, verbose=True):
        url = self.url_prefix + url_postfix
        res = self.session.put(url, params=self.append_vdom_params(params), data=data)
        self.update_csrf() # update session's csrf
        return self.check_response(res, verbose)

    def delete(self, url_postfix, params=None, data=None, verbose=True):
        url = self.url_prefix + url_postfix
        res = self.session.delete(url, params=self.append_vdom_params(params), data=data)
        self.update_csrf()  # update session's csrf
        return self.check_response(res, verbose)

    def get_v1(self, url_postfix, params=None, data=None, verbose=True):
        url = self.url_prefix + url_postfix
        # Pass 'request' or 'json' data as parameters for V1
        payload = self.append_vdom_params(params)
        if params:
            if 'request' in params:
                payload = 'request' + '=' + params['request']
            elif 'json' in params:
                payload = 'json' + '=' + params['json']

        # Send request
        res = self.session.get(url, params=payload, data=data)
        self.update_csrf()  # update session's csrf
        return self.check_response(res, verbose)

    def post_v1(self, url_postfix, params=None, data=None, verbose=True):
        url = self.url_prefix + url_postfix
        # Pass 'request' or 'json' data as parameters for V1
        payload = self.append_vdom_params(params)
        if params:
            if 'request' in params:
                payload = 'request' + '=' + params['request']
            elif 'json' in params:
                payload = 'json' + '=' + params['json']

        # Send request
        res = self.session.post(url, params=payload, data=data)
        self.update_csrf()  # update session's csrf
        return self.check_response(res, verbose)

    def put_v1(self, url_postfix, params=None, data=None, verbose=True):
        url = self.url_prefix + url_postfix
        # Pass 'request' or 'json' data as parameters for V1
        payload = self.append_vdom_params(params)
        if params:
            if 'request' in params:
                payload = 'request' + '=' + params['request']
            elif 'json' in params:
                payload = 'json' + '=' + params['json']

        # Send request
        res = self.session.put(url, params=payload, data=data)
        self.update_csrf()  # update session's csrf
        return self.check_response(res, verbose)

    def delete_v1(self, url_postfix, params=None, data=None, verbose=True):
        url = self.url_prefix + url_postfix
        # Pass 'request' or 'json' data as parameters for V1
        payload = self.append_vdom_params(params)
        if params:
            if 'request' in params:
                payload = 'request' + '=' + params['request']
            elif 'json' in params:
                payload = 'json' + '=' + params['json']

        # Send request
        res = self.session.delete(url, params=payload, data=data)
        self.update_csrf()  # update session's csrf
        return self.check_response(res, verbose)

    def append_vdom_params(self, params):
        if params and type(params) is dict:
            if not ('vdom' in params):
                params['vdom'] = self.vdom
        return params

    def check_response(self, response, verbose=True, get_text=False):

        self.logger.debug('{0} {1}'.format(response.request.method, response.request.url))

        # Check response status, content and compare with original request
        if response.status_code == 200:
            if (get_text):#Set True if want to download file - H23
                return response.text
            # Success code, now check json response
            try:
                # Retrieve json data
                res = response.json()
            except:
                error = 'Invalid JSON response'
                self.logger.error(error)
                self.logger.info(response.text) #H23
                raise BadResponse(error, response.text)
            else:
                # Check if json data is empty
                if not res:
                    error = 'JSON data is emtpy'
                    self.logger.error(error)
                    raise BadResponse(error)

                # Check status
                if 'status' in res:
                    if res['status'] != 'success':
                        self.logger.error('JSON error {0}\n{1}'.format(res['error'], res))
                        raise BadResponse('Error response', res.text)

                # Check http_status if any
                if 'http_status' in res:
                    if res['http_status'] != 200:
                        self.logger.error('JSON error {0}\n{1}'.format(res['error'], res))
                        raise BadResponse('Error http_status', res.text)

                # Check http method
                if 'http_method' in res:
                    if res['http_method'] != response.request.method:
                        self.logger.error('Incorrect METHOD request {0},\
                                  response {1}'.format(response.request.method,
                                                       res['http_method']))
                        raise BadResponse('Unmatched http_method', res.text)

                # Check results
                if 'results' in res:
                    if not res['results']:
                        self.logger.error('Results is empty')
                        raise BadResponse('Results is empty', res.text)

                # Check vdom

                # Check path

                # Check name

                # Check action
                return res
        else:
            try:
                # Retrieve json data
                response.json()
            except:
                pass
                self.logger.error('Fail with status: {0}'.format(response.status_code))
            else:
                pass
                self.logger.error('Fail with status: {0}'.format(response.status_code))
            finally:
                self.logger.error(response.text)
                return False
###############################################################################
def testmain():
    urlprefix = 'https://8.8.8.8:9443'
    username = 'user'
    password = 'pass'
    vdom = 'root'

    fgt = FGT(urlprefix,vdom)  #FGT(urlprefix,vdom) #vdom=None
    fgt.login(username, password)
    
    #Download backup forti
    res = fgt.get('/api/v2/monitor/system/config/backup?scope=global',get_text=True)
    fileTXT_save(res, nameFile = "backupForti.conf")

    #
    res = fgt.get('/api/v2/monitor/router/ipv4/select/')#https://161.132.109.162:9443/api/v2/monitor/router/ipv4/select/
    pprint(res)

    # Example of CMDB API requests
    #res = fgt.get('/api/v2/cmdb/system/interface')
    #pprint(res)
    #res = fgt.get('/api/v2/cmdb/firewall/policy')
    #headers = 'Content-Disposition': attachment
    #res = fgt.get('/api/v2/cmdb/vpn.certificate/ca')
    #res = fgt.get('/')
    #res = fgt.get('/api/v2/monitor/system/config/backup?mkey=Fortinet_Factory&type=local&scope=global')
    #res = fgt.get('/api/v2/monitor/system/config/download?mkey=Fortinet_Factory&type=local&scope=global')
    #pprint(res)
    """
    # Uncomment below to run other sample requests
    res = fgt.get('/api/v2/cmdb/firewall/address', params={"action":"schema", "vdom":vdom})
    pprint(res)

    res = fgt.get('/api/v2/cmdb/firewall/address', params={"action":"default", "vdom":vdom})
    pprint(res)

    res=fgt.get('/api/v2/cmdb/firewall/address', params={"vdom":vdom})
    pprint(res)

    res=fgt.post('/api/v2/cmdb/firewall/address', params={"vdom":vdom},
                                              data={"json":{"name":"attacker1",
                                                            "subnet":"1.1.1.1 255.255.255.255"}},
                                              verbose=True)
    pprint(res)
    """
    """
    fgt.post('/api/v2/cmdb/firewall.service/custom', params={"vdom":vdom},
                                                     data={"json":{"name":"server1_port",
                                                                   "tcp-portrange":80}},
                                                     verbose=True)
    fgt.put('/api/v2/cmdb/firewall/address/address1', params={"vdom":vdom},
                                              data={"json":{"name":"address2"}})
    fgt.post('/api/v2/cmdb/firewall/policy', params={"vdom":vdom},
                                             data={"json":{"policyid":0,
                                                           "srcintf":[{"name":"lan"}],
                                                           "srcaddr":[{"name":"all"}],
                                                           "dstintf":[{"name":"wan1"}],
                                                           "dstaddr":[{"name":"all"}],
                                                           "service":[{"name":"ALL"}],
                                                           "schedule":"always",
                                                           "action":"accept"}})
    fgt.put('/api/v2/cmdb/firewall/policy/1', params={"vdom":vdom,"action":"move", "after":2})
    fgt.delete('/api/v2/cmdb/firewall/address/address2', params={"vdom":vdom})
    fgt.delete('/api/v2/cmdb/firewall/address', params={"vdom":vdom})
    """

    # Example of Monitor API requests
    # Uncomment below to run other sample requests
    """
    fgt.get('/api/v2/monitor')
    fgt.get('/api/v2/monitor/firewall/policy', params={"vdom":vdom})
    fgt.post('/api/v2/monitor/firewall/policy/clear_counters', params={"vdom":vdom, "policy":"[4,7]"})
    fgt.get('/api/v2/monitor/firewall/session-top', params={"report_by":"source",
                                                            "sort_by":"bytes",
                                                            "vdom":vdom})
    fgt.get('/api/v2/monitor/firewall/session', params={"vdom":vdom,
                                                        "ip_version":"ipboth",
                                                        "start":0,
                                                        "count":1,
                                                        "summary":True})
    """
    # Always logout after testing is done
    fgt.logout()
###############################################################################
def receive_parameters_from_bash():
    #global ip , port , user , passw , command , ip_logstash , port_logstash
    parser = argparse.ArgumentParser()
    parser.add_argument("-i","--ip",help="ip of host")
    parser.add_argument("-pp","--port",help="Port of host")
    parser.add_argument("-u","--user",help="Usuario SSH")
    parser.add_argument("-p","--password",help="Password SSH")
    parser.add_argument("-c","--command",help="URL of API res")
    parser.add_argument("-ip_out","--ip_out",help="IP of logstash")
    parser.add_argument("-pp_out","--pp_out",help="Port of logstash")

    args = parser.parse_args()

    if args.ip: ip = str(args.ip)
    if args.port: port = int(args.port)
    if args.user: user = str(args.user)
    if args.password: passw = str(args.password)
    if args.command: command = str(args.command)
    if args.ip_out: ip_logstash = str(args.ip_out)
    if args.pp_out: port_logstash = int(args.pp_out)

    if( ip==None or port==None or user==None or passw==None):
        print("\nERROR: Faltan parametros.")
        print("ip\t= ["+str(ip)+"] \nport\t= ["+str(port)+"] \nuser\t= ["+str(user)+"] \n"+"passw\t= ["+str(passw)+"]")
        sys.exit(0)
    
    if( ip_logstash==None or port_logstash==None):
        print("\nERROR: Faltan parametros.")
        print("ip_out\t= ["+str(ip_logstash)+"]\npp_out\t= ["+str(port_logstash)+"]")
        sys.exit(0)

    vdom = 'root'
    urlprefix = 'https://' + str(ip) + ":" + str(port)
    
    fgt = FGT(urlprefix,vdom)  #FGT(urlprefix,vdom) #vdom=None
    fgt.login(user, passw)
    
    #Download of backup
    if(command=='/api/v2/monitor/system/config/backup?scope=global'):
        res = fgt.get(command,get_text=True)
        #fileTXT_save(res, nameFile = "backupForti.txt")
        #Send backup file to logstash
        send_json( {'url_api': command ,'backup_file':res, 'host': ip } , IP=ip_logstash, PORT=port_logstash)
    else:
        res = fgt.get(command) # /api/v2/monitor/router/ipv4/select/
        #pprint(res)
        #Send data to logstash
        res.update({'url_api': command , "host": ip })
        send_json( res , IP=ip_logstash, PORT=port_logstash)
    fgt.logout()

if __name__ == '__main__':
    #testmain()
    receive_parameters_from_bash()
"""
DATOS A DESCARGAR DEL FIREWALL
firewall/session/select/ GET List all active firewall sessions (optionally filtered).
firewall/shaper/select/ GET List of statistics for configured firewall shapers.
license/status/select/ GET Get current license and registration status.
system/resource/usage/ GET Retreive current and historical usage data for a provided
resource.
"""
