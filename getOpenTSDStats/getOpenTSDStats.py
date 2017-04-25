#from vspk.vsdk import v3_0 as vsdk
try:
    from vspk import v3_2 as vsdk
except ImportError:
    from vspk.vsdk import v3_2 as vsdk

import config
import opentsdb_pandas as opd
from influxdb import DataFrameClient
import numpy as np

import bambou
import requests
import csv
import sys, getopt
import os.path
import traceback
import re
import time
from datetime import datetime, timedelta
#import pandas as pd
from collections import namedtuple
import operator
from operator import itemgetter, attrgetter, methodcaller
from Queue import Queue
from threading import Thread

requests.packages.urllib3.disable_warnings()


SCRIPT_VERSION = '0.1'
DEBUG = False
TIME = False
THREADS = 4

PROCESSED_ITEMS = 0

#Nuage   VSD
LOGIN_USER = "csproot"
LOGIN_PASS = "csproot"
LOGIN_ENTERPRISE = "csp"
LOGIN_API_URL = "https://vsd1:8443" # VNS
LOGIN_API_VERSION = "3_2"



#Threads
class Worker(Thread):
    """Thread executing tasks from a given tasks queue"""
    def __init__(self, tasks):
        Thread.__init__(self)
        self.tasks = tasks
        self.daemon = True
        self.start()

    def run(self):
        while True:
            func, args, kargs = self.tasks.get()
            try:
                func(*args, **kargs)
            except Exception, e:
                print e
            finally:
                self.tasks.task_done()

class ThreadPool:
    """Pool of threads consuming tasks from a queue"""
    def __init__(self, num_threads):
        self.tasks = Queue(num_threads)
        for _ in range(num_threads): Worker(self.tasks)

    def add_task(self, func, *args, **kargs):
        """Add a task to the queue"""
        self.tasks.put((func, args, kargs))

    def wait_completion(self):
        """Wait for completion of all the tasks in the queue"""
        self.tasks.join()


#Global List of VSD object - CACHE
_EnterpriseList = {}

_L2Domain = namedtuple("L2Domain", ["enterpriseId","domain"])
_L2DomainList = {}

_Domain = namedtuple("Domain", ["enterpriseId","domain"])
_DomainList = {}

_Zone = namedtuple("Zone", ["domainId","zone"])
_ZoneList = {}

_Subnet = namedtuple("Subnet", ["zoneId","subnet"])
_SubnetList = {}



def createVsdkSession():
    #Connect to VSD
    session = None
    if 'version' in vsdk.NUVSDSession.__init__.__code__.co_varnames:
        #If older SDK
        session = vsdk.NUVSDSession(username=LOGIN_USER,
                                    password=LOGIN_PASS,
                                    enterprise=LOGIN_ENTERPRISE,
                                    api_url=LOGIN_API_URL,
                                    version=LOGIN_API_VERSION)
    else:
        session = vsdk.NUVSDSession(username=LOGIN_USER,
                                    password=LOGIN_PASS,
                                    enterprise=LOGIN_ENTERPRISE,
                                    api_url=LOGIN_API_URL)
    session.start()
    return session

def getEnterpriseObject(name, session=None):
    global _EnterpriseList
    if session is None:
        return None, "VSD session not available"

    if name is not None or name != '':
        enterprise = None
        if name in _EnterpriseList.keys():
            enterprise = _EnterpriseList[name]
            return enterprise, "Enterprise catched object"
        else:
            enterprise = session.user.enterprises.get_first(
                filter=("name == '%s'" % name))

            if enterprise is not None:
                try:
                    enterprise.fetch()
                    _EnterpriseList[name] = enterprise
                    return enterprise, "Enterprise fetched, Enterprise=%s, Id=%s" % (enterprise.name, enterprise.id)
                except:
                    return None,"Enterprise not found"

    return None,"Enterprise not found"

#L3 Domain
def getL3DomainObject(enterpriseObject, domainName):
    global _DomainList
    if enterpriseObject is None:
        return None, "Enterprise not available"

    if domainName is not None or domainName != '':
        domain = None
        if (enterpriseObject.id, domainName) in _DomainList.keys():
            domain = _DomainList[(enterpriseObject.id, domainName)]
            return domain, "Domain cached object"
        else:
            domain = enterpriseObject.domains.get_first(filter=("name == '%s'" % domainName) )
            if domain is not None:
                try:
                    domain.fetch()
                    _DomainList[_Domain(enterpriseObject.id, domainName)] = domain
                    return domain, "L3 Domain fetched, L3 Domain=%s, Id=%s" % (domain.name, domain.id)
                except:
                    return None,"L3 Domain not found"

    return None,"L3 Domain not found"

#Zone
def getL3ZoneObject(domainObject, zoneName):
    global _ZoneList
    if domainObject is None:
        return None, "Domain not available"

    if zoneName is not None or zoneName != '':
        zone = None
        if (domainObject.id, zoneName) in _ZoneList.keys():
            zone = _ZoneList[(domainObject.id, zoneName)]
            return zone, "Zone cached object"
        else:
            zone = domainObject.zones.get_first(filter=("name == '%s'" % zoneName) )
            if zone is not None:
                try:
                    zone.fetch()
                    _ZoneList[_Zone(domainObject.id, zoneName)] = zone
                    return zone, "Zone fetched, Zone=%s, Id=%s" % (zone.name, zone.id)
                except:
                    return None,"Zone not found"

    return None,"Zone not found"

#Subnet
def getL3SubnetObject(zoneObject, subnetName):
    global _SubnetList

    if zoneObject is None:
        return None, "Zone not available"

    if subnetName is not None or subnetName != '':
        subnet = None
        if (zoneObject.id, subnetName) in _SubnetList.keys():
            subnet = _SubnetList[(zoneObject.id, subnetName)]
            return subnet, "Subnet cached object"
        else:
            subnet = zoneObject.subnets.get_first(filter=("name == '%s'" % subnetName) )
            if subnet is not None:
                try:
                    subnet.fetch()
                    _SubnetList[_Subnet(zoneObject.id, subnetName)] = subnet
                    return subnet, "Subnet fetched, Subnet=%s, Id=%s" % (subnet.name, subnet.id)
                except:
                    return None,"Subnet not found"

    return None,"Subnet not found"

#Gateway
def getGatewayObject(gatewayName, session=None):
    global _GatewayList

    if session is None:
        return None, "VSD connection is not available"

    if gatewayName is not None or gatewayName != '':
        gateway = None
        if gatewayName in _GatewayList.keys():
            gateway = _GatewayList[gatewayName]
            return gateway, "Gateway cached object"
        else:
            #Get VSG
            try:
                gateway = session.user.gateways.get_first(filter=("name == '%s'" % gatewayName) )
                gateway.fetch()
                _GatewayList[gatewayName] = gateway
                return gateway, "Gateway fetched, Gateway=%s, Id=%s" % (gateway.name, gateway.id)
            except:
                gateway = None

            if gateway is None and hasattr(session.user,'redundancy_groups'):
                #Get Redundant VSG
                try:
                    gateway = session.user.redundancy_groups.get_first(filter=("name == '%s'" % gatewayName))
                    gateway.fetch()
                    _GatewayList[gatewayName] = gateway
                    return gateway, "Gateway fetched, Gateway=%s, Id=%s" % (gateway.name, gateway.id)
                except:
                    return None,"Gateway not found"

    return None,"Gateway not found"

#Port
def getGatewayPortObject(gatewayObject, portPhysicalName):
    global _PortList

    if gatewayObject is None:
        return None, "Gateway is not available"

    if portPhysicalName is not None or portPhysicalName != '':
        port = None
        if (gatewayObject.id, portPhysicalName) in _PortList.keys():
            port = _PortList[(gatewayObject.id, portPhysicalName)]
            return port, "Port cached object"
        else:
            #Get VSG Port
            try:
                port = gatewayObject.ports.get_first(filter=("physicalName == '%s'" % portPhysicalName) )
                port.fetch()
                _PortList[_Port(gatewayObject.id, portPhysicalName)] = port
                return port, "Port fetched, Port=%s, Id=%s" % (port.name, port.id)
            except:
                port = None

            #Redundant VSG Ports
            if port is None and hasattr(gatewayObject,'vsg_redundant_ports'):
                try:
                    port = gatewayObject.vsg_redundant_ports.get_first(filter=("physicalName == '%s'" % portPhysicalName))
                    port.fetch()
                    return port, "Port fetched, Port=%s, Id=%s" % (port.name, port.id)
                except:
                    return None,"Port not found"

    return None,"Port not found"

#Vlan
def getGatewayPortVlanObject(portObject, vlanValue):
    global _VlanList

    if portObject is None:
        return None, "Gateway is not available"

    if vlanValue is not None or vlanValue != '':
        vlan = None
        if (portObject.id, vlanValue) in _VlanList.keys():
            vlan = _VlanList[(portObject.id, vlanValue)]
            return vlan, "Vlan cached object"
        else:
            vlan = portObject.vlans.get_first(filter=("value == %s" % vlanValue) )
            if vlan is not None:
                try:
                    vlan.fetch()
                    _VlanList[_Vlan(portObject.id, vlanValue)] = vlan
                    return vlan, "Vlan fetched, Vlan=%s, Id=%s" % (vlanValue, vlan.id)
                except:
                    return None,"Vlan not found"

    return None,"Vlan not found"

#Vport
def getL3VportObject(subnetObject, vPortName):
    if subnetObject is None:
        return None, "Subnet not available"

    if vPortName is not None or vPortName != '':
        vport = None
        vport = subnetObject.vports.get_first(filter=("name == '%s'" % vPortName) )
        if vport is not None:
            try:
                vport.fetch()
                return vport, "Vport fetched, Vport=%s, Id=%s" % (vport.name, vport.id)
            except:
                return None,"Vport not found"

    return None,"Vport not found"















def gatherVsdSubnets(session):
    subnetList = []

    if session is None:
        return None, "VSD session not available"

    #Get All Enterprises:
    enterprises = session.user.enterprises.get()

    if enterprises and len(enterprises)>0:
        for enterprise in enterprises:
            domains = enterprise.domains.get()

            if domains and len(domains)>0:
                for domain in domains:
                    zones = domain.zones.get()

                    if zones and len(zones)>0:
                        for zone in zones:
                            subnets = zone.subnets.get()

                            if subnets and len(subnets)>0:
                                for subnet in subnets:
                                    enterprise_name = enterprise.name
                                    domain_name = domain.name
                                    zone_name = zone.name
                                    subnet_name = subnet.name

                                    subnetList.append({ 'enterprise' : enterprise_name, 'domain': domain_name, 'zone': zone_name, 'subnet': subnet_name, 'subnet_id': subnet.id })

    return subnetList, ""





def custom_resampler(array_like):
    print 'Array Like: %s' % (array_like)
    return np.sum(array_like) + 0


def gatherOpenTsdSubnetStats(openTsdHost, subnetItem, startTime, endTime, fields):
    statList = []

    if fields is None or len(fields)==0:
        return None, "No fields provided"

    for field in fields:
        try:
            print 'Subnet ID: %s' % (subnetItem['subnet_id'])
            data = opd.ts_get(field, startTime, endTime, 'subnetId=%s' % (subnetItem['subnet_id']), hostname=openTsdHost)
        except :
            data = None
            pass

        if data is not None:
            #print list(data)

            if data.empty:
                pass
            else:
                #Convert to DataFrame
                df = data.to_frame(name=field)

                #Generate Time Delta
                df['time'] = df.index
                df['delta'] = ((df['time'] - df['time'].shift()).fillna(60))
                df['deltas'] = df['delta'].apply(lambda x: int( x.total_seconds() ) )
                df['bits'] = df[field].apply(lambda x: x*8)
                df['bps'] = df.apply(lambda row: (int(row['bits'] * 1.0 / row['deltas']) if row['deltas'] >0 else 0), axis=1)

                print "Panda: df.ix=%s\n field:%s\n\n" %  (df.ix[:,'bps':'bps'], field)

    return statList, ""


def exportToInfluxDB(serie, subnetItem, field):
    if config is None or config.InfluxDB is None:
        return None, "No InfluxDB config"

    try:
        client = DataFrameClient(config.InfluxDB['host'], config.InfluxDB['port'], config.InfluxDB['username'], config.InfluxDB['password'], config.InfluxDB['dbname'])

        client.write_points(serie,field, tags = {'enterprise': subnetItem['enterprise'], 'domain': subnetItem['domain'], 'zone': subnetItem['zone'], 'subnet':subnetItem['subnet']})

    except Exception, e:
        return e





def processOpenTsdData():
    global PROCESSED_ITEMS
    session = createVsdkSession()

    endTime =datetime.now()
    startTime = endTime + timedelta(hours=-1)

    openTsdHost = config.OpenTSD['host']
    fields = config.OpenTSD['fields']

    print 'Fields: %s' % (fields)

    if session is None:
        return None, "VSD session not available"


    #Get all Subnets
    (subnetList, error) = gatherVsdSubnets(session)

    print 'Subnet List:'
    print '%s' % (subnetList)

    if subnetList and len(subnetList)>0:
        for subnetItem in subnetList:
            print 'Subnet: %s' % (subnetItem['subnet'])
            (statList, error) = gatherOpenTsdSubnetStats(openTsdHost, subnetItem, startTime, endTime, fields)

            if statList is None:
                print 'ERROR: %s' % error

            if statList and len(statList)>0:
                for statItem in statList:
                    print list(statItem)



def printVersion(args):
    helpString  = "\n"
    helpString += " Script version %s\n" % SCRIPT_VERSION

    return helpString

def printHelp(argvs):
    helpString  = "\n"
    helpString += " SYNOPSIS\n"
    helpString += "    %s [OPTIONS]\n" % argvs[0]
    helpString += "\n"
    helpString += " DESCRIPTION\n"
    helpString += "    This script will collect subnet Stats from OpenSTD,\n"
    helpString += "    and push it to a InfluxDB\n"
    helpString += "\n"
    helpString += " OPTIONS\n"
    helpString += "    -h, --help      Print this help\n"
    helpString += "    -v, --version   Print this version\n"    
    helpString += "    --debug         Error output\n"
    helpString += "    -t, --time      Time <processing></processing>\n"
    helpString += "\n"
    helpString += " EXAMPLES\n"    
    helpString += "    To import from a CSV file:\n"
    helpString += "    %s -i create_l3_domain.csv\n" % argvs[0]
    helpString += "\n"

    return helpString

def main(argvs):
    global DEBUG, TIME, csvErrorWriter

    argv = argvs[1:]

    try:
        opts, args = getopt.getopt(argv,"htvi:o:g:",["time","help","debug","input=","output=","group="])
    except getopt.GetoptError:
        print printHelp(argvs)
        sys.exit(2)


    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print printHelp(argvs)
            sys.exit()
        elif opt in ("-v", "--version"):
            print printVersion(argvs)
            sys.exit()
        elif opt in ('-t','--time'):
            TIME = True
        elif opt in ("--debug"):
            DEBUG = True
        elif opt in ("-i", "--input"):
            inputfile = arg
        elif opt in ("-o", "--output"):
            outputfile = arg
        elif opt in ("-g","--group"):
            groups = arg

    if len(args) > 0:
        if inputfile == '':
            inputfile = args[0]

    print "Debug: %s" % DEBUG


    #Create VSD Session 
    session=createVsdkSession()

    if session is None:
        print "Cannot connect to VSD"
    else:
        #Process OpenTSD Data
        processOpenTsdData()

if __name__ == "__main__":
    startTime = time.time()
    main(sys.argv)
    endTime = time.time()

    if TIME:
        duration = endTime - startTime
        print 'Start: %s     End: %s\nDuration: %s' % (
                time.strftime("%H:%M:%S", time.localtime(startTime)),
                time.strftime("%H:%M:%S", time.localtime(endTime)),
                datetime.timedelta(seconds=duration) )
        print 'Processed Items: %s' % PROCESSED_ITEMS
