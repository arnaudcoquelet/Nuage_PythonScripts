try:
    from vspk import v3_2 as vsdk
except ImportError:
    from vspk.vsdk import v3_2 as vsdk

import re
import datetime
import time
import sys, getopt
import os.path
import jtextfsm as textfsm
import sys
import logging




SCRIPT_VERSION = '0.1'
DEBUG = False
TIME = False
THREADS = 4

PROCESSED_ITEMS = 0

#Nuage VSD
LOGIN_USER = "csproot"
LOGIN_PASS = "csproot"
LOGIN_ENTERPRISE = "csp"
LOGIN_API_URL = "https://vsd1:8443"
LOGIN_API_VERSION = "3_2"



############################################################################################################
#  LOGGER
#
############################################################################################################
logger = logging.getLogger('getServiceDetails')
logger.setLevel(logging.INFO)

# create file handler which logs even debug messages
fh = logging.FileHandler('debug.log')
fh.setLevel(logging.DEBUG)
# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
# create formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
formatter = logging.Formatter('%(asctime)s - %(message)s')
ch.setFormatter(formatter)
# add the handlers to the logger
logger.addHandler(fh)
logger.addHandler(ch)

############################################################################################################


def compareText(name, filter):
    if re.search(filter.lower(), name.lower() ) is None:
        return False
    else:
        return True

    return False



############################################################################################################
#  VSD Functions
# 
############################################################################################################

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

    logger.debug("Connected to VSD")
    
    return session

def getL3DomainRoutingInfo(domainId):
    if domainId is None:
        print_warning('Error - Domain not found with ID=%s' % (domainId) )
        return None

    try:
        domain = vsdk.NUDomain(id=domainId)
        domain.fetch()

        backhaulRD = domain.back_haul_route_distinguisher
        backhaulRT = domain.back_haul_route_target
        backhaulVNID = domain.back_haul_vnid
        domainRD = domain.route_distinguisher
        domainRT = domain.route_target
        serviceID = domain.service_id

        return (serviceID, backhaulVNID, backhaulRD, backhaulRT)
    except Exception, e:
        return None

def getL3SubnetRoutingInfo(subnetId):
    if subnetId is None:
        print_warning('Error - Subnet not found with ID=%s' % (subnetId) )
        return None

    try:
        subnet = vsdk.NUSubnet(id=subnetId)
        subnet.fetch()

        vnID = subnet.vn_id
        domainRD = subnet.route_distinguisher
        domainRT = subnet.route_target
        serviceID = subnet.service_id

        return (serviceID, vnID, domainRD, domainRT)
    except Exception, e:
        return None

def getL2DomainRoutingInfo(domainId):
    if domainId is None:
        print_warning('Error - L2 Domain not found with ID=%s' % (domainId) )
        return None

    try:
        domain = vsdk.NUL2Domain(id=domainId)
        domain.fetch()

        VNID = domain.vn_id
        domainRD = domain.route_distinguisher
        domainRT = domain.route_target
        serviceID = domain.service_id

        return (serviceID, VNID, domainRD, domainRT)
    except Exception, e:
        return None

def getVSDRoutingInformation(enterpriseFilter, domainFilter):
    vsdRoutingList = []

    #Connect to VSD
    session = createVsdkSession()
    if session is None:
        print_warning('Error - Cannot connect to VSD')
        return None

    #Get All Enterprises
    enterprises = session.user.enterprises.get()

    if enterprises is None:
            print_info('No Enterprise found')
            next

    #Audit each Enterprise
    for enterprise in enterprises:
        enterpriseName = enterprise.name

        if compareText(enterpriseName, enterpriseFilter):
            #Get L3 Domains
            domains = enterprise.domains.get()
            if domains is None:
                print_info('%s - No domain found' % enterpriseName)
                next

            for domain in domains:
                domainId = domain.id
                domainName = domain.name

                if compareText(domainName, domainFilter):
                    #Get L3 Domain routing Info (Backhaul)
                    routingInfo = getL3DomainRoutingInfo(domainId)
                    if routingInfo is not None:
                        (serviceID, VNID, domainRD, domainRT) = routingInfo
                        domainType = "L3"
                        subnetName="L3 Domain"
                        vsdRoutingList.append((enterpriseName,domainName,domainType,subnetName, serviceID, VNID, domainRD, domainRT) )

                    #Get All Subnet Routing Info
                    subnets = domain.subnets.get()
                    for subnet in subnets:
                        subnetId = subnet.id
                        subnetName = subnet.name
                        subnetRoutingInfo = getL3SubnetRoutingInfo(subnetId)

                        if routingInfo:
                            (serviceID, VNID, domainRD, domainRT) = subnetRoutingInfo
                            vsdRoutingList.append((enterpriseName,domainName,domainType,subnetName, serviceID, VNID, domainRD, domainRT) )

            #Get L2 Domains
            l2domains = enterprise.l2_domains.get()
            if l2domains is None:
                print_info('%s - No L2 Domain found' % enterpriseName)
                next

            for l2domain in l2domains:
                domainId = l2domain.id
                domainName = l2domain.name

                if compareText(domainName, domainFilter):
                    routingInfo = getL2DomainRoutingInfo(domainId)
                    if routingInfo is not None:
                        (serviceID, VNID, domainRD, domainRT) = routingInfo
                        domainType = "L2"
                        subnetName="L2 Domain"
                        vsdRoutingList.append((enterpriseName,domainName,domainType,subnetName, serviceID, VNID, domainRD, domainRT) )

    return vsdRoutingList



def printVersion(args):
    helpString  = "\n"
    helpString += " Script version %s\n" % SCRIPT_VERSION

    return helpString


def printHelp(argvs):
    helpString = "\n"
    helpString += " SYNOPSIS\n"
    helpString += "    %s [OPTIONS]\n" % argvs[0]
    helpString += "\n"
    helpString += " DESCRIPTION\n"
    helpString += "    This script will export the Domains info related to routing"
    helpString += "\n"
    helpString += " OPTIONS\n"
    helpString += "    -h, --help         Print this help\n"
    helpString += "    -v, --version      Print this version\n"
    helpString += "    -o, --output       Output the result to a csv file\n"
    helpString += "    -e, --enterprise   Filter on Enterprise name\n"
    helpString += "    -d, --domain       Filter on Domain name\n"
    helpString += "\n"

    return helpString


def main(argvs):
    global TIME,PROCESSED_ITEMS,csvWriter

    argv = argvs[1:]

    outputfile = 'domain_routing.csv'
    enterprisefilter = ''
    domainfilter = ''
    try:
        opts, args = getopt.getopt(
            argv, "hvo:e:d:", ["help","version","output=", "enterprise", "domain"])
    except getopt.GetoptError:
        print_info(printHelp(argvs))
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print_info(printHelp(argvs))
            sys.exit()
        elif opt in ("-v", "--version"):
            print_info(printVersion(argvs))
            sys.exit()
        elif opt in ("-o", "--output"):
            outputfile = arg
        elif opt in ("-e", "--enterprise"):
            enterprisefilter = arg
        elif opt in ("-d", "--domain"):
            domainfilter = arg


    logger.info( "Output File: %s" % outputfile )
    logger.info( "Enterprise filter: %s" % enterprisefilter)
    logger.info( "Domain filter: %s" % domainfilter)

    # Get All Audit Erros
    vsdRoutingList = getVSDRoutingInformation(enterprisefilter, domainfilter)

    #Output to CSV file
    if vsdRoutingList and len(vsdRoutingList) >0:
        f =  open(outputfile, 'w')
        f.write("Enterprise,DomainName,DomainType,SubnetName,ServiceID,VNID,domainRD,domainRT\n") 
        for routinginfo in vsdRoutingList:
            (enterpriseName,domainName,domainType,SubnetName,serviceID, VNID, domainRD, domainRT) = routinginfo
            logger.debug( "%s,%s,%s,%s,%s,%s,%s,%s" % (enterpriseName,domainName,domainType,SubnetName, serviceID, VNID, domainRD, domainRT) )
            f.write( "%s,%s,%s,%s,%s,%s,%s,%s\n" % (enterpriseName,domainName,domainType,SubnetName, serviceID, VNID, domainRD, domainRT) )

        f.close()

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
