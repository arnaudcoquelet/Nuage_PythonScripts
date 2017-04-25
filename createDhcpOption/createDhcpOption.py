try:
    from vspk import v3_2 as vsdk
except ImportError:
    from vspk.vsdk import v3_2 as vsdk

import requests
import csv
import sys
import getopt
import os.path
import traceback
import time, datetime
from collections import namedtuple

requests.packages.urllib3.disable_warnings()


SCRIPT_VERSION = '0.1'
DEBUG = False
TIME = False

PROCESSED_ITEMS = 0

# Nuage   VSD
LOGIN_USER = "csproot"
LOGIN_PASS = "csproot"
LOGIN_ENTERPRISE = "csp"
LOGIN_API_URL = "https://vsd1:8443"
LOGIN_API_VERSION = "3_2"

#CSV
CSV_FIELDS = ['Enterprise', 'L3_Domain_Name', 'Zone_Name','Subnet_Name', 'Action', 'Option', 'Value','Type']
CSVERROR_FIELDS = CSV_FIELDS[:]
CSVERROR_FIELDS.append('Error')

csvErrorWriter = None


#Global List of VSD object - CACHE
_EnterpriseList = {}

_Domain = namedtuple("Domain", ["enterpriseId","domain"])
_DomainList = {}

_Zone = namedtuple("Zone", ["domainId","zone"])
_ZoneList = {}

_Subnet = namedtuple("Subnet", ["zoneId","subnet"])
_SubnetList = {}

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


def printErrorCsv(csvRow, error, csvWriter):
    if csvWriter is None:
        return

    if csvRow is None:
        return

    csvRow['Error'] = error
    csvWriter.writerow(csvRow)

    if DEBUG:
        print error


def checkFields(csvFields):
    if csvFields is None or not isinstance(csvFields, list) or len(csvFields) == 0:
        return False

    for f in csvFields:
        if f not in CSV_FIELDS:
            return False

    return True


def createVsdkSession():
    # Connect to VSD
    session = None
    if 'version' in vsdk.NUVSDSession.__init__.__code__.co_varnames:
        # If older SDK
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




def applyDhcpOptionToDomain(enterpriseName,domainName,action,option,value,formattype,session):
    return applyDhcpOptionToObject(enterpriseName,domainName,None,None,action,option,value,formattype,session)

def applyDhcpOptionToZone(enterpriseName,domainName,zoneName,action,option,value,formattype,session):
    return applyDhcpOptionToObject(enterpriseName,domainName,zoneName,None,action,option,value,formattype,session)

def applyDhcpOptionToSubnet(enterpriseName,domainName,zoneName,subnetName,action,option,value,formattype,session):
    return applyDhcpOptionToObject(enterpriseName,domainName,zoneName,subnetName,action,option,value,formattype,session)



def dhcpOptionToObject(vsdObject,action,option,value,formattype):
    if vsdObject is None:
        return None, "Error - No object to add DHCP"

    if action == "ADD":
        return addDhcpOptionToObject(vsdObject,action,option,value,formattype)
    elif action == "DELETE":
        return deleteDhcpOptionToObject(vsdObject,action,option)
    elif action == "UPDATE":
        return updateDhcpOptionToObject(vsdObject,action,option,value,formattype)

def deleteDhcpOptionToObject(vsdObject,action,option):
    if "dhcp_options" in dir(vsdObject):
        optionHex = hex(int(option))[2:]
        if(len(optionHex) % 2) == 1:
            optionHex = '0' + optionHex

        dhcpOption = vsdObject.dhcp_options.get_first(filter="type == '%s'" % optionHex)
        if dhcpOption is None:
            return None, "Error - could not found DHCP Option %s" % option

        print "Deleting Option %s" % option

        dhcpOption.delete()
    return True, "Option %s deleted" % option

def updateDhcpOptionToObject(vsdObject,action,option,value,formattype):
    if "dhcp_options" in dir(vsdObject):
        optionHex = hex(int(option))[2:]
        if(len(optionHex) % 2) == 1:
            optionHex = '0' + optionHex

        dhcpOption = vsdObject.dhcp_options.get_first(filter="type == '%s'" % optionHex)
        if dhcpOption is None:
            return None, "Error - could not found DHCP Option %s" % option

        if formattype == 'IP':
            ip = value.split('.')
            valueHex = ''
            for ipItem in ip:
                valueHex += '{:02X}'.format(int(ipItem))

        elif formattype == 'STRING':
            valueHex = value.encode("HEX")
        elif formattype == 'INT':
            valueHex=format(int(value),"08x")
        else:
            valueHex = value

        if(len(valueHex) % 2) == 1:
            valueHex = '0' + valueHex
        lengthHex = hex(len(valueHex)/2)[2:]
        if(len(lengthHex) % 2) == 1:
            lengthHex = '0' + lengthHex

        try:
            print "Updating Option %s = %s" % (option, value)

            dhcpOption.value = valueHex
            dhcpOption.length = lengthHex
            dhcpOption.save()
        except Exception, e:
            return None, "Error - (%s, %s, %s): %s" % (action,option,value,e)

        return dhcpOption, None

def addDhcpOptionToObject(vsdObject,action,option,value,formattype):
    if vsdObject is None:
        return None, "Error - No object to add DHCP"

    #Check if vsdObject has a "dhcp_options" attribute
    if "dhcp_options" in dir(vsdObject):
        optionHex = hex(int(option))[2:]
        if(len(optionHex) % 2) == 1:
            optionHex = '0' + optionHex

        if formattype == 'IP':
            ip = value.split('.')
            valueHex = ''
            for ipItem in ip:
                valueHex += '{:02X}'.format(int(ipItem))

        elif formattype == 'STRING':
            valueHex = value.encode("HEX")
        elif formattype == 'INT':
            valueHex=format(int(value),"08x")
        else:
            valueHex = value

        if(len(valueHex) % 2) == 1:
            valueHex = '0' + valueHex
        lengthHex = hex(len(valueHex)/2)[2:]
        if(len(lengthHex) % 2) == 1:
            lengthHex = '0' + lengthHex
        
        try:
            dhcpOption = vsdk.NUDHCPOption(type=optionHex,value=valueHex,length=lengthHex)
            print "Adding Option %s = %s" % (option, value)

            vsdObject.create_child(dhcpOption)

            return dhcpOption, None
        except Exception, e:
            return None, "Error - (%s, %s, %s): %s" % (action,option,value,e)
    else:
        return None, "Error - Not an object to add DHCP"

    return None, "Error - Not an object to add DHCP"

def applyDhcpOptionToObject(enterpriseName,domainName,zoneName,subnetName,action,option,value,formattype,session):

    if action.upper() == 'DELETE':
        action = 'DELETE'
    elif action.upper() == 'UPDATE':
        action = 'UPDATE'
    elif action.upper() == 'ADD':
        action = 'ADD'
    else:
        action = None

    if enterpriseName is None:
        return False, "No VSD connection"

    #Get the Enterprise Object
    enterprise,error = getEnterpriseObject(enterpriseName, session)
    if enterprise is None:
        return None,error

    #Get the Domain Object
    domain,error = getL3DomainObject(enterprise, domainName)
    if domain is None:
        return None, error

    if zoneName is None or zoneName == '':
        #Add DHCP option to Domain
        return dhcpOptionToObject(domain, action,option,value,formattype)
    else:
        #Get the Zone Object
        zone,error = getL3ZoneObject(domain, zoneName)
        if zone is None:
            return None, error

        if subnetName is None or subnetName == '':
            #Add DHCP option to Zone
            return dhcpOptionToObject(zone, action,option,value,formattype)
        else:
            #Get the Subnet Object
            subnet,error = getL3SubnetObject(zone, subnetName)
            if subnet is None:
                return None, error

            #Add DHCP Option to Subnet
            return dhcpOptionToObject(subnet, action,option,value,formattype)

    return None, 'Error'

def applyDhcpOption(enterpriseName,domainName,zoneName,subnetName,action,option,value,formattype,session):
    if session is None:
        return None, "Error - No connection to VSD"

    if len(subnetName) > 0:
        return applyDhcpOptionToSubnet(enterpriseName,domainName,zoneName,subnetName,action,option,value,formattype,session)
    elif len(zoneName) > 0:
        return applyDhcpOptionToZone(enterpriseName,domainName,zoneName,action,option,value,formattype,session)
    elif len(domainName) >0:
        return applyDhcpOptionToDomain(enterpriseName,domainName,action,option,value,formattype,session)

    return None, "Error - No connection to VSD"



def applyDhcpOptions(inputfile=None, outputfile=None, session=None, csvWriter=None):
    global PROCESSED_ITEMS

    # Check if CSV
    if os.path.isfile(inputfile):
        # Import CSV
        csvreader = csv.DictReader(open(inputfile, mode='r'))

        # Check fields
        fieldnames = csvreader.fieldnames
        if checkFields(fieldnames):
            for row in csvreader:
                # Create individual VLANs
                print "Applying DHCP Options to %s %s %s" % (row['L3_Domain_Name'], row['Zone_Name'], row['Subnet_Name'])
                dhcpOption, error = applyDhcpOption(row['Enterprise'],row['L3_Domain_Name'], row['Zone_Name'], row['Subnet_Name'], row['Action'], row['Option'], row['Value'], row['Type'],session)

                PROCESSED_ITEMS += 1

                if dhcpOption is None:
                    printErrorCsv(row, error, csvWriter)
        else:
            print "Incorrect CSV format."
            sys.exit()

    else:
        print "Input file not found."
        sys.exit()


def printVersion(args):
    helpString = "\n"
    helpString += " Script version %s\n" % SCRIPT_VERSION

    return helpString


def printHelp(argvs):
    helpString = "\n"
    helpString += " SYNOPSIS\n"
    helpString += "    %s [OPTIONS]\n" % argvs[0]
    helpString += "\n"
    helpString += " DESCRIPTION\n"
    helpString += "    This script will create DHCP option\n"
    helpString += "    based on a CSV file\n"
    helpString += "    CSV Fields:\n"
    helpString += "    - Enterprise\n"
    helpString += "    - L3_Domain_Name\n"
    helpString += "    - Zone_Name\n"
    helpString += "    - Subnet_Name\n"
    helpString += "    - Action (ADD,DELETE,UPDATE)\n"
    helpString += "    - Option\n"
    helpString += "    - Value\n"
    helpString += "    - Type (IP,STRING,INT,RAW)\n"
    helpString += "\n"
    helpString += " OPTIONS\n"
    helpString += "    -h, --help      Print this help\n"
    helpString += "    -v, --version   Print this version\n"
    helpString += "    -i, --input     To specify the input csv file\n"
    helpString += "    -o, --output    To specify the error file\n"
    helpString += "    --debug         Error output\n"
    helpString += "    -t, --time      Processing time\n"
    helpString += "\n"
    helpString += " EXAMPLES\n"
    helpString += "    To import from a CSV file:\n"
    helpString += "    %s -i create_dhcp_option.csv\n" % argvs[0]
    helpString += "\n"

    return helpString


def main(argvs):
    global DEBUG, TIME

    argv = argvs[1:]

    inputfile = ''
    outputfile = 'create_dhcp_option_error.csv'

    try:
        opts, args = getopt.getopt(
            argv, "thvi:o:", ["time","help", "debug", "input=", "output="])
    except getopt.GetoptError:
        print printHelp(argvs)
        sys.exit(2)

    if len(argv) == 0:
        print printHelp(argvs)
        sys.exit()

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print printHelp(argvs)
            sys.exit()
        elif opt in ("-t", "--time"):
            TIME = True
        elif opt in ("-v", "--version"):
            print printVersion(argvs)
            sys.exit()
        elif opt in ("--debug"):
            DEBUG = True
        elif opt in ("-i", "--input"):
            inputfile = arg
        elif opt in ("-o", "--output"):
            outputfile = arg

    print "Input File: %s" % inputfile
    print "Output File: %s" % outputfile
    print "Debug: %s" % DEBUG

    # Create VSD Session
    session = createVsdkSession()

    if session is None:
        print "Cannot connect to VSD"
    else:
        # Create CSV Error file
        csvErrorWriter = csv.DictWriter(
            open(outputfile, mode='w'), fieldnames=CSVERROR_FIELDS)
        csvErrorWriter.writeheader()

        # Build DHCP Options
        applyDhcpOptions(inputfile, outputfile, session, csvErrorWriter)


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