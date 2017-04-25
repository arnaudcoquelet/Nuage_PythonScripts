###################################################################################################################
# GENERAL IMPORT
#
from __future__ import print_function
try:
    from vspk import v3_2 as vsdk
except ImportError:
    from vspk.vsdk import v3_2 as vsdk

import json
import datetime
import time
import sys
import getopt
import csv
import requests
import json
import re
import getpass
import os

import filecmp # Needed for File Comparison
import difflib, optparse # Needed for DIFF to work 

import operator
from operator import itemgetter, attrgetter, methodcaller

from multiprocessing import Pool 

requests.packages.urllib3.disable_warnings()

import logging
import sys, traceback

import snimpy.snmp
SNMP_COMMUNITY = "public"

###################################################################################################################


#Nuage VSD
VSD_USER = ""
VSD_PASS = ""
VSD_ENTERPRISE = "csp"
VSD_API_URL = "https://vsd1:8443"
VSD_API_VERSION = "3_0"


THREADS = 4
SCRIPT_VERSION = 0.1
TIME=True
DEBUG=False

RESULT_ITEMS = {}


SDP_DC_Filters = { 'DC1': ['1.1.1'], 
                   'DC2': ['2.2.2'], 
                   'DC1_XRS' : ['10.1.1.1', '10.1.1.2'], 
                   'DC2_XRS' : ['10.2.2.1', '10.2.2.2'] 
                 }


def print_warning(*objs):
    print("WARNING: ", *objs, file=sys.stderr)

def print_debug(*objs):
    global DEBUG

    if DEBUG:
        print("DEBUG: ", *objs, file=sys.stdout)

def print_info(*objs):
    print(*objs, file=sys.stderr)

def print_normal(*objs):
    print(*objs, file=sys.stdout)


################################################################################################
# This is the DIFF Function here: ##

def FileDiff(file1, file2, HtmlFileName, options): #File1 = FileName of File1 / #File2 = FileName of File2
    fromdate = time.ctime(os.stat(file1).st_mtime)
    todate = time.ctime(os.stat(file2).st_mtime)
    fromlines = open(file1, 'U').readlines()
    tolines = open(file2, 'U').readlines()

    if options == 'u':
        diff = difflib.unified_diff(fromlines, tolines, file1, file2, fromdate, todate, n=n)
    elif options == 'n':
        diff = difflib.ndiff(fromlines, tolines)
    elif options == 'm':
        
        diff = difflib.HtmlDiff().make_file(fromlines,tolines,file1,file2,context=options,numlines=3)
    else:
        diff = difflib.context_diff(fromlines, tolines, file1, file2, fromdate, todate, n=n)

    orig_stdout = sys.stdout

    f = file(HtmlFileName, 'w')
    sys.stdout = f
    sys.stdout.writelines(diff)
    sys.stdout = orig_stdout
    f.close()

################################################################################################


################################################################################################
# Get VSG/VSA IP from the VSD
#

def createVsdkSession(vsdUrl, vsdEnterprise, vsdUsername, vsdPassword):
    # Connect to VSD
    session = None
    if 'version' in vsdk.NUVSDSession.__init__.__code__.co_varnames:
        # If older SDK
        session = vsdk.NUVSDSession(username=vsdUsername,
                                    password=vsdPassword,
                                    enterprise=vsdEnterprise,
                                    api_url=vsdUrl,
                                    version=LOGIN_API_VERSION)
    else:
        session = vsdk.NUVSDSession(username=vsdUsername,
                                    password=vsdPassword,
                                    enterprise=vsdEnterprise,
                                    api_url=vsdUrl)
    session.start()
    return session

def getVsgListFromVsd(vsdUrl, vsdEnterprise, vsdUsername, vsdPassword):
    #Check VSD IP
    if vsdUrl == '':
        #Ask login
        vsdIp = raw_input("Enter the VSD IP/Fqdn: ")
        vsdUrl = "https://%s:8443" % (vsdIp)

    #Check Username and Password
    if vsdUsername == '':
        #Ask login
        vsdUsername = raw_input("Enter your VSD login: ")

    if vsdPassword == '':
        #Ask password
        vsdPassword = getpass.getpass()

    #Check VSD Enterprise
    if vsdEnterprise == '':
        #Ask login
        vsdEnterprise = raw_input("Enter the Enterprise: ")

    session = createVsdkSession(vsdUrl, vsdEnterprise, vsdUsername, vsdPassword)
    vsp = session.user.vsps.get_first()
    vsgs = vsp.hscs.get()

    return vsgs

def getVsgIpsFromVsd(vsdUrl, vsdEnterprise, vsdUsername, vsdPassword,vsgIpfilter, vsgNamefilter, useVsgManagement):
    vsg_list = {}
    vsgs = getVsgListFromVsd(vsdUrl, vsdEnterprise, vsdUsername, vsdPassword)

    if vsgs and len(vsgs)>0:
        for vsg in vsgs:
            name = vsg.name
            address = vsg.address
            managementIP =vsg.management_ip

            if (vsgNamefilter in name) and (vsgIpfilter in managementIP):
                if useVsgManagement:
                    vsg_list[name] = managementIP
                else:
                    vsg_list[name] = address

    return vsg_list

################################################################################################


################################################################################################
# SNMP Collection
#
def getVsgSdpsBySnmp(name, ip):
    OID_id = (1,3,6,1,4,1,6527,3,1,2,4,4,3,1,1)
    OID_ip = (1,3,6,1,4,1,6527,3,1,2,4,4,3,1,4)
    OID_admin = (1,3,6,1,4,1,6527,3,1,2,4,4,3,1,8)
    OID_oper = (1,3,6,1,4,1,6527,3,1,2,4,4,3,1,9)

    SDPs = {}
    try:
        print_info("Processing %s (%s)   " % (name, ip))
        time.sleep(0.1)
        session = snimpy.snmp.Session(ip, community=SNMP_COMMUNITY)
        
        #Get ALL SDP ID
        results = list( session.walk( OID_id ) )
        for r in results:
            (key, value) = r
            SDPs[key[-1]] = {'sdp': value}

        #Get ALL SDP Admin Status
        results = list( session.walk( OID_admin ) )
        for r in results:
            (key, value) = r
            if value == 1:
                SDPs[key[-1]]['Admin'] = 'up'
            else:
                SDPs[key[-1]]['Admin'] = 'down'

        #Get ALL SDP Oper Status
        results = list( session.walk( OID_oper ) )
        for r in results:
            (key, value) = r
            if value == 1:
                SDPs[key[-1]]['Oper'] = 'up'
            else:
                SDPs[key[-1]]['Oper'] = 'down'


        #Get ALL SDP IP
        results = list( session.walk( OID_ip ) )
        for r in results:
            (key, value) = r

            #Fix improper IP address parsing
            if ("%s" % (value)).count('.') < 3:
                ipaddr = ".".join("{:0}".format(ord(c)) for c in value)
                value = ipaddr
            SDPs[key[-1]]['IP'] = value
    except Exception,e:
        print_warning("%s (%s): %s" % (name, ip, e) )

    print_debug('SDPs= %s' % (SDPs))
    return SDPs

def getVsgsSdpsSnmp(vsg_tupple):
    global RESULT_ITEMS

    name, ip = vsg_tupple

    #Get all SDPs from VSG
    sdps = getVsgSdpsBySnmp (name, ip)

    #Classify each SDP:
    classified_SDP = {}
    classified_SDP['Other'] = {'Up':0, 'Down': 0}
    for sdpClass, sdp_filters in SDP_DC_Filters.iteritems():
        classified_SDP[sdpClass] = {'Up':0, 'Down': 0}


    print_debug('VSG: %s' % (name))
    for sdp, sdp_output in sdps.iteritems():
        foundSpdClass = None
        down=0
        up=0

        if sdp_output and sdp_output['IP']:
            if sdp_output['Oper'] in "Down":
                down= 1
            else:
                up= 1

            for sdpClass, sdp_filters in SDP_DC_Filters.iteritems():
                if foundSpdClass is not None:
                    break
                for sdp_filter in sdp_filters:
                    if sdp_output['IP'].startswith(sdp_filter):
                        foundSpdClass = sdpClass
                        break

            if foundSpdClass is None:
                foundSpdClass = 'Other'
                print_debug("OTHER = %s" % (sdp_output))

            classified_SDP[foundSpdClass][sdp] = {}
            classified_SDP[foundSpdClass][sdp] = sdp_output
            classified_SDP[foundSpdClass]['Up'] += up
            classified_SDP[foundSpdClass]['Down'] += down
            print_debug('SDPClass: %s' % (foundSpdClass))
            print_debug('classified_SDP: %s' % (classified_SDP))


    print_debug('Classified SDPs: %s' % (classified_SDP))
    RESULT_ITEMS[name] = {'name':name, 'ip': ip, 'output': classified_SDP, 'raw_output': '' }

    return {'name':name, 'ip': ip, 'output': classified_SDP, 'raw_output': '' }


def getVsgsSdps(vsdUrl, vsdEnterprise, vsdUsername, vsdPassword, vsgIpfilter, vsgNamefilter, useVsgManagement, vsgListFile):
    global RESULT_ITEMS

    vsg_list = {}
    if not vsgListFile:
        vsg_list = getVsgIpsFromVsd(vsdUrl, vsdEnterprise, vsdUsername, vsdPassword,vsgIpfilter, vsgNamefilter, useVsgManagement)
    else:
        with open(vsgListFile) as data_file:
            vsg_list = json.load(data_file)
            # print_info("VSG List:\n%s" % (vsg_list))


    print_debug("VSG List:\n%s" % (vsg_list))
    print_info( "")

    pool = Pool(THREADS)
    items = []
    for name,ip in vsg_list.iteritems():
        items.append( (name, ip) )

    results = pool.map(getVsgsSdpsSnmp, items)
    pool.close() 
    pool.join()

    #print_info("results:\n%s\n" % results)
    for result in results:
        RESULT_ITEMS[ result['name'] ] = result


    return RESULT_ITEMS

################################################################################################




################################################################################################
# Print Help and Version
#

def getHeader():
    return 'VSG_Name,VSG_IP,SDP Group,SDP Count'

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
    helpString += "    This script will audit the SDP on each VSG\n"
    helpString += "\n"
    helpString += " OPTIONS\n"
    helpString += "    -h, --help            Print this help\n"
    helpString += "    -v, --version         Print this version\n"
    helpString += "    -o, --output          Output filename\n"
    helpString += "    -d, --debug           Enable Debug output\n"
    helpString += "    --vsd-ip              VSD ip or fqdn\n"
    helpString += "    --vsd-enterprise      VSD user's Enterprise \n"
    helpString += "    --vsd-username        VSD username\n"
    helpString += "    --vsd-password        VSD password\n"
    helpString += "    --vsg-ip              VSG ip filter\n"
    helpString += "    --vsg-name            VSG name filter\n"
    helpString += "    --vsg-list            File containing list of VSG and IP to process\n"
    helpString += "    -p, --process         Nb of simulated connections\n"
    helpString += "    --before              Collect information for the Before\n"
    helpString += "    --after               Collect and Compare with the Before\n"
    helpString += "    -m, --management      Use Management interface instead of Inbound\n"
    helpString += "\n"

    return helpString

def main(argvs):
    global TIME,csvWriter, THREADS, DEBUG

    argv = argvs[1:]

    outputfile = 'vsg_SDP-output.csv'
    vsgNamefilter = ''
    vsgIpfilter=''
    useVsgManagement = False
    vsgListFile=''

    vsdUrl = VSD_API_URL
    vsdEnterprise = VSD_ENTERPRISE
    vsdUsername = VSD_USER
    vsdPassword = VSD_PASS

    vsgUsername = ''
    vsgPassword = ''

    vsgBefore = False
    vsgAfter = False

    try:
        opts, args = getopt.getopt(
            argv, "hvdo:p:m", ["help","version","output=","debug",
                               "vsg-name=","vsg-ip=",'vsg-username=','vsg-password=', 'vsg-management', 'vsg-list=',
                               'vsd-ip=','vsd-enterprise=', 'vsd-username=','vsd-password=',
                               'process=', 'after', 'before','compare'])
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
        elif opt in ("-p", "--process"):
            THREADS = int(arg)
        elif opt in ("-d", "--debug"):
            DEBUG = True


        elif opt in ("--vsd-ip"):
            vsdUrl = "https://%s:8443" % (arg)
        elif opt in ("--vsd-enterprise"):
            vsdEnterprise = arg
        elif opt in ("--vsd-username"):
            vsdUsername=arg
        elif opt in ("--vsd-password"):
            vsdPassword=arg

        elif opt in ("-m", "--vsg-management"):
            useVsgManagement = True
        elif opt in ("--vsg-name"):
            vsgNamefilter = arg
        elif opt in ("--vsg-ip"):
            vsgIpfilter = arg
        elif opt in ("--vsg-username"):
            vsgUsername=arg
        elif opt in ("--vsg-password"):
            vsgPassword=arg

        elif opt in ("--vsg-list"):
            vsgListFile = arg
        elif opt in ("--before"):
            vsgBefore=True
        elif opt in ("--after"):
            vsgAfter=True


    print_info( "VSD IP: %s" % vsdUrl )
    print_info( "VSD Enterprise: %s" % vsdEnterprise)
    print_info( "VSD Username: %s" % vsdUsername)
    print_info( "")
    print_info( "VSG IP Filter: %s" % vsgIpfilter)
    print_info( "VSG Name Filter: %s" % vsgNamefilter )
    print_info( "")
    print_info( "Number of simulated connections: %s" % THREADS)
    print_info( "")

    outputfile_original = outputfile
    out, ext = os.path.splitext(outputfile)
    outputfile_before = out + '-before' + ext
    outputfile_after = out + '-after' + ext
    output_HtmlFile = out + '.html'

    if vsgBefore:
        outputfile = outputfile_before
        print_info( "Collecting Before")

    if vsgAfter:
        outputfile = outputfile_after
        print_info( "Collecting After")

    print_info( "Output File: %s" % outputfile )
    print_info( "")


    #Run the CLI commands against the VSGs
    RESULT_ITEMS = getVsgsSdps(vsdUrl, vsdEnterprise, vsdUsername, vsdPassword,
                               vsgIpfilter, vsgNamefilter,useVsgManagement, vsgListFile)


    #Write to outputfile
    if RESULT_ITEMS and len(RESULT_ITEMS)>0:
        print_info( "")
        print_info('Exporting results to: %s' % (outputfile) )

        f = open(outputfile,'w')
        f.write('%s\n' % (getHeader()))

        #Sort the Output per Router Name
        RESULT_ITEMS_SortedKeys = sorted(RESULT_ITEMS.keys())
        for vsgname in RESULT_ITEMS_SortedKeys:
            output =  RESULT_ITEMS[vsgname]['output']
            name = RESULT_ITEMS[vsgname]['name']
            ip = RESULT_ITEMS[vsgname]['ip']

            if output:
                #f.write('%s,%s,SDP,%s\n' % (name, ip, output))
                #Sort per SDP Filter name
                output_SortedKeys = sorted(output.keys())
                for key in output_SortedKeys: 
                    f.write('%s,%s,%s,Up:%s  Down:%s\n' % (name, ip, key, output[key]['Up'], output[key]['Down']))
        f.close()

        #Write dump to file
        f = open('%s.dump' % outputfile,'w')
        f.write('%s' % (RESULT_ITEMS))
        f.close()


    #Compare two outputs
    if vsgAfter:
        print_info ('')
        #Check if both file exist
        if not os.path.isfile(outputfile_before):
            print_warning("The BEFORE file is missing (%s)" % (outputfile_before))
        elif not os.path.isfile(outputfile_after):
            print_warning("The AFTER file is missing (%s)" % (outputfile_after))
        else:
            outputCompare = filecmp.cmp (outputfile_before, outputfile_after)
            print_info("COMPARE:")
            
            if outputCompare:
                print_info("Same information in both files")
            else:
                print_info('-->   %s compared to %s is NOT the same!!!    <--' % (outputfile_before, outputfile_after) )
                options = 'm'
                FileDiff(outputfile_before, outputfile_after, output_HtmlFile, options)
                print_info('Check file named: %s' % (output_HtmlFile))
                print_info('')


if __name__ == "__main__":
    startTime = time.time()
    main(sys.argv)
    endTime = time.time()

    if TIME:
        duration = endTime - startTime
        print_info ('')
        print_info ('Process stats:')
        print_info ('Start: %s     End: %s\nDuration: %s' % (
                    time.strftime("%H:%M:%S", time.localtime(startTime)),
                    time.strftime("%H:%M:%S", time.localtime(endTime)),
                    datetime.timedelta(seconds=duration)))
