from netmiko import ConnectHandler
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from collections import namedtuple
import csv
import json
import re
import sys
import getopt
import os.path
import traceback
import time, datetime
from datetime import timedelta
import socket

SCRIPT_VERSION = '0.1'
DEBUG = False
TIME = False

PROCESSED_ITEMS = 0
START_TIME = ''
SCRIPT_PATH = ''
csvNsgStatusWriter = None

#List of VSCs
VSCs = {}

#List of NSGs  
NSGs = {}



##################################################################################################################
#
#   REGEX
#
##################################################################################################################


PATTERN_UPTIME = re.compile("^(\d+)d\s*(\d{1,2}):(\d{1,2}):(\d{1,2})")
PATTERN_NSG_DATAPATH = re.compile("^Datapath-Id\s*:\s*va-(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})", re.MULTILINE)

PATTERN_NSG_IP = re.compile("(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
PATTERN_NSG_INSTANCE = re.compile("\s(?P<instance>\d{1,3})")

PATTERN_NSG_UPTIME = re.compile("^Uptime.*:\s*(\d+d\s*\d{1,2}:\d{1,2}:\d{1,2})", re.MULTILINE)
PATTERN_NSG_ROLE = re.compile("^Cntrl\.\s*role\s*:\s*(\w*)", re.MULTILINE)
PATTERN_NSG_CNX_TYPE = re.compile("Cntrl\.\s*Conn\.\s*type\s*:\s*(\w*)", re.MULTILINE)
PATTERN_NSG_CNX_STATE = re.compile("^Cntrl\.\s*Conn\.\s*state\s*:\s*(\w*)", re.MULTILINE)
PATTERN_NSG_JSON_STATE = re.compile("^JSON\s*Conn\.\s*State\s*:\s*(\w*)", re.MULTILINE)
PATTERN_NSG_JSON_UPTIME = re.compile("^JSON\s*Sess\.\s*Uptime\s*:\s*(\d+d\s*\d{1,2}:\d{1,2}:\d{1,2})", re.MULTILINE)





class NSG(object):

    def __init__(self):
        self.datapath = ''
        self.ip = ''
        self.instance = ''
        self.nsg_status = {}
        self.last_scan = ''

    def isPartiallyDown(self):
        if self.nsg_status and len(self.nsg_status.keys()) >0:
            for key, status in self.nsg_status.iteritems():
                #print 'NSG: %s' % ( status.toDict() )
                if status.state.lower() == 'down':
                    return True
                if status.cnx_state.lower() == 'down':
                    return True
                if status.json_state.lower() == 'down':
                    return True

        return False

    def toStr(self):
        txt = ''

        txt = 'ID: %s\n' % (self.datapath)
        for key, stat in self.nsg_status.iteritems():
            txt += ' IP:%s(%s) - vsc: %s' % (self.ip, stat.ip, stat.vsc_ip)
            txt += '   (Uptime:%s, Role: %s)' % (stat.uptime, stat.role)
            txt += '\n'

        return txt

class NSG_STATUS(object):

    def __init__(self):
        self.datapath = ''
        self.ip = ''
        self.instance = ''
        self.state = ''
        self.uptime = ''
        self.vsc_ip = ''
        self.vsc = ''
        self.role = ''
        self.cnx_type = ''
        self.cnx_state = ''
        self.json_state = ''
        self.json_uptime = ''
        self.xmpp_error_code = ''
        self.xmpp_error_text = ''
        self.severity = 'normal'   #normal, minor, major, critical
        self.last_scan = ''

    def toStr(self):
        return 'vsc: %s/%s/%s/%s, uptime: %s, json: %s/%s' % (self.ip, self.role, self.cnx_type,self.cnx_state,self.uptime, self.json_state, self.json_uptime)

    def toDict(self):
        result = {}
        result['NSG_Id'] = self.datapath
        result['NSG_IP'] = self.ip
        result['VSC'] = self.vsc_ip
        result['Status'] = self.state
        result['Role'] = self.role
        result['Connexion'] = self.cnx_state
        result['Uptime'] = self.uptime
        result['Json'] = self.json_state
        result['Json_Uptime'] = self.json_uptime
        result['Xmpp_Error'] = self.xmpp_error_code
        result['Xmpp_Text'] = self.xmpp_error_text

        return result


#CSV
CSV_FIELDS = ['NSG_Id', 'NSG_IP', 'VSC', 'Status','Role','Connexion','Uptime','Json','Json_Uptime','Xmpp_Error','Xmpp_Text','Last_Scan']

CSVERROR_FIELDS = CSV_FIELDS[:]
CSVERROR_FIELDS.append('Error')


##################################################################################################################
#
#   REGEX
#
##################################################################################################################

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
        if f not in CSVERROR_FIELDS:
            return False

    return True



##################################################################################################################
#
#   REPORTS
#
##################################################################################################################

def getLocalIp():
    ip = ''
    try :
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('google.com', 0))
        ip = s.getsockname()[0]
    except Exception, e:
        ip = ''

    return ip

def generateNsgDownAlarmTxt(nsgs):
    alarm = "%s NSG(s) detected DOWN: \n\n" % (len(nsgs))

    for nsgIp, nsg in nsgs.iteritems():
        alarm += nsg.toStr() + "\n"

    return alarm

def generateNsgDownAlarmHtml(nsgs):

    style = """
    <style type="text/css">
    .tg  {border-collapse:collapse;border:none;}
    .tg td{font-family:Arial, sans-serif;font-size:14px;padding:10px 5px;border-style:solid;border-width:0px;word-break:normal;vertical-align:top;}
    .tg th{font-family:Arial, sans-serif;font-size:14px;font-weight:normal;padding:10px 5px;border-style:solid;border-width:0px;word-break:normal;text-align:center;vertical-align:top;}
    .tg .tg-center{text-align:center;}
    .tg .tg-bold{font-weight:bold;}

    .tg .nsg-critical{background-color:#fd6864;font-weight:bold;}
    .tg .vsc-critical{background-color:#fd6864;}
    .tg .status-critical{background-color:#fd6864;font-weight:bold;}
    .tg .role-critical{background-color:#fd6864;}
    .tg .connexion-critical{background-color:#fd6864;}
    .tg .cuptime-critical{background-color:#fd6864;}
    .tg .json-critical{background-color:#fd6864;}
    .tg .juptime-critical{background-color:#fd6864;}


    .tg .nsg-major{background-color:#ffcc67;font-weight:bold;}
    .tg .vsc-major{background-color:#ffcc67;}
    .tg .status-major{background-color:#ffcc67;font-weight:bold;}
    .tg .role-major{background-color:#ffcc67;}
    .tg .connexion-major{background-color:#ffcc67;}
    .tg .cuptime-major{background-color:#ffcc67;}
    .tg .json-major{background-color:#ffcc67;}
    .tg .juptime-major{background-color:#ffcc67;}


    .tg .nsg-minor{background-color:#fffc9e;font-weight:bold;}
    .tg .vsc-minor{background-color:#fffc9e;}
    .tg .status-minor{background-color:#fffc9e;font-weight:bold;}
    .tg .role-minor{background-color:#fffc9e;}
    .tg .connexion-minor{background-color:#fffc9e;}
    .tg .cuptime-minor{background-color:#fffc9e;}
    .tg .json-minor{background-color:#fffc9e;}
    .tg .juptime-minor{background-color:#fffc9e;}
    </style>
    """

    table = """
    <table class="tg">
      <tr>
        <th class="tg-baqh">ID</th>
        <th class="tg-baqh">NSG WAN</th>
        <th class="tg-baqh">VSC</th>
        <th class="tg-baqh">Status</th>
        <th class="tg-baqh">Role</th>
        <th class="tg-baqh">Connexion</th>
        <th class="tg-baqh">Uptime</th>
        <th class="tg-baqh">Json</th>
        <th class="tg-baqh">Uptime</th>
      </tr>
      """

    tableend = "</table>"

    text = ""

    text += """
    <p>
        %s NSG(s) detected down
    </p>
    """ % (len(nsgs) )

    text += table
    for ip,nsg in nsgs.iteritems():
        if nsg.nsg_status:
            for vscIp, nsg_stat in nsg.nsg_status.iteritems():
                tmpTr = ""
                tmpTr += "<tr>\n"
                tmpTr += "<td class=\"nsg-%s\">%s</td>\n" % (nsg_stat.severity, nsg_stat.datapath)
                tmpTr += "<td class=\"nsg-%s\">%s</td>\n" % (nsg_stat.severity, nsg_stat.ip)
                tmpTr += "<td class=\"vsc-%s\">%s</td>\n" % (nsg_stat.severity, nsg_stat.vsc_ip)
                tmpTr += "<td class=\"status-%s\">%s</td>\n" % (nsg_stat.severity, nsg_stat.state.upper())
                tmpTr += "<td class=\"role-%s\">%s</td>\n" % (nsg_stat.severity, nsg_stat.role)
                tmpTr += "<td class=\"connexion-%s\">%s</td>\n" % (nsg_stat.severity, nsg_stat.cnx_state)
                tmpTr += "<td class=\"cuptime-%s\">%s</td>\n" % (nsg_stat.severity, nsg_stat.uptime)
                tmpTr += "<td class=\"json-%s\">%s</td>\n" % (nsg_stat.severity, nsg_stat.json_state)
                tmpTr += "<td class=\"juptime-%s\">%s</td>\n" % (nsg_stat.severity, nsg_stat.json_uptime)
                tmpTr += "</tr>\n"

                text += tmpTr

    text += tableend

    text += """
    <p>
        Report generated on %s by %s
    </p>
    """ % (START_TIME, getLocalIp()) 

    text = """
    <html>
        <head>
            %s
        </head>
        <body>
            %s
        </body>
    </html>
    """ % (style, text)
    return text


def generateNsgStatusReportTxt(nsgs):
    report = ""


    report += "Number of NSG scanned: %s\n" % ( len(nsgs)  )

    header = """
|-----------------|-----------------|--------|-----------|------|------------------|
| NSG             | VSC             | Status | Role      | Json | Uptime           |
|-----------------|-----------------|--------|-----------|------|------------------|
"""

    text = ''
    nsgDownCounter = 0
    for ip,nsg in nsgs.iteritems():
        if nsg.nsg_status:
            for vscIp, nsg_stat in nsg.nsg_status.iteritems():
                text += "| %s | %s | %s | %s | %s | %s |\n"  \
                        %  (str.rjust(str(nsg_stat.ip),15), 
                            str.rjust(str(nsg_stat.vsc_ip),15),
                            str.ljust(str(nsg_stat.state.upper()),6),
                            str.ljust(str(nsg_stat.role),9),
                            str.ljust(str(nsg_stat.json_state),4), 
                            str.ljust(str(nsg_stat.json_uptime),16) )

                if nsg_stat.state == 'DOWN':
                    nsgDownCounter +=1

    footer = "|-----------------|-----------------|--------|-----------|------|------------------| \n"

    if nsgDownCounter>0:
        report += "The scan discover some NSG are down.\n"
    else:
        report += "All the NSGs seem to be UP.\n"


    report += "\n" + header + text + footer 

    report += "\n Report generated on %s" % (START_TIME)

    return report


def generateNsgStatusReportHtml(nsgs):

    style = """
    <style type="text/css">
    .tg  {border-collapse:collapse;border:none;}
    .tg td{font-family:Arial, sans-serif;font-size:14px;padding:10px 5px;border-style:solid;border-width:0px;word-break:normal;vertical-align:top;}
    .tg th{font-family:Arial, sans-serif;font-size:14px;font-weight:normal;padding:10px 5px;border-style:solid;border-width:0px;word-break:normal;text-align:center;vertical-align:top;}
    .tg .tg-center{text-align:center;}
    .tg .tg-bold{font-weight:bold;}

    .tg .nsg-critical{background-color:#fd6864;font-weight:bold;}
    .tg .vsc-critical{background-color:#fd6864;}
    .tg .status-critical{background-color:#fd6864;font-weight:bold;}
    .tg .role-critical{background-color:#fd6864;}
    .tg .connexion-critical{background-color:#fd6864;}
    .tg .cuptime-critical{background-color:#fd6864;}
    .tg .json-critical{background-color:#fd6864;}
    .tg .juptime-critical{background-color:#fd6864;}


    .tg .nsg-major{background-color:#ffcc67;font-weight:bold;}
    .tg .vsc-major{background-color:#ffcc67;}
    .tg .status-major{background-color:#ffcc67;font-weight:bold;}
    .tg .role-major{background-color:#ffcc67;}
    .tg .connexion-major{background-color:#ffcc67;}
    .tg .cuptime-major{background-color:#ffcc67;}
    .tg .json-major{background-color:#ffcc67;}
    .tg .juptime-major{background-color:#ffcc67;}


    .tg .nsg-minor{background-color:#fffc9e;font-weight:bold;}
    .tg .vsc-minor{background-color:#fffc9e;}
    .tg .status-minor{background-color:#fffc9e;font-weight:bold;}
    .tg .role-minor{background-color:#fffc9e;}
    .tg .connexion-minor{background-color:#fffc9e;}
    .tg .cuptime-minor{background-color:#fffc9e;}
    .tg .json-minor{background-color:#fffc9e;}
    .tg .juptime-minor{background-color:#fffc9e;}
    </style>
    """

    table = """
    <table class="tg">
      <tr>
        <th class="tg-baqh">ID</th>
        <th class="tg-baqh">NSG WAN</th>
        <th class="tg-baqh">VSC</th>
        <th class="tg-baqh">Status</th>
        <th class="tg-baqh">Role</th>
        <th class="tg-baqh">Connexion</th>
        <th class="tg-baqh">Uptime</th>
        <th class="tg-baqh">Json</th>
        <th class="tg-baqh">Uptime</th>
      </tr>
      """

    tableend = "</table>"

    text = ""

    text += """
    <p>
        Number of NSG scanned: %s
    </p>
    """ % (len(nsgs) )

    text += table
    for datapath,nsg in nsgs.iteritems():
        #print "%s" % datapath
        #print "%s" % nsg
        if nsg.nsg_status:
            for vscIp, nsg_stat in nsg.nsg_status.iteritems():
                tmpTr = ""
                tmpTr += "<tr>\n"
                tmpTr += "<td class=\"nsg-%s\">%s</td>\n" % (nsg_stat.severity, nsg_stat.datapath)
                tmpTr += "<td class=\"nsg-%s\">%s</td>\n" % (nsg_stat.severity, nsg_stat.ip)
                tmpTr += "<td class=\"vsc-%s\">%s</td>\n" % (nsg_stat.severity, nsg_stat.vsc_ip)
                tmpTr += "<td class=\"status-%s\">%s</td>\n" % (nsg_stat.severity, nsg_stat.state.upper())
                tmpTr += "<td class=\"role-%s\">%s</td>\n" % (nsg_stat.severity, nsg_stat.role)
                tmpTr += "<td class=\"connexion-%s\">%s</td>\n" % (nsg_stat.severity, nsg_stat.cnx_state)
                tmpTr += "<td class=\"cuptime-%s\">%s</td>\n" % (nsg_stat.severity, nsg_stat.uptime)
                tmpTr += "<td class=\"json-%s\">%s</td>\n" % (nsg_stat.severity, nsg_stat.json_state)
                tmpTr += "<td class=\"juptime-%s\">%s</td>\n" % (nsg_stat.severity, nsg_stat.json_uptime)
                tmpTr += "</tr>\n"

                text += tmpTr

    text += tableend

    text += """
    <p>
        Report generated on %s by %s
    </p>
    """ % (START_TIME, getLocalIp())

    text = """
    <html>
        <head>
            %s
        </head>
        <body>
            %s
        </body>
    </html>
    """ % (style, text)
    return text

def sendNsgStatusReport(emailConfig, nsgs):
    #Send Status Update
    if emailConfig["enable"]:
        sendEmailNsgStatus(emailConfig, nsgs)

def sendNsgDownAlarm(emailConfig, nsgs):
    #Send Status Update
    if emailConfig["enable"]:
        sendEmailNsgDown(emailConfig, nsgs)


def sendEmail(emailConfig, text, html):
    if emailConfig is None:
        return None

    COMMASPACE = ', '

    msg = MIMEMultipart('alternative')
    msg['Subject'] = "%s - %s" % (emailConfig['subject'], START_TIME)
    msg['From'] = emailConfig['from']
    msg['To'] = COMMASPACE.join(emailConfig['to'])

    msg.attach( MIMEText(text, 'plain') )
    msg.attach( MIMEText(html, 'html') )

    try:
       smtpObj = smtplib.SMTP(emailConfig['smtp']['host'])
       smtpObj.sendmail(emailConfig['from'], emailConfig['to'], msg.as_string())
       smtpObj.quit()
       print "Successfully sent email"
    except SMTPException:
       print "Error: unable to send email"

def sendEmailNsgStatus(emailConfig, nsgs):
    if nsgs:
        text = ''

        text = generateNsgStatusReportTxt(nsgs)
        html = generateNsgStatusReportHtml(nsgs)

        sendEmail(emailConfig, text, html)

def sendEmailNsgDown(emailConfig, nsgs):
    if nsgs:
        text = ''

        text = generateNsgDownAlarmTxt(nsgs)
        html = generateNsgDownAlarmHtml(nsgs)

        sendEmail(emailConfig, text, html)





##################################################################################################################
#
#   NSG Status
#
##################################################################################################################

def getNsgStatusFromVsc(vsc):
    if vsc is None:
        return []

    #Connect to VSC
    # ipd = {                            
    #    #'device_type': 'ipd_7750',
    #    'device_type': 'cisco_ios',
    #    'ip': vsc['ip'],
    #    'username': vsc['username'],
    #    'password': vsc['password'],
    #    'verbose': False,
    # }

    net_connect = ConnectHandler(**vsc)

    time.sleep(1)
    #prompt = net_connect.find_prompt() 
    
    #Get each NSG
    nsgStatusList = []
    nsgList=[]


    output = net_connect.send_command_expect("show vswitch-controller vswitches vs-ip \t")
    matches = [m.groupdict() for m in PATTERN_NSG_IP.finditer(output)]
    for m_ip in matches:
        #print 'IP: %s' % (m_ip)

        #Get all Instances in case multiple on same IP
        command = "show vswitch-controller vswitches vs-ip %s vs-instance" % (m_ip['ip'])
        output = net_connect.send_command_expect("%s \t" % (command))

        #Clean output
        output = output.replace(command,"")
        match = re.search(r"(<vs-instance>)", output)
        start = match.start(1)
        output = output[start:]

        matches_instances = [m.groupdict() for m in PATTERN_NSG_INSTANCE.finditer(output)]

        for m_instance in matches_instances:
            # print m_ip['ip']
            # print m_instance['instance']
            nsgList.append( {'ip': m_ip['ip'], 'instance': m_instance['instance']})

    # print nsgList


    if len(nsgList) == 0:
        return None

    for nsg in nsgList:
        nsg_status = None
        text = net_connect.send_command_expect("show vswitch-controller vswitches vs-ip %s vs-instance %s detail"% (nsg['ip'], nsg['instance']) )

        nsg_status = parseVscShowVswitchVsIpDetail(vsc, nsg, text)
        

        if nsg_status:
            nsg_status.last_scan = START_TIME
            nsgStatusList.append(nsg_status)

    net_connect.disconnect()

    return nsgStatusList

def parseVscUptimeFormat(uptime):
    time = ''
    days = 0
    hours = 0
    minutes = 0
    seconds = 0

    #try:
    if True:
        matches = [m.groups() for m in PATTERN_UPTIME.finditer(uptime)]
        for m in matches:
            days =int(m[0])
            hours =int(m[1])
            minutes =int(m[2])
            seconds =int(m[3])

        return timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)
    #except Exception, e:
    #    return None

def parseVscShowVswitchVsIpDetail(vsc, nsg, text):
    nsg_status = NSG_STATUS()
    nsg_status.vsc_ip = vsc["ip"]
    nsg_status.vsc = vsc
    nsg_status.ip = nsg['ip']
    nsg_status.instance = nsg['instance']

    #Get Datapath ID:
    matches = [m.groups() for m in PATTERN_NSG_DATAPATH.finditer(text)]
    for m in matches:
        nsg_status.datapath = m[0]

    #Get uptime
    matches = [m.groups() for m in PATTERN_NSG_UPTIME.finditer(text)]
    for m in matches:
        nsg_status.uptime = m[0]
    if nsg_status.uptime:
        nsg_status.uptime = parseVscUptimeFormat(nsg_status.uptime)

    #Get VSC role
    matches = [m.groups() for m in PATTERN_NSG_ROLE.finditer(text)]
    for m in matches:
        nsg_status.role =m[0]

    #Get VSC cnx type
    matches = [m.groups() for m in PATTERN_NSG_CNX_TYPE.finditer(text)]
    for m in matches:
        nsg_status.cnx_type =m[0]

    #Get VSC cnx state
    matches = [m.groups() for m in PATTERN_NSG_CNX_STATE.finditer(text)]
    for m in matches:
        nsg_status.cnx_state =m[0].lower()

    #Get JSON state
    matches = [m.groups() for m in PATTERN_NSG_JSON_STATE.finditer(text)]
    for m in matches:
        nsg_status.json_state= m[0].lower()

    #Get JSON uptime
    matches = [m.groups() for m in PATTERN_NSG_JSON_UPTIME.finditer(text)]
    for m in matches:
        nsg_status.json_uptime =m[0]
    if nsg_status.json_uptime:
        nsg_status.json_uptime = parseVscUptimeFormat(nsg_status.json_uptime)

    if nsg_status.cnx_state == "ready" and  nsg_status.json_state == "up":
        nsg_status.state = "UP"
    else:
        nsg_status.state = "DOWN"
        nsg_status.severity = "critical"

    return nsg_status

def checkVscFromConfig(vscItem):
    if vscItem is None:
        return None

    if not hasattr(vscItem,"port"):
        vscItem["port"] = 22


    if 'ip' in vscItem.keys():
        if 'username' in vscItem.keys():
            if 'password' in vscItem.keys():
                return vscItem

    return None


def getCurrentNsgStatus(configVscs, outputfile=None):
    global PROCESSED_ITEMS, VSCs, NSGs

    if configVscs is None:
        print "Error while loading the config file."
        sys.exit()

    #Get the VSC
    VSCs = configVscs

    if VSCs is None or len(VSCs.keys()) == 0 :
        print "No VSC listed in the config file."
        sys.exit()

    #From each VSC, collect all the NSG status
    for key, vscConfig in VSCs.iteritems():

        vsc = checkVscFromConfig(vscConfig)
        if vsc:
            nsgs_status = getNsgStatusFromVsc(vsc)
            if nsgs_status is None:
                break

            for nsgStatus in nsgs_status:
                dp = '%s' % (nsgStatus.datapath)
                if not dp in NSGs.keys():
                    nsg = NSG()

                    nsg.datapath = dp
                    nsg.ip = nsgStatus.ip
                    nsg.last_scan = nsgStatus.last_scan
                    NSGs[dp] = nsg

                nsg = NSGs[dp]
                nsg.nsg_status[nsgStatus.vsc_ip] = nsgStatus

    return NSGs


def loadPreviousNsgStatusCsvAsDown(outputfile=None):
    previousNSGs = {}
    csvreader = None

    #Check if CSV
    if os.path.isfile(outputfile):
        #Import CSV
        csvreader = csv.DictReader(open(outputfile, mode='r'))

        #Check fields
        fieldnames = csvreader.fieldnames
        if checkFields(fieldnames):
            for row in csvreader:
                if not row['NSG_Id'] in previousNSGs.keys():
                    nsg = NSG()
                    nsg.datapath = row['NSG_Id']
                    nsg.ip = row['NSG_IP']
                    nsg.last_scan = row['Last_Scan']
                    previousNSGs[ row['NSG_Id'] ] = nsg

                mnsg_status = NSG_STATUS()
                mnsg_status.datapath = row['NSG_Id']
                mnsg_status.ip = row['NSG_IP']
                mnsg_status.vsc_ip = row['VSC']
                mnsg_status.state = "down"
                mnsg_status.role = row['Role']
                mnsg_status.cnx_state = 'down'
                mnsg_status.uptime = '0:00:00'
                mnsg_status.json_state = 'down'
                mnsg_status.json_uptime = '0:00:00'
                mnsg_status.xmpp_error_code = row['Xmpp_Error']
                mnsg_status.xmpp_error_text = row['Xmpp_Text']
                mnsg_status.severity = 'critical'

                #print "%s , %s, %s" % (row['NSG_Id'], row['NSG_IP'], row['VSC'])
                previousNSGs[ row['NSG_Id'] ].nsg_status[ row['VSC'] ] = mnsg_status


    return previousNSGs


def generateNsgStatusCsv(outputfile=None, nsgs=None):
    csvNsgStatusWriter= None
    csvNsgStatusWriter = csv.DictWriter(
        open(outputfile, mode='w'), fieldnames=CSVERROR_FIELDS)
    csvNsgStatusWriter.writeheader()

    if nsgs is None:
        return None

    for ip,nsg in nsgs.iteritems():
        if nsg.nsg_status and len(nsg.datapath.strip() ) >0:
            for vscIp, nsg_status in nsg.nsg_status.iteritems():
                data = nsg_status.toDict()
                data['NSG_Id'] = nsg.datapath
                data['NSG_IP'] = nsg.ip
                data['Last_Scan'] = START_TIME
                csvNsgStatusWriter.writerow(data)




def getNsgStatus(configfile=None, outputfile=None, report=False):
    #Load config json
    config = json.load(open(configfile))

    #Get old NSG status
    oldNsgs = loadPreviousNsgStatusCsvAsDown(outputfile)
    # print "Current CSV content:"
    # for oldNsgDatapath, oldNsg in oldNsgs.iteritems():
    #     print "\n\n%s" % oldNsg.toStr()
    #     for oldVsc, oldNsgStatus in oldNsg.nsg_status.iteritems():
    #         print  "%s" % oldNsgStatus.toDict()

    # Get NSG info from VSC
    nsgs = getCurrentNsgStatus(config["vsc"], outputfile)
    print "Scanned NSG content:"
    for nsgIp,nsg in nsgs.iteritems() :
        print nsg.toStr()

    # Add unscanned NSGs from previous scans
    modifiedNsgs = {}
    if oldNsgs and len(oldNsgs.keys())>0 :
        for oldDatapath, oldNsg in oldNsgs.iteritems():
            if oldNsg.datapath in nsgs.keys():
                if oldNsg.nsg_status :
                    for oldIpVsc, oldNsgStatus in oldNsg.nsg_status.iteritems():
                        if not oldIpVsc in nsgs[oldDatapath].nsg_status.keys():
                            nsgs[oldDatapath].nsg_status[oldIpVsc] = oldNsgStatus
            else:
                #Add to the list if not scanned
                nsgs[oldDatapath] = oldNsg


    # Create CSV Report file
    generateNsgStatusCsv(outputfile, nsgs)

    if report:
        #Send Report email
        sendNsgStatusReport(config["email"], nsgs)
    else:
        #Get NSG in alarm state
        nsgAlarms = {}
        print 'Checking for issues on NSG'
        for nsgIp, nsg in nsgs.iteritems():
            print 'NSG: %s' % (nsg.toStr())
            if nsg.isPartiallyDown() and len(nsg.datapath.strip() ) > 0 :
                print 'NSG Down= %s' % (nsg.toStr())
                nsgAlarms[nsgIp] = nsg

        #Send Alarm email if NSG is down
        sendNsgDownAlarm(config["email"], nsgAlarms)





##################################################################################################################
#
#   MAIN
#
##################################################################################################################


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
    helpString += "    This script will scan VSCs for NSG details\n"
    helpString += "    VSCs are describe in json config file\n"
    helpString += "    - IP\n"
    helpString += "    - Username\n"
    helpString += "    - Password\n"
    helpString += "    - Port\n"
    helpString += "\n"
    helpString += " OPTIONS\n"
    helpString += "    -h, --help      Print this help\n"
    helpString += "    -v, --version   Print this version\n"
    helpString += "    -c, --config    Config file (default: config.json)\n"
    helpString += "    -o, --output    To specify the error file\n"
    helpString += "    --debug         Error output\n"
    helpString += "    -t, --time      Processing time\n"
    helpString += "\n"
    helpString += " EXAMPLES\n"
    helpString += "    To import from a CSV file:\n"
    helpString += "    %s -c config.json\n" % argvs[0]
    helpString += "\n"

    return helpString

def main(argvs):
    global DEBUG, TIME

    argv = argvs[1:]

    configfile =  '%s/config.json' % ( SCRIPT_PATH )
    outputfile =  '%s/nsg_status.csv' % ( SCRIPT_PATH )
    report = False

    try:
        opts, args = getopt.getopt(
            argv, "thvc:o:r", ["time","help", "debug", "config=", "output=", "report"])
    except getopt.GetoptError:
        print printHelp(argvs)
        sys.exit(2)

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
        elif opt in ("-c", "--config"):
            configfile = arg
        elif opt in ("-o", "--output"):
            outputfile = arg
        elif opt in ("-r", "--report"):
            report = True
           

    print "Input File: %s" % configfile
    print "Output File: %s" % outputfile
    print "Debug: %s" % DEBUG

    getNsgStatus(configfile, outputfile, report)





if __name__ == "__main__":
    SCRIPT_PATH = str( os.path.dirname(os.path.realpath(__file__)) )

    startTime = time.time()
    START_TIME = time.strftime("%D %H:%M:%S", time.localtime(startTime))
    main(sys.argv)
    endTime = time.time()

    if TIME:
        duration = endTime - startTime
        print 'Start: %s     End: %s\nDuration: %s' % (
                time.strftime("%H:%M:%S", time.localtime(startTime)),
                time.strftime("%H:%M:%S", time.localtime(endTime)),
                datetime.timedelta(seconds=duration) )
        print 'Processed Items: %s' % PROCESSED_ITEMS
