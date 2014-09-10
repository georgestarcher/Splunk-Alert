#!/opt/splunk/bin/python

import os
import sys
import logging as logger
import time
import urllib, urllib2
from emailSplunkXARF import *
from mako.template import Template
from email.mime.text import MIMEText
from abuselist import *

__author__ = "george@georgestarcher.com (George Starcher)"
_MI_APP_NAME = 'Alert-To-XARF'


#SYSTEM EXIT CODES
_SYS_EXIT_FAILED_SPLUNK_AUTH = 7
_SYS_EXIT_FAILED_ABUSE_FILE = 8 
_SYS_EXIT_FAILED_EMAIL = 9

#OUTPUT OPTIONS
_DEBUG = 0 
_LOG_ACTION = 1

# Setup Alert Script Logging File: will be picked up into index=_internal
os.umask(0)
outputFileName = _MI_APP_NAME+'-log.txt'
outputFileLog = os.path.join(os.environ['SPLUNK_HOME'],'var','log','splunk',outputFileName)
logger.basicConfig(format='%(asctime)s %(levelname)s %(message)s', filename=outputFileLog, filemode='a+', level=logger.INFO, datefmt='%Y-%m-%d %H:%M:%S %z')
logger.Formatter.converter = time.gmtime

# X-ARF See Specification: https://github.com/abusix/xarf-specification/blob/master/xarf-specification_0.2.md
# set xArtAttachment to "none" if you do not wish to attach the evidence sample
# we set the reported from and domain to our information, and type of report to login-attack/auth to match our search on ssh abuse
# port and sourcetype are set to 22 for ssh and ipv4 as we are dealing with normal ip addresses causing the abuse

# Intial Setup: Change the following values for your environment
# xArfReportedFrom = the reply to/from of the emailed abuse report
# xArfReportingDomain = your organization's domain name
# xArfReportCC = set this to your xArfReportedFrom if you want to archive copies otherwise set it to an empty string ""
# xArfAttachment = text/plain; will result in the sample evidence log attachment, Choosing None; will disable attaching sample logs

xArfType = "PLAIN"
xArfReportedFrom = "abuse@mydomain.local"
xArfReportingDomain = "mydomain.local"
xArfReportCC = xArfReportedFrom
xArfReportID = "%s@%s" %(time.time(),xArfReportingDomain)
xArfReportType = "login-attack"
xArfCategory = "auth"
xArfAttachment = "text/plain"
xArfUserAgent = "X-ARF Reporting"
xArfSchemeURL = "http://www.x-arf.org/schema/abuse_login-attack_0.1.0.json"
xArfPort = "22"
xArfSourceType = "ipv4"
xArfVersion = "0.2"
xArfTLP = "green"

# Location of the mako email body template for the Abuse Human Readable email body
mail_template = os.path.join(os.environ['SPLUNK_HOME'],'bin','scripts','templates','xarf-abuse.tmpl')

# Functions

def versiontuple(v):
        return tuple(map(int, (v.split("."))))

def logDebug(s):
	""" print any extra debug info """
	if _DEBUG:
		logger.info("script="+_MI_APP_NAME+" %s" % str(s))
    
def logError(s):
	""" print any errors that occur """
	logger.error("script="+_MI_APP_NAME+" %s" % str(s))

def logAction(s):
	""" log events to show normal activity of the alert script """
	if _LOG_ACTION:
		logger.info("script="+_MI_APP_NAME+" %s" % str(s))

def getSplunkVersion(sessionKey):
	""" function to obtain the Splunk software version. This is used to determine parsing of the sessionKey """

	from xml.dom import minidom

	base_url = 'https://localhost:8089'

	request = urllib2.Request(base_url + '/services/server/info',None,headers = { 'Authorization': ('Splunk %s' %sessionKey)})
	server_content = urllib2.urlopen(request)
	serverDoc = minidom.parseString(server_content.read())
	entryInfo = serverDoc.getElementsByTagName('entry')
	key_nodes = entryInfo[0].getElementsByTagName('content')[0].getElementsByTagName('s:key')
	nodes = filter(lambda node: node.attributes['name'].value == 'version', key_nodes)
	version = nodes[0].firstChild.nodeValue

	return(version)

def getSplunkUser(sessionKey):
        """ function to obtain the Splunk software version. This is used to determine parsing of the sessionKey """

        from xml.dom import minidom

        base_url = 'https://localhost:8089'

        request = urllib2.Request(base_url + '/services/authentication/current-context',None,headers = { 'Authorization': ('Splunk %s' %sessionKey)})
        server_content = urllib2.urlopen(request)
        serverDoc = minidom.parseString(server_content.read())
        entryInfo = serverDoc.getElementsByTagName('entry')
        key_nodes = entryInfo[0].getElementsByTagName('content')[0].getElementsByTagName('s:key')
        nodes = filter(lambda node: node.attributes['name'].value == 'username', key_nodes)
        username = nodes[0].firstChild.nodeValue

        return(username)

def exitAlertScript(a):
	if _DEBUG:
		logDebug("action=stopped")
	sys.exit(a)

if __name__ == "__main__":

	if _DEBUG:
		logDebug("action=started")

# Obtain the Splunk authentication session key

        # read session key sent from splunkd 
	sessionKey = sys.stdin.readline().strip()

	if len(sessionKey) == 0:
        	logError("Did not receive a session key from splunkd. ")
	        exitAlertScript(_SYS_EXIT_FAILED_SPLUNK_AUTH)

# Adjust the returned sessionKey text based on Splunk version

	splunkVersion = getSplunkVersion(sessionKey)

	if versiontuple(splunkVersion) < versiontuple("6.1.1"):
		sessionKey = sessionKey[11:]
	else:
		sessionKey = urllib.unquote(sessionKey[11:]).decode('utf8')	

	logDebug("sessionKey="+sessionKey)
	logDebug("splunkVersion="+splunkVersion)

# Obtain the alert events, then the optional evidence sample for each alert result row 

        alertEventsFile = os.environ['SPLUNK_ARG_8']

        try:
                alertAbuseList = abuseList(alertEventsFile)
        except Exception, e:
                logError("type=AlertFileError error=%s" % str(e))
                exitAlertScript(_SYS_EXIT_FAILED_ALERT_FILE)

        if xArfAttachment=="text/plain":
	        logDebug("action=FetchEvidence")
            _alertScriptServiceAccount = getSplunkUser(sessionKey)
                try:
                       for abuseEvent in alertAbuseList.abuselist:
                           search_query = abuseEvent.getEvidence(_alertScriptServiceAccount,sessionKey)
                           logDebug("evidence=%s " % str(abuseEvent.evidence))
                except Exception, e:
                        logError("type=GetEvidenceError error=%s" % str(e))

# Send abuse email for each row in the alert results table
	try:
                emailXARFQueue = emailSplunk(sessionKey)
                emailBodyTemplate = Template(filename=mail_template)
        except Exception, e:
                logError("type=SplunkMailInitializationError error=%s" % str(e))
                exitAlertScript(_SYS_EXIT_SPLUNK_EMAIL)

        for abuseEvent in alertAbuseList.abuselist:
                try:
                       emailXARFQueue.humanPart = MIMEText(emailBodyTemplate.render(startTime=abuseEvent.startTime, endTime=abuseEvent.endTime, numUsers=abuseEvent.numUsers, ip=abuseEvent.source, sourcename=abuseEvent.sourceName, city=abuseEvent.city, region=abuseEvent.region, country=abuseEvent.country, count=abuseEvent.count, users=abuseEvent.users, service=abuseEvent.app, target=abuseEvent.target))
		       emailXARFQueue.message['Subject'] = "abuse report about "+abuseEvent.source+" - "+abuseEvent.startTime
                       emailXARFQueue.message['From'] =  xArfReportedFrom
                       emailXARFQueue.message['To'] = abuseEvent.contact
		       emailXARFQueue.message['Cc'] = xArfReportCC
		       emailXARFQueue.message.add_header('X-ARF','YES')
		       emailXARFQueue.message.add_header('Auto-Submitted', 'auto-generated')
		       emailXARFQueue.message.add_header('X-XARF', xArfType)
		       emailXARFQueue.jsonReport['Reported-From'] = xArfReportedFrom
		       emailXARFQueue.jsonReport['Report-ID'] = xArfReportID 
		       emailXARFQueue.jsonReport['Date'] = abuseEvent.endTime
		       emailXARFQueue.jsonReport['Report-Type'] = xArfReportType
		       emailXARFQueue.jsonReport['Category'] = xArfCategory
		       emailXARFQueue.jsonReport['Service'] = abuseEvent.app
		       emailXARFQueue.jsonReport['User-Agent'] = xArfUserAgent 
		       emailXARFQueue.jsonReport['Source'] = abuseEvent.source
		       emailXARFQueue.jsonReport['Source-Type'] = xArfSourceType 
                       emailXARFQueue.jsonReport['Port'] = xArfPort
		       emailXARFQueue.jsonReport['Occurences'] = abuseEvent.count
		       emailXARFQueue.jsonReport['Attachment'] = xArfAttachment 
		       emailXARFQueue.jsonReport['TLP'] = xArfTLP
		       emailXARFQueue.jsonReport['Version'] = xArfVersion
		       emailXARFQueue.jsonReport['Scheme-URL'] = xArfSchemeURL 
                       emailXARFQueue.evidence = abuseEvent.evidence
              	       emailXARFQueue.sendEmail()
		       actionNotification = "reportID="+xArfReportID+" app="+abuseEvent.app+" category="+xArfCategory+" src_ip="+abuseEvent.source+" abuseContact="+abuseEvent.contact+" dest_ip="+abuseEvent.target+" occurences="+abuseEvent.count
		       logAction("action=sent %s" % str(actionNotification))
		       emailXARFQueue.resetMessage()
                except Exception, e:
                        logError("type=SplunkMailError error=%s" % str(e))
                        exitAlertScript(_SYS_EXIT_SPLUNK_EMAIL)


	exitAlertScript(0)

