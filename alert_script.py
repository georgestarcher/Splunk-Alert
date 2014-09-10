#!/opt/splunk/bin/python

import os
import sys
from targetlist import * 
from credentialsFromSplunk import *
from ips import *
import logging as logger
import time

__author__ = "george@georgestarcher.com (George Starcher)"
_MI_APP_NAME = 'Alert-Script'

#SYSTEM EXIT CODES
_SYS_EXIT_FAILED_SPLUNK_AUTH = 7
_SYS_EXIT_FAILED_TP = 8 
_SYS_EXIT_FAILED_TARGET_FILE = 9

#OUTPUT OPTIONS
_DEBUG = 0
_LOG_ACTION = 1

# Setup Alert Script Logging File: will be picked up into index=_internal
os.umask(0)
outputFileName = _MI_APP_NAME+'-log.txt'
outputFileLog = os.path.join(os.environ['SPLUNK_HOME'],'var','log','splunk',outputFileName)
logger.basicConfig(format='%(asctime)s %(levelname)s %(message)s', filename=outputFileLog, filemode='a+', level=logger.INFO, datefmt='%Y-%m-%d %H:%M:%S %z')
logger.Formatter.converter = time.gmtime

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

if __name__ == "__main__":

	if _DEBUG:
		logDebug("action=started")

# Define the source in Splunk for the stored credential

	splunkapp = "myadmin"
	realm = 'ips'
	username = 'splunk'

# Obtain the Splunk authentication session key

        # read session key sent from splunkd 
        sessionKey = sys.stdin.readline().strip()

        if len(sessionKey) == 0:
        	logError("Did not receive a session key from splunkd. ")
		exitAlertScript(_SYS_EXIT_FAILED_SPLUNK_AUTH)

# Adjust the returned sessionKey text based on Splunk version

        splunkVersion = getSplunkVersion(sessionKey)
        if versiontuple(splunkVersion) < versiontuple("6.1.2"):
                sessionKey = sessionKey[11:]
        else:
                sessionKey = urllib.unquote(sessionKey[11:]).decode('utf8')

        logDebug("sessionKey="+sessionKey)
        logDebug("splunkVersion="+splunkVersion)

# Define the ips connection

        ipsCredential = credential(splunkapp,realm,username)
        policy_name = "Quarantine SSH Attempts"
	    ips_ip = 'ipaddress'

# Get the stored credential from Splunk

	try:
		ipsCredential.getPassword(sessionKey)
	except Exception, e:
		logError("Splunk Credential Error: %s" % str(e))
		exitAlertScript(_SYS_EXIT_FAILED_SPLUNK_AUTH)

# Active the ips connection object	
	try:
		ssh_ips = ips(ips_ip,ipsCredential.username, ipsCredential.password,policy_name)
	except Exception, e:
	        logError("IPS Error: %s" % str(e))
		exitAlertScript(_SYS_EXIT_FAILED_IPS)	

# Obtain the path to the alert events compressed file and load the search results to the list


        alertEventsFile = os.environ['SPLUNK_ARG_8']

	try:
		alertTargetList = targetlist(alertEventsFile)
	except Exception, e:
		logError("Target File Error: %s" % str(e))
		exitAlertScript(_SYS_EXIT_FAILED_TARGET_FILE)

# Quarantine each source ip in the alert results table

	for address in alertTargetList.targetlist:
		try:
			ssh_ips.addQuarantine(address)
		except Exception, e:
			logError("IPS Quarantine Error: %s" % str(e))
			exitAlertScript(_SYS_EXIT_FAILED_IPS)

	exitAlertScript(0)

