#!/opt/splunk/bin/python

import os
import sys
from targetlist import * 
from credentialsFromSplunk import *
from ips import *
import logging

__author__ = "george@georgestarcher.com (George Starcher)"
_MI_APP_NAME = 'Alert-Script'

#SYSTEM EXIT CODES
_SYS_EXIT_FAILED_SPLUNK_AUTH = 7
_SYS_EXIT_FAILED_TP = 8 
_SYS_EXIT_FAILED_TARGET_FILE = 9

#OUTPUT OPTIONS
_DEBUG = 0 

# Set up logging suitable for splunkd consumption
logging.root
logging.root.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(levelname)s %(message)s')
handler = logging.StreamHandler()
handler.setFormatter(formatter)
logging.root.addHandler(handler)

# OUTPUT FILES
os.umask(0)
if _DEBUG:
	outputFileDebug = '/opt/splunk/var/log/splunk/'+_MI_APP_NAME+'-debug.txt'
	debugFile = open(outputFileDebug, 'w')


# Functions

def doPrint(s):
	""" A wrapper Function to output data by same method (print vs sys.stdout.write)"""
    	sys.stdout.write(s+"\r\n")
	if _DEBUG:
		debugFile.write(s+"\r\n")
    
def print_error(s):
	""" print any errors that occur """
	doPrint("<error><message>%s</message></error>" % str(s))
	logging.error(s)

def logAction(s):
	""" option action logging """
	doPrint(s)

def exitAlertScript(a):
	if _DEBUG:
		doPrint("Stopping: "+_MI_APP_NAME)
		outputFileDebug.close()
	sys.exit(a)

if __name__ == "__main__":

	if _DEBUG:
		doPrint("Starting: "+_MI_APP_NAME)

# Define the source in Splunk for the stored credential

	splunkapp = "myadmin"
	realm = 'ips'
	username = 'splunk'

# Obtain the Splunk authentication session key

        # read session key sent from splunkd 
        sessionKey = sys.stdin.readline().strip()

        if len(sessionKey) == 0:
        	print_error("Did not receive a session key from splunkd. ")
		exitAlertScript(_SYS_EXIT_FAILED_SPLUNK_AUTH)

	doPrint("session key: "+sessionKey)

# Define the tipping point connection

        ipsCredential = credential(splunkapp,realm,username)
        policy_name = "Quarantine SSH Attempts"
	ips_ip = 'ipaddress'

# Get the stored credential from Splunk

	try:
		ipsCredential.getPassword(sessionKey)
	except Exception, e:
		print_error("Splunk Credential Error: %s" % str(e))
		exitAlertScript(_SYS_EXIT_FAILED_SPLUNK_AUTH)

# Active the ips connection object	
	try:
		ssh_ips = ips(ips_ip,ipsCredential.username, ipsCredential.password,policy_name)
	except Exception, e:
	        print_error("IPS Error: %s" % str(e))
		exitAlertScript(_SYS_EXIT_FAILED_IPS)	

# Obtain the path to the alert events compressed file

        alertEventsFile = os.environ['SPLUNK_ARG_8']

	try:
		alertTargetList = targetlist(alertEventsFile)
	except Exception, e:
		print_error("Target File Error: %s" % str(e))
		exitAlertScript(_SYS_EXIT_FAILED_TARGET_FILE)

# Quarantine each source ip in the alert results table

	for address in alertTargetList.targetlist:
		try:
			ssh_ips.addQuarantine(address)
		except Exception, e:
			print_error("IPS Quarantine Error: %s" % str(e))
			exitAlertScript(_SYS_EXIT_FAILED_IPS)

	exitAlertScript(0)

