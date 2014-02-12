#!/opt/splunk/bin/python

import os
import sys
from credentialsFromSplunk import *
import logging
from gsheet import spreadsheet

__author__ = "george@georgestarcher.com (George Starcher)"
_MI_APP_NAME = 'Alert-To-GoogleSpreadsheet'

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

# OPTIONAL DEBUG OUTPUT FILE
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
	if _LOG_ACTION:
		outputFileAction.write(s+"\r\n")

def exitAlertScript(a):
	if _DEBUG:
		doPrint("Stopping: "+_MI_APP_NAME)
		outputFileDebug.close()
	if _LOG_ACTION:
		outputFileAction.close()
	sys.exit(a)

if __name__ == "__main__":

	if _DEBUG:
		doPrint("Starting: "+_MI_APP_NAME)

# Define the source in Splunk for the stored credential

	splunkapp = "myadmin"
	realm = 'googledocs'
	username = 'googleusername'
	spreadsheet_name = "Splunk Test"

# Obtain the Splunk authentication session key

        # read session key sent from splunkd 
        sessionKey = sys.stdin.readline().strip()

        if len(sessionKey) == 0:
        	print_error("Did not receive a session key from splunkd. ")
		exitAlertScript(_SYS_EXIT_FAILED_SPLUNK_AUTH)

	doPrint("session key: "+sessionKey)

# Define the Google credential

        googleCredential = credential(splunkapp,realm,username)

# Get the stored credential from Splunk

	try:
		googleCredential.getPassword(sessionKey)
	except Exception, e:
		print_error("Splunk Credential Error: %s" % str(e))
		exitAlertScript(_SYS_EXIT_FAILED_SPLUNK_AUTH)

# Active the Google Spreadsheet connection object	
	try:
		alert_spreadsheet = spreadsheet(googleCredential.username, googleCredential.password,spreadsheet_name)
	except Exception, e:
	        print_error("Google Error: %s" % str(e))
		exitAlertScript(_SYS_EXIT_FAILED_TP)	

# Upload the results to the Google Spreadsheet 

        alertEventsFile = os.environ['SPLUNK_ARG_8']

	try:
		alert_spreadsheet.loadData(alertEventsFile)
	except Exception, e:
		print_error("Target File Error: %s" % str(e))
		exitAlertScript(_SYS_EXIT_FAILED_TARGET_FILE)

	exitAlertScript(0)

