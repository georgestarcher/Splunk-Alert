# Splunk Alert Script Template and Example

## Files:
1. credentialsFromSplunk.py: a wrapper class to take a valid Splunk session key and retrieve a set of credentials saved within a specified Splunk app context
2. targetlist.py: a class intended as an IP address list handler. Takes a path to Splunk alert results and extracts the first column assuming it is a list of IPv4 addresses
3. gsheet.py: a home brew class for sending Splunk alert results to a defined google spreadsheet. You have to edit the expected columns in this class right now.
4. alert_to_gsheet.py: an alert script called by a Splunk alert that uses the credentialsFromSplunk and gsheet classes.
5. alert_script.py: an example alert script that calls a placeholder IPS class as if you were controlling a network IPS via it's own Python class wrapper to Rest API calls.

## Summary:

The combination of the credentialsFromSplunk.py, gsheet.py and alert_to_gsheet.py will function if properly configured with Splunk. It is meant as a demonstration of sending Splunk alert detail data to a system external to Splunk.

The combination of the credentialsFromSplunk.py, targetlist.py and alert_cscript.py can work to control a network IPS if you provide the interfacing Python class to make the matching IPS Rest API calls. 

This code is meant to go along with the explanation on my personal blog at georgestarcher.com.

## Requirements:

###alert_to_gsheet.py

* Installation the google gdata Python SDK src subfolders (atom and gdata) folders into your $SPLUNK_HOME/lib/Python2.7/site-packages/
* Your Splunk instance can reach Google
* You have a valid google credential for this purpose that has permissions to the spreadsheet mentioned below
* You have created a Google Spreadsheet named "Splunk Test" with the columns:Date,IP,Post
* You really want to put this hopefully non sensitive data into Splunk.
* These Python files are expected to be placed together in the $SPLUNK_HOME/bin/scripts/ folder
* The default settings are assuming you have created a Splunk App named myadmin and used the setup.xml method to save your google credentials into the app for retrieval by these scripts. This is so credentials are stored encrypted not in the clear in these scripts

###alert_script.py

* That you have written your own Python class wrapping REST API calls to your IPS matching what I in this script
* Keep in mind this won't work on it's own, it is provided as an example. See point above
* It and the credentialsFromSplunk.py and targetlist.py are expected to be placed together in the $SPLUNK_HOME/bin/scripts/ folder
* Yo have created valid credentials within a Splunk app and edited the script variables appropriately for service user account name, the realm name etc that you used

###BOTH alert scripts

* You may need to edit the hashbang at the top of each alert script file to match the path to the python folder of your particular Splunk install. The default I have is assuming its installed on Unix to the default Splunk location
* You may need to edit the path to the Splunk log folder for the path to write the optional debug file
* If you want to use the debug change the debug flag to 1 from 0

