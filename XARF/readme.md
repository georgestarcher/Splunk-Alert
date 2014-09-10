#Welcome to the Splunk X-ARF Alert Script Project

Please note you have been provided an early release of this project. It is subject to change. Do not share it outside your organization without contacting george@georgestarcher.com The materials, code, etc will be publicly released in conjunction with a talk on Alert Script Automation at the Splunk user conference .conf 2014. If you have any feedback, requests or bug reports please contact george@georgestarcher.com

**All materials in this project are provided under the MIT software license. See license.txt for details.**

[X-ARF is the Extended Abuse Reporting Format][1]. The provided search will enable you to trigger the alert script that generates and emails an abuse report for each matching events.

The scripts are intended to provide a working educational code base that can be built upon to provide any desired X-ARF compliant abuse notifications from Splunk. The scripts are specifically setup to handle authentication ssh abuse reporting leveraging the [Splunk Common Information model][3].

##Risks of Usage:
There are some risks to automated abuse reporting. The abuse contact information that abuse emails are sent to come from the Abusix contact database. This is the same method used in the complaint option of fail2ban. I make no claims on the veracity or accuracy of that information. In some cases I have observed abuse contact information is directed to an email box for spam collection and automatic reporting to realtime blacklist systems. So there is some chance of placing your email gateway onto a blacklist as a spammer and abuser for trying to report abuse. Ironic I know. I recommend you setup a email relay gateway explicitly for the purpose of sending automated abuse reports so that your main business email gateways do not get blacklisted and impact your business. You have been warned.

The abuseContact lookup depend on DNS lookups. You should consider carefully what volume of matches you will get against the main search generating the alerts that drive the alert script. You can find more discussion on DNS caching at: [http://www.georgestarcher.com/splunk-dns-lookup-performance-and-caching-with-dnsmasq/][4]

##Email Gateway:
The current version of this code obtains the mail gateway settings from Splunk's email settings. I will be adding a manual override option soon. 

##Installation of the Scripts:
1. You must have setup the abuseContact lookup as detailed at: [http://www.georgestarcher.com/splunk-a-dns-lookup-for-abuse-contacts/][2]
2. You must have the dnsLookup setup in Spunk. See the external lookup example at [http://docs.splunk.com/Documentation/Splunk/6.1.3/Knowledge/Addfieldsfromexternaldatasources][5]
3. Create the folder $SPLUNK_HOME/bin/scripts/templates 
4. Copy the xarf-abuse.tmpl file into the templates folder from step 2 above. This is the Python Mako Template for the abuse email body. You can modify the mail wording in this template if desired.
5. Copy the python scripts:alert_to_xarf.py, emailSplunkXARF.py, abuselist.py into $SPLUNK_HOME/bin/scripts
6. Edit the script alert_to_xarf.py to set the options listed in the next section

##Configuration of the options:
You must change the following in the script alert_to_xarf.py.

###_alertScriptServiceAccount:
Fill in the Splunk Username that the driving alert search/script will be scheduled to run under. I typically use a "service account" for alerts so I do not have to worry about ownership of Splunk knowledge objects when staff leaves the company. I will add code in the future to automatically determine the user account name that triggered the script and use it.

###xArfReportedFrom:
You must set this value to be the email address you wish the abuse reports to be sent "from." This may be your own abuse contact email so you can receive valid resolution replies. Or you might consider a no reply address if you never wish to see valid replies, email delivery failure notices, etc. You may control having outgoing abuse reports CC'd to your reportedFrom address by XYZ.

###xArfReportingDomain:
Set this to your domain only.

###xArfReportCC:
Leave this set to xArfReported from if you want the report email CC'd to your abuse contact address.
Change it to another address if desired, or a null string like "" if no CC is wanted.

###xArfAttachment:
Leave the default of "text/plain" if you want the sample log events attached to the report. Per X-arf mime 3 part.

##Other options:
By default the number of sample evidence attached is up to 15. If you wish to change it you will need to add the value to the abuseEvent.getEvidence call in alert_to_xarf.py script. 
Example:
search_query = abuseEvent.getEvidence(_alertScriptServiceAccount,sessionKey,"10")

##The Searches:
You are assumed to have Splunk Universal Forwarders collecting your Unix/Linux logs and maybe SSH attempts against network gear collected. These logs MUST be processed against the Common Information Model for the provided searches to work. We are reporting against tag=authentication action=failure app=sshd.

We also assume you have your hosts properly filling in the host field of their logs with a clean FQDN that you can reverse DNS lookup against to get their IP. This will be necessary since typical unix ssh logs don't specify the targeted IP address and we need to be able to report that to the abusing source contact.

###The Alert Search:

You will need to schedule this search and make it trigger alert_to_xarf.py once per search. I have been running my alert hourly.

The following search is what generates our abuse reporting driver events. 
We first search for any sshd failures based on the common information model. 
Drop out a desired source IP range such as our own space. 
Next build the earliest and latest times abuse events started. 
Set our abuse threshold at 4 failures. 
Lookup the abuse contact.
Handle all the DNS/IP information.
Get IP location information.
Format our abuse table.
Drop out any events where abuseContact has spam in the name. This is to reduce sending reports to a spam bucket that reports you to blacklists.

> tag=authentication action=failure app=sshd NOT src_ip=10.0.0.0/8  | stats count values(user) AS Users first(_time) AS EndTime last(_time) AS StartTime by src_ip, host, app | where count>4 | lookup abuseLookup ip AS src_ip| lookup dnsLookup ip AS src_ip OUTPUT hostname AS src_hostname | eval src_hostname=if(isNull(src_hostname),"unknown",src_hostname) | lookup dnsLookup hostname AS host OUTPUT ip AS dest_ip  | eval dest_host=host | iplocation src_ip  | eval StartTime=strftime(StartTime,"%Y-%m-%d %T %z") | eval EndTime=strftime(EndTime,"%Y-%m-%d %T %z") | eval City=if(isNull(City),"unknown city",City) | eval Region=if(isNull(Region),"unknown region",Region) | eval Country=if(isNull(Country),"unknown country",Country)| eval DistinctUserNames=mvcount(Users) | table src_ip, src_hostname, City, Region, Country, abusecontact, StartTime, EndTime, dest_ip, dest_host, app, count, DistinctUserNames, Users | search dest_ip=* NOT abusecontact=*spam*

###The Evidence Search:
If you have allowed the default action of attaching sample log events to the report the search events are used to make a rest api call back into Splunk to search and attach those events. The search is in the script abuselist.py in the getEvidence function. We actually swap out the timestamp at the front of the raw events with the same timestamp adding timezone information needed to report the abuse accurately. You can see the code if you wish.

> search_query = 'search tag=authentication action=failure app=sshd src_ip='+self.source+' earliest="'+earliestTimestamp+'" latest="'+latestTimestamp+'" | head '+numEvents+' | eval eventTime=strftime(_time,"%Y-%m-%d %T %z") | eval eventLog=substr(_raw,timeendpos+1) | eval eventDetail=eventTime+" "+eventLog | table eventDetail'

##Viewing script activity in Splunk Logs:
There are two logging options for the alert script. The are controlled in the Output Options section at the top of alert_to_xarf.py.
The log file is written to $SPLUNK_HOME/splunk/var/log/splunk as Alert-To-XARF-log.txt
If Splunk is picking up logs properly you can search in Splunk like: 
> index=_internal script='Alert-To-XARF' NOT StreamedSearch action=sent | timechart span=1h count AS ReportsSent

* Setting _DEBUG to 1 will provide various messages such as the script starting etc. Anywhere you see a doPrint is a debug message. This is useful when first setting up the alerting or if you start modifying this code for other alerts.
* Leaving _LOG_ACTION at 1 will ensure an event is logged for each report sent out. This will let you dashboard report sending activity. Look for the logAction if interested.
* Errors are always logged.

Good Luck and Happy Abuse Reporting!

[1]: http://www.x-arf.org
[2]: http://www.georgestarcher.com/splunk-a-dns-lookup-for-abuse-contacts/
[3]: http://docs.splunk.com/Documentation/CIM/latest/User/Overview
[4]: http://www.georgestarcher.com/splunk-dns-lookup-performance-and-caching-with-dnsmasq/
[5]: http://docs.splunk.com/Documentation/Splunk/6.1.3/Knowledge/Addfieldsfromexternaldatasources