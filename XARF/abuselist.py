"""abuselist.py
	Abuse List Class file
"""

# define target object
class abuseEvent:
	"""Abuse Event Object:

		Attributes:

			startTime -- the time of the first abuse event for the source IP
			endTime -- the time last seen for abuse events for the source IP
			source -- the source IP of the abuse
			sourceName -- the FQDN reverse DNS lookup of the source
			city -- the City geolocation of the source
			region -- the Region/State geolocation of the source
			country -- the County geolocation of the source
			app -- the service being abused: example sshd. recommend using Splunk Common Information Model to ensure app field is populated properly
			target -- the host being targeted for abuse
			count -- the number of abuse occurances in the alert time period
			numUsers -- the number of distinct usernames attempted in the authentication abuse
			users -- the string list of attempted usernames
			contact -- abuse contact email
			evidence -- the list of retrieved evidence sample logs
	"""

	def __init__(self,source,sourceName,city,region,country,app,contact,startTime,endTime,target,count,numUsers,users):
		self.startTime = startTime
		self.endTime = endTime
		self.source = source
		self.sourceName = sourceName
		self.city = city
		self.region = region
		self.country = country
		self.app = app
		self.target = target
		self.count = count
		self.numUsers = numUsers
		self.users = users
		self.contact = contact
		self.evidence = [] 

	def getEvidence(self, username, sessionKey, numEvents="15"):
		"""Function getEvidence: uses session key to obtain a number of log events as evidence.
		"""

		import datetime 
		import urllib, urllib2
		from xml.dom import minidom

		base_url = 'https://localhost:8089'

	        # convert the timestamps from the search results into search command format friendly for earliest and latest

		tempTimeEarliest = datetime.datetime.strptime(self.startTime[:-6], "%Y-%m-%d %H:%M:%S")
		tempTimeLatest = datetime.datetime.strptime(self.endTime[:-6], "%Y-%m-%d %H:%M:%S")

		earliestTimestamp = tempTimeEarliest.strftime("%m/%d/%Y:%H:%M:%S")
		latestTimestamp = tempTimeLatest.strftime("%m/%d/%Y:%H:%M:%S")

	        # define the search query template we need to get evidence logs filing in time range and desired source ip
	        # note in the search we replace the original timestamp with full one with time zone to help for abuse reporting

                search_query = 'search tag=authentication action=failure app=sshd src_ip='+self.source+' earliest="'+earliestTimestamp+'" latest="'+latestTimestamp+'" | head '+numEvents+' | eval eventTime=strftime(_time,"%Y-%m-%d %T %z") | eval eventLog=substr(_raw,timeendpos+1) | eval eventDetail=eventTime+" "+eventLog | table eventDetail'

	        # make rest api call using sessionKey to obtain the search results and put them into a python list
		request = urllib2.Request(base_url + '/servicesNS/%s/search/search/jobs/export' % (username),
		data = urllib.urlencode({'search': search_query,'output_mode': 'csv'}),
		headers = { 'Authorization': ('Splunk %s' %sessionKey)})
		search_results = urllib2.urlopen(request)
		result_output = search_results.read().replace('"','')
		self.evidence = result_output.split('\n')
		self.evidence.pop(0)

                return(search_query)
	
	def __str__(self):
		"""Function Override: return target value 
		"""
		
		return self.source

# define targetlist object
class abuseList:
	"""Abuse List object:

		Attributes:

			abuselist -- the list of all contained abuse events 

	"""

	def __init__(self, eventResultsPath, skip="yes"):

		import csv
		import gzip

		self.abuselist = []
		self.filepath = eventResultsPath
		self.skipheader = skip

		# Handle to the csv contents of the alerts events compressed file

		try:
        		eventContents = csv.reader(gzip.open(self.filepath, 'rb'))

		except Exception, e:
			 raise Exception, "%s" % str(e)	

		eventIterator = iter(eventContents)
		
		#skip header makes it skip past the first row to account for column header coming from Splunk search results

		if self.skipheader == "yes":
			eventIterator.next()

		#  Add an abuse event for each row of the returned results
	        for line in eventIterator:
			source = line[0]
			sourceName = line[1]
			city = line[2]
			region = line[3]
			country = line[4]
			contact = line[5]
			startTime = line[6]
			endTime = line[7]
			target = line[8]
			app = line[10]
			count = line[11]
			numUsers = line[12]
			users = line[13]
                	self.abuselist.append(abuseEvent(source,sourceName,city,region,country,app,contact,startTime,endTime,target,count,numUsers,users))

	def __str__(self):
		"""Function Override: Print Target List Object
		"""

		return self.targetlist

def main():

	import sys

        if len(sys.argv) < 2:
                raise Exception, "Missing arguments"
        else:
                filePath = sys.argv[1]
                skip = "no"

        try:
                testList = abuseList(filePath, skip)
        except Exception, e:
                raise Exception, "'%s'" % str(e)

        for event in testList.abuseList:
                print event.target

if __name__ == "__main__":

	main()

