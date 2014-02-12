"""credentialsFromSplunk.py
	Credentials Stored in Splunk Credentials Class file
"""

class credential:
	""" Credential object:
		Attributes:

			app: the Splunk app storing the credential
			realm: the system needing the credential
			username: the username for the credential
			password: the credential's password or key

		access the credentials in /servicesNS/nobody/<myapp>/storage/passwords
	"""

	def __init__(self, app, realm, username):	
		self.app = app
		self.realm = realm
		self.username = username
		self.password = "" 

	def __str__(self):
		"""Function Override: Print credential object
		"""
		
		return 'App:%s Realm:%s Username:%s Password:%s\r\n'% (self.app,self.realm,self.username,self.password)

	def getPassword(self, sessionkey):
        	import splunk.entity as entity

		if len(sessionkey) == 0:
			raise Exception, "No session key provided"
		if len(self.username) == 0:
			raise Exception, "No username provided"
		if len(self.app) == 0:
			raise Exception, "No app provided"
		
		# clip the session= text off the session key information sent in via stdio when Splunk calls a script
		sessionKey = sessionkey[11:]

        	try:
        	# list all credentials
                	entities = entity.getEntities(['admin', 'passwords'], namespace=self.app, owner='nobody', sessionKey=sessionKey)
        	except Exception, e:
                	raise Exception, "Could not get %s credentials from splunk. Error: %s" % (self.app, str(e))

        	for i, c in entities.items():
                	if (c['realm'] == self.realm and c['username'] == self.username):
                        	self.password = c['clear_password']
				return

        	raise Exception, "No credentials have been found"

def main():

        import os
        import sys

        sessionKey = 'test'
        realm = 'googledocs'
        app = 'myadmin'
        username = 'googleusername'

        splunkCredential = credential(app,realm,username)
        splunkCredential.getPassword(sessionKey)

        print splunkCredential

if __name__ == "__main__":
	"""You will get an error on importing the Splunk entity class if not run via the Splunk context
		try $SPLUNK_PATH/bin/splunk cmd python credentials.py
		You will still get an error without a valid session key so just expect an error when testiny by hand
	"""
	main()
