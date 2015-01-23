"""ips.py
    IPS Rest API interface class
    Error/Status messages stored in the .status attribute of the instantiated object
"""


import urllib, urllib2
import base64
import sys

class ips:

    """ips object: 
        
        Attributes:
        
            mgmt_address -- the ip address or resolvable dns name for the IPS management server
            username -- the username to log into mgmt with
            password -- the password to log into mgmt with
            policy_name -- the active response policy name to be controlled
            status --  has value OK if the connection and credentials test succesfully
    """

    def __init__(self, mgmt_address, username, password, policy_name=""):   
        self.mgmt_address = mgmt_address
        self.username = username
        self.password = password
        self.policy_name = policy_name
        self.status = "unknown"

        self.getStatus()
            
    def __str__(self):
        """Function Override: Print IPS object
        """
        
        return 'MGMT ADDRESS:%s Username:%s Password:%s Status:%s'% (self.mgmt_address,self.username,self.password,self.status)

    def urlAction (self, url):
        """Function: call the REST API URL with the stored authentication credentials
        """

        username = self.username
        password = self.password

        request = urllib2.Request(url)
        base64string = base64.encodestring('%s:%s' % (username, password)).replace('\n', '')
        request.add_header("Authorization", "Basic %s" % base64string)
        result = urllib2.urlopen(request)

        return result.read()

    def getStatus(self):
        """Function: call the status REST API URL to confirm credentials and system response.
            expected response is OK
        """

        url = "https://"+self.mgmt_address+"/dbAccess/tptDBServlet?method=Status"

        try:
            self.status=self.urlAction(url) 

        except Exception, e:
            raise Exception, "%s" % str(e)  
            
    def removeQuarantine(self, target_ip):
        """Function: call the remove from Active Response Quarantine REST API URL
            currently coded only for ip addresses not domain names.
        """

        ip_arg = urllib.urlencode({'ip':target_ip}) 
        url = "https://"+self.mgmt_address+"/quarantine/unquarantine?"+ip_arg

        try:
            self.status=self.urlAction(url)
        
        except Exception, e:
            raise Exception, "%s" % str(e) 

    def addQuarantine(self, target_ip):
        """Function: call the add to Active Response Policy Quarantine REST API URL
            currently coded only for ip addresses not domain names
            currently coded to not provide a duration override, it will default to the one for the policy.
        """

        ip_arg = urllib.urlencode({'ip':target_ip})
        policy_arg = urllib.urlencode({'policy':self.policy_name})
        url = "https://"+self.mgmt_address+"/quarantine/quarantine?"+ip_arg+"&"+policy_arg

        try:
            result = self.urlAction(url)
        except Exception, e:
            raise Exception, "%s" % str(e) 


def main():

    #Sample active response policy name, yours may vary
    policy_name = "Quarantine SSH Attempts"

    username = 'testuser'
    password = 'testpassword'
    mgmt_address = 'ipaddress'
    target = sys.argv[1]

    test_ips = ips(mgmt_address, username, password, policy_name)
    test_ips.addQuarantine(target)

    print test_ips

if __name__ == "__main__":

    main()
