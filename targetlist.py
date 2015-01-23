"""targetlist.py
    Target List Class file
    Yeah it is overkill for just flipping through a list. But may want to add some self validation later for the types
        of addresses.
"""

# define target object
class target:
    """target List Object:

        Attributes:

            target -- the target value
            type -- fqdn, ipv6 or ipv4
    """

    def __init__(self,target,type='ipv4'):
        # default type to ipv4 assuming incoming ipv4 ip address
        self.target = target
        self.type = type

    def __str__(self):
        """Function Override: return target value 
        """
        
        return self.target

# define targetlist object
class targetlist:
    """Target List object:

        Attributes:

            targetlist -- the list of all contained targets 
            description -- description of the list

    """

    def __init__(self, eventResultsPath, skip="yes", desc="unknown"):

        import csv
        import gzip

        self.targetlist = []
        self.filepath = eventResultsPath
        self.description = desc
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

        # Send a notification for each source ip in the alert results table
        for line in eventIterator:
            self.targetlist.append(target(line[0]))

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
        desc = "test"

    try:
        testList = targetlist(filePath, skip, desc)
    except Exception, e:
        raise Exception, "'%s'" % str(e)

    for ip in testList.targetlist:
        print str(ip)

if __name__ == "__main__":

    main()

