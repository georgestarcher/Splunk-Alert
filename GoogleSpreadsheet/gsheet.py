"""gsheet.py
    Google Spreadsheet interface class
    Note that right now the dictionary mapping is defined and handled here rather than in the alert script that calls it
    see the loadData() function
"""

import sys
import gdata.docs
import gdata.docs.service
import gdata.spreadsheet.service
import re, os

class spreadsheet:

    """spreadsheet object: 
        
        Attributes:
            username -- the google user name    
            password -- the password to the google account 
            name -- the document name
            spreadsheetID -- the Google API spreadsheet ID retrieved by matching the document name
            worksheetID -- the Google API worksheet ID within the spreadsheet, assumed to be first sheet
    """

    def __init__(self, username, password, name):   
        self.username = username
        self.password = password
        self.name = name
        self.client = ""
        self.spreadsheetID = ""
        self.worksheetID = ""
        self.listFeed = ""
        self.rows = ""

        self.open()
            
    def __str__(self):
        """Function Override: Print spreadsheet contents 
        """

        print 'Spreadsheet ID:%s' % (self.spreadsheetID)
        print 'Worksheet ID:%s' % (self.worksheetID)

        for line in self.rows:
            print line              
        return("\r\n")

    def read (self):
        """Function: Pull in all the rows 
        """

        self.rows = self.listFeed.entry

    def addData(self, dataDict):
        """Function: Insert the data in dict format to the google spreadsheet
        """

        entry = self.client.InsertRow(dataDict, self.spreadsheetID, self.worksheetID)

    def open(self):
        """Function: Open the google spreadsheet and read in the data 
        """

        # Connect to Google
        self.client = gdata.spreadsheet.service.SpreadsheetsService()
        self.client.email = self.username
        self.client.password = self.password
        self.client.source = 'spreadsheet.py' 
        self.client.ProgrammaticLogin()

        q = gdata.spreadsheet.service.DocumentQuery()
        q['title'] = self.name
        q['title-exact'] = 'true'
        feed = self.client.GetSpreadsheetsFeed(query=q)
        self.spreadsheetID = feed.entry[0].id.text.rsplit('/',1)[1]
        feed = self.client.GetWorksheetsFeed(self.spreadsheetID)
        self.worksheetID = feed.entry[0].id.text.rsplit('/',1)[1]
        self.listFeed = self.client.GetListFeed(self.spreadsheetID, self.worksheetID)

        try:
            self.read()

        except Exception, e:
            raise Exception, "%s" % str(e)  

    def loadData(self, eventResultsPath, skip="yes"):
        """Function: take the gzip Splunk results file, extract and build the data dict for the spreadsheet
            assumes the output from the Splunk alert matches the dict format defined here
        """

        import csv
        import gzip
        import datetime
    
        filepath = eventResultsPath
        skipheader = skip

        # Handle to the csv contents of the alerts events compressed file

        try:
            eventContents = csv.reader(gzip.open(filepath, 'rb'))

        except Exception, e:
            raise Exception, "%s" % str(e)

        eventIterator = iter(eventContents)

        #skip header makes it skip past the first row to account for column header coming from Splunk search results
        if skipheader == "yes":
            eventIterator.next()

        # Build the alert results dict and add to the google spreadsheet
        for line in eventIterator:
            dataDict = {}
            dateTime = datetime.datetime.fromtimestamp(float(line[0]))
            dataDict['date'] = dateTime.strftime("%Y-%m-%d %I:%M:%S")
            dataDict['ip'] = line[2]
            dataDict['post'] = line[4]
            self.addData(dataDict)
        
def main():
    import getopt
    
    """ Define the google spreadsheet name for testing. A spreadsheet by this name must exist in the google account
    """

    name = "Splunk Test"
    username = ''
    password = ''

    # parse command line options
    try:
        opts, args = getopt.getopt(sys.argv[1:], "", ["user=", "pw="])
    except getopt.error, msg:
        print 'python gsheet.py --user [username] --pw [password] '
        sys.exit(2)

    # Process options
    for o, a in opts:
        if o == "--user":
            username = a
        elif o == "--pw":
            password = a

    if username == '' or password == '':
        print 'python gsheet.py --user [username] --pw [password] '
        sys.exit(2)
    
    test_spreadsheet = spreadsheet(username, password, name)

    print test_spreadsheet

if __name__ == "__main__":

    try:
        main()
    except Exception, e:
        raise Exception, "%s" % str(e)

