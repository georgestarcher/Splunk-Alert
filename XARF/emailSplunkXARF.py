"""emailSplunkXARF.py
    Mail Settings and Sending Class to send X-ARF Reports to Abuse Contacts
    http://www.x-arf.org/index.html
"""
import email

class emailSplunk:
    """ emailConnection Object:
        Attributes:

            server: the email smtp gateway server to send mail through
            sender: the from address to send email as
            use_ssl: to use SSL with the smtp mail gateway
            use_tls: to use TLS wih the smtp mail gateway
            username: the username to use with authenticated smtp if required
            password: the password to use with authenticated smtp if required
            sessionKey: the Splunk session key used to obtain the email settings from Splunk
            message: the multipart MIME email message to be sent
            humanPart: the human readable MIME body of the email message to be sent
            jsonReport: the X-ARF MIME part two required json information being reported
            evidence: the optional evidence events for the X-ARF MIME part three

        Object is initialized with a Splunk sessionKey to populate the mail settings from Splunk.
        External code sets the MIME parts and then calls a send. If mulitple messages are to be sent via this connection object, call the resetMessage method between messages.
    """

    def __init__(self, sessionKey):
        import urllib

        self.server = "localhost"
        self.sender = "splunk"
        self.use_ssl = "false"
        self.use_tls = "false"
        self.username = ""
        self.password = ""
        self.sessionKey = sessionKey 
        self.message = email.mime.Multipart.MIMEMultipart()
        self.humanPart = email.mime.Text.MIMEText("")
        self.jsonReport = {}
        self.evidence = []
    
        self.getMailSettings()

    def __str__(self):
        """Function Override: print email settings object
        """

        return 'Server:%s UseSSL: %s UseTLS: %s Username:%s Password:%s Sender:%s\r\n'% (self.server, self.use_ssl, self.use_tls, self.username, self.password, self.sender)

    def resetMessage(self):
        self.message = email.mime.Multipart.MIMEMultipart()
        self.humanPart = email.mime.Text.MIMEText("")
        self.jsonReport = {}
        self.evidence = []  

    def getMailSettings(self):

        import splunk.entity as entity

        try:
            namespace  = "search" 
            ent = entity.getEntity('admin/alert_actions', 'email', namespace=namespace, owner='nobody', sessionKey=self.sessionKey)

            self.server = ent['mailserver']
            self.sender = ent['from']
            if ent['use_ssl'] == "1":
                self.use_ssl = True
            else:
                self.use_ssl = False 

            if ent['use_tls'] == "1":
                self.use_tls = True 
            else:
                self.use_tls = False

            if 'auth_username' in ent and 'clear_password' in ent:
                self.username = ent['auth_username']
                self.password = ent['clear_password']
        except Exception, e:
            raise Exception, "Could not get email settings from splunk. SessionKey=%s Error: %s" % (self.sessionKey, str(e))

        return

    def sendEmail(self):
        import smtplib, string

        if len(self.message['From']) == 0:
            sender = self.sender
        else:
            sender = self.message['From']


        # make sure the sender is a valid email address
        if sender.find("@") == 1:
            sender = sender + '@' + socket.gethostname()
        if sender.endswith("@"):
            sender = sender + 'localhost'
    
        self.message.attach(self.humanPart)

        if (self.jsonReport):
            yaml = ""
            for key in self.jsonReport.keys():
                yaml = yaml + "%s: %s\n" %(key, self.jsonReport[key])
                jsonReportPart = email.mime.Text.MIMEText("")
                jsonReportPart.set_payload(yaml)
                jsonReportPart.set_charset('utf8')
                jsonReportPart.set_type('text/plain')
                jsonReportPart.add_header('name','report.txt')
            self.message.attach(jsonReportPart)         
        if (self.evidence):
            evidenceReport = ""
            for line in self.evidence:
                evidenceReport= evidenceReport + "%s\n" %(line)
                evidenceReportPart = email.mime.Text.MIMEText("")
                evidenceReportPart.set_payload(evidenceReport)
                evidenceReportPart.set_charset('utf8')
                evidenceReportPart.set_type('text/plain')
                evidenceReportPart.add_header('name','evidence.txt')
            self.message.attach(evidenceReportPart)

        try:
            smtp = smtplib.SMTP(self.server)

            if self.use_ssl:
                smtp = smtplib.SMTP_SSL(self.server)
            else:
                smtp = smtplib.SMTP(self.server)

            if self.use_tls:
                smtp.ehlo()
                smtp.starttls()
                smtp.ehlo()

            if len(self.username) > 0 and len(self.password) > 0:
                smtp.login(self.username, self.password)
            smtp.sendmail(sender, self.message['To'].split(",") + self.message['Cc'].split(",") , self.message.as_string())
            smtp.quit()
            return
        except Exception, e:
            raise Exception, "Could not send email to:%s Server:%s User:%s SSL: %s, TLS: %s Error: %s" % (self.message['To'], self.server, self.username, self.use_ssl, self.use_tls, str(e))

        return

def main():
    import os
    import sys

    sessionKey = 'test'

    mailSystem = emailSplunk(sessionKey)
    mailSystem.sendEmail()


if __name__ == "__main__":
        """You will get an error on importing the Splunk entity class if not run via the Splunk context
                try $SPLUNK_PATH/bin/splunk cmd python emailSplunkXARF.py
                You will still get an error without a valid session key so just expect an error when testing by hand
        """
        main()
