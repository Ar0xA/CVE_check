#use https://cve.circl.lu to display all CVE's for a vendor/product combination
#outputs a warning when a cve is newer than last notification date
#by Ar0xA

from ares import CVESearch
import json, sys, time, smtplib

from email.mime.text import MIMEText


#cvss_treshhold, notify only if same or higher
cvss_treshhold = 7.0

#email config
#do we want to send a mail?
email_notify = True
#from
email_from = ""
#to
email_to = ""
#emailserver
#gmail
email_server = ""
email_port = 587
email_login = ""
email_password = ""

#read file with vendor/product list
#one vendor/product per line!
vendor_productfile = open('vendprod.lst','r')

#if no lastrun time, lets create the file now
lastrunepoch = 0
try:
    tmpfile = open('lastrun','r')
    lastrunepoch = int(tmpfile.read())
    tmpfile.close()
except:
    print "No timestamp file found for notification time, making lastrun file"
    epoch_time = int(time.time())
    epochfile= open('lastrun','w+')
    epochfile.write(str(epoch_time))
    epochfile.close()
    print "This time is now the check time for new notifications"
    sys.exit()

for vendprod in vendor_productfile:
    if vendprod[0] == '#':
        pass
    else:
        #lets do some checking!
        print ("Checking for: " + vendprod)
        cve = CVESearch()
        resultset = cve.search(vendprod.strip())
        parsed_json = json.loads(resultset)
        for result in parsed_json:
            #print result
            cve_id= result['id']
            cve_cvss = result['cvss']
            cve_summary = result['summary']
            try:
                cve_lastmodified = result['last-modified']
            except:
                cve_lastmodified = result['Modified']
            cve_refs = result['references']
            cve_refstrings=""
            for item in cve_refs:
                cve_refstrings += str(item) + "\n"
            cve_vulnconf = result['vulnerable_configuration']
            cve_vulnstrings =""
            for item in cve_vulnconf:
                cve_vulnstrings += str(item) + "\n"
            resultinfo = "CVE:\n" + str(cve_id) + "\n\nLast modified:\n" + str(cve_lastmodified) + "\n\nCVSS:\n" + str(cve_cvss) + "\n\nSummary:\n" + str(cve_summary) + "\n\nVulnerable configurations:\n" + str(cve_vulnstrings) + "\n\nReferences:\n" + str(cve_refstrings)

            #is the cve last-update newer than the last run epoch?
            try:
                cve_updated_epoch = int(time.mktime(time.strptime(cve_lastmodified,"%Y-%m-%dT%H:%M:%S.%f")))
            except:
                cve_updated_epoch = int(time.mktime(time.strptime(cve_lastmodified,"%Y-%m-%dT%H:%M:%S")))
            if cve_updated_epoch >= lastrunepoch:
                print "CVE is newer than last run time!"
                #is the cvss above treshhold?
                if cvss_treshhold <= float(cve_cvss):
                    print "CVSS treshhold is over minimum, notify!"
                    if email_notify:
    		        msg = MIMEText(resultinfo)
                        msg['From'] = email_from
    		        msg['To']= email_to
                        msg['Subject']= "Vendor: " + str(vendprod) + str(cve_id) + " CVSS: " + str(cve_cvss) + " Last modified: " + str(cve_lastmodified)
                        s = smtplib.SMTP(email_server,email_port)
    		        s.starttls()
                        s.login(email_login,email_password)
                        s.sendmail(email_from,[email_to], msg.as_string())
                        s.quit()
                        print "mail send!"
                    else:
                        print "Not emailing"
                        print resultinfo
                else:
                    print "CVSS treshhold lower, no notify"
            else:
                print "CVE is older than last runtime, ignore"

#Before we done, write the current epoch time of when we done.
print "Done with run, writing current time to file"
epoch_time = int(time.time())
epochfile= open('lastrun','w+')
epochfile.write(str(epoch_time))
epochfile.close()
#byebye
