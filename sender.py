#!/usr/bin/env python3
import smtplib
smtpobj = smtplib.SMTP('localhost', 10025)
smtpobj.ehlo()
from_address="ipaddress@pr400ne"
to_address="test@test.com"

f=open("mail.eml", "r")
mymessage=f.read()
f.close()

smtpobj.sendmail(from_address, to_address, mymessage)
smtpobj.close()
