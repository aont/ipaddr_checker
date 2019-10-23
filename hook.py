#!/usr/bin/env python3
import sys
import email

import re
import requests
import base64
import signal
import config
import sendgrid
import syslog

syslog.openlog("ipaddres-checker")

newip_pattern = re.compile(r'接続先1：(\d+[.]\d+[.]\d+[.]\d+)')

def mylog(message):
    # sys.stdout.write("%s\n" % message)
    syslog.syslog(message)
    
def mailviasendgrid(message_str):
    mylog(u"mailing via sendgrid")
    sg_username = config.SENDGRID_USERNAME
    sg_recipient = config.SENDGRID_RECIPIENT
    sg_apikey = config.SENDGRID_APIKEY
    sg_client = sendgrid.SendGridAPIClient(sg_apikey)
    sg_from = sendgrid.Email(email=sg_username, name="IP Address Checker")
    message = sendgrid.Mail(from_email=sg_from, to_emails=[sg_recipient], subject=u"Update of IP Address", plain_text_content=message_str)
    message.reply_to = sg_recipient
    sg_client.send(message)

def noipupdate(ipaddr):
    api_URL="https://dynupdate.no-ip.com/nic/update"
    b64Val = base64.b64encode((config.NOIP_USER+":"+config.NOIP_PASSWORD).encode()).decode()
    useragent=config.USERAGENT
    
    ddns = config.DDNS_HOST
    mylog("target ddns: %s" % ddns)
    # params = { 'hostname': ddns, 'myip':ipaddr }
    params = { 'hostname': ddns }
    headers = { 'User-Agent': useragent, "Authorization": "Basic %s" % b64Val }
    result=requests.get(api_URL, params=params, headers=headers)
    mylog(result.text.rstrip())

message_bytes = sys.stdin.buffer.read()
message_str = message_bytes.decode('iso2022_jp', errors='replace')    
mailviasendgrid(message_str)

match = newip_pattern.search(message_str)
if match:
    ipaddr=match.group(1)
    mylog("IP Address: %s" % ipaddr)
    noipupdate(ipaddr)
else:
    mylog("[warn] unexpected format")

syslog.closelog()
