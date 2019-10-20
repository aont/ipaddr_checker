#!/usr/bin/env python3
import sys
sys.stderr.write('preparing SMTP server. please wait...\n')
# sys.stderr.flush()

import asyncio
import re
import requests
import base64
import signal

import config
import sendgrid

# import syslog

from_address="ipaddress@pr400ne"
pattern = re.compile(r'接続先1：(\d+[.]\d+[.]\d+[.]\d+)')

# syslog.openlog("mysmtpd")
def mylog(message):
    sys.stderr.write("%s\n" % message)
    # syslog.syslog(message)

async def mailviasendgrid(message_str):
    mylog(u"mailing via sendgrid")
    sg_username = config.SENDGRID_USERNAME
    sg_recipient = config.SENDGRID_RECIPIENT
    sg_apikey = config.SENDGRID_APIKEY
    sg_client = sendgrid.SendGridAPIClient(sg_apikey)
    sg_from = sendgrid.Email(email=sg_username, name="IP Address Checker")
    message = sendgrid.Mail(from_email=sg_from, to_emails=[sg_recipient], subject=u"Update of IP Address", plain_text_content=message_str)
    message.reply_to = sg_recipient
    sg_client.send(message)

async def noipupdate(ipaddr):
    api_URL="https://dynupdate.no-ip.com/nic/update"
    b64Val = base64.b64encode((config.NOIP_USER+":"+config.NOIP_PASSWORD).encode()).decode()
    useragent=config.USERAGENT
    
    ddns = config.DDNS_HOST
    mylog("target ddns: %s" % ddns)
    params = { 'hostname': ddns, 'myip':ipaddr }
    headers = { 'User-Agent': useragent, "Authorization": "Basic %s" % b64Val }
    result=requests.get(api_URL, params=params, headers=headers)
    mylog(result.text.rstrip())


class MyHandler:
    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        envelope.rcpt_tos.append(address)
        return '250 OK'
    async def handle_DATA(self, server, session, envelope):
        if envelope.mail_from==from_address:
            mylog('Message from %s' % envelope.mail_from)
            mylog('Message for %s' % envelope.rcpt_tos)
            content = envelope.content.decode('iso2022_jp', errors='replace')
            pattern = re.compile(r'接続先1：(\d+[.]\d+[.]\d+[.]\d+)')
            match = pattern.search(content)
            if match is None:
                raise Exception("unexpected")
            ipaddr=match.group(1)
            mylog("IP Address: %s" % ipaddr)
            asyncio.ensure_future(mailviasendgrid(content), loop=loop)
            asyncio.ensure_future(noipupdate(ipaddr), loop=loop)
            return '250 Message accepted for delivery'
        return '250 Message accepted for delivery'


import aiosmtpd.controller
loop = asyncio.get_event_loop()
controller = aiosmtpd.controller.Controller(MyHandler(), loop=loop, hostname="", port=10025)
controller.start()
signals = [signal.SIGINT]
mylog("running now. stop to send %s" % " or ".join(map(lambda s: str(s), signals)) )
sig = signal.sigwait(signals)
mylog('%s caught, shutting down' % sig)
controller.stop()

