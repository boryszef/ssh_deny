#!/usr/bin/python

# For this to work, you have to add rules to iptables:
#
#:BLACK_HOLE - [0:0]
#:PASS_THROUGH - [0:0]
#
#[0:0] -A INPUT -j PASS_THROUGH
#
#[0:0] -A BLACK_HOLE -p icmp -j DROP
#[0:0] -A BLACK_HOLE -p tcp -j DROP
#[0:0] -A BLACK_HOLE -p udp -j DROP
#[0:0] -A PASS_THROUGH -p udp
#[0:0] -A PASS_THROUGH -p tcp
#[0:0] -A PASS_THROUGH -p icmp

from sys import stdin, argv
import time
import re
import smtplib
from email.mime.text import MIMEText
import subprocess as sp
import signal

# Settings:
#
timeout = 15*60
treshold = 10
mail_server = "example.com"
recipient = "admin@example.org"
sender = "root@example.com"
reply_to = "user@example.com"
hostname = "example.net"
#
# (end of settings)

# Log entries to look for: these show a break-in attempt

#re_postponed = re.compile("Postponed keyboard-interactive for root from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
re_failed = re.compile("Failed keyboard-interactive/pam for .* from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
re_invalid = re.compile("Invalid user .* from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
re_root = re.compile("SSH: Server;Ltype: Authname;Remote: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-\d+;Name: root")
re_unknown = re.compile("lost connection after UNKNOWN from .*\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]")
re_nonsmtp = re.compile("warning: non-SMTP command from .*\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]")

def term_handler(signum, frame):
    log.write("Caught signal %d\n" % signum)
    if signum == signal.SIGTERM:
        log.write("Exiting.\n")
        log.close()
        exit(0)

log = open("/var/log/sshd_deny.log", "a", 1)

deny_started = time.strftime("%Y-%m-%d %H:%M:%S")
log.write("Starting %s at %s.\n" % (argv[0], deny_started))

signal.signal(signal.SIGTERM, term_handler)

msg = stdin.readline()
total_failures = 0

record = {}

def purge(now):
    global record, total_failures
    for k in record.keys():
        if max(record[k]) < now-timeout:
            total_failures += len(record[k])
            log.write("%s with %d records retired.\n" % (k, len(record[k])))
            record.pop(k)

def deny():
    global record, total_failures

    for_denial = []

    for k in record.keys():
        if len(record[k]) >= treshold:
            failures = record[k]
            failures.sort()
            total_failures += len(failures)
            log.write("Denying access for %s\n" % k)
            msg = MIMEText("""Denying access for %s
%d failed connections recorded within %.0f seconds.
Total number of failed attempts since %s is %d.""" % (k, len(failures),
            failures[-1]-failures[0], deny_started, total_failures))
            msg['Subject'] = "Break-in attempt at %s" % hostname
            msg['From'] = sender
            msg['Reply-To'] = reply_to
            msg['To'] = recipient
            msg['Message-id'] = k + "@" + hostname
            s = smtplib.SMTP(mail_server)
            s.sendmail(sender, [ recipient ], msg.as_string())
            s.quit()
            record.pop(k)
            for_denial.append(k)

    if for_denial:
        for k in for_denial:
            output = sp.check_output(["/sbin/iptables",
                "-A", "INPUT",
                "-p", "tcp",
                "-s", k,
                "-g", "BLACK_HOLE"])
            log.write(output)



while msg:
    tmp = msg.split('@')
    stamp = float(tmp[0])
    now = time.time()
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    #result = re_postponed.match(tmp[1])
    result = re_failed.match(tmp[1])
    if not result: result = re_invalid.match(tmp[1])
    if not result: result = re_root.match(tmp[1])
    if not result: result = re_unknown.match(tmp[1])
    if not result: result = re_nonsmtp.match(tmp[1])
    if result:
        ip = result.group(1)
        if not record.has_key(ip):
            record[ip] = []
        record[ip].append(stamp)
        log.write("%s %f:\n" % (now_str, now))
        log.write("%s added to the list with timestamp %f\n" % (ip, stamp))
        log.write("The original message was:\n")
        log.write(msg)
    purge(now)
    deny()
    msg = stdin.readline()

log.close()
