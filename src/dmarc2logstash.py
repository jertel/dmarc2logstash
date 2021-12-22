import argparse
from datetime import date, datetime
import fnmatch
import gzip
import zipfile
import io
import json
import os
import time
import logging
import re
import signal
import socket
import sys
import poplib
from email import parser
import xml.etree.ElementTree as ET

log = logging.getLogger("dmarc2logstash")

def setupLogging():
  formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
  ch = logging.StreamHandler()
  ch.setLevel(logging.INFO)
  ch.setFormatter(formatter)
  log.addHandler(ch)
  log.setLevel(logging.INFO)

def connect(server, username, password, timeout):
  debugLevel = os.environ.get('POP3_DEBUG_LEVEL', "0")
  log.info("Connecting to POP3 server; server=%s; username=%s; debugLevel=%s" % (server, username, debugLevel))
  conn = poplib.POP3_SSL(server)
  conn.sock.settimeout(timeout)
  conn.set_debuglevel(int(debugLevel))
  conn.user(username)
  conn.pass_(password)
  return conn

def isTrue(flag):
  if flag == 1 or flag == "true" or flag == "True" or flag == "TRUE" or flag == True:
    return True
  return False

def download(server, username, password, jsonOutputFile, timeout, shouldDelete, shouldDeleteFailures):
  success = 0
  failure = 0
  conn = connect(server, username, password, timeout)
  messages = conn.list()[1]
  log.info("Connected to POP3 server; newMessages=%d" % (len(messages)))
  for i in range(1, len(messages) + 1):
    txt = conn.retr(i)[1]
    raw = ""
    for j in range(len(txt)):
      raw = raw + txt[j].decode() + "\n"
    msg = parser.Parser().parsestr(raw)
    log.info("Reading message; messageIdx=%d; messageSubject=\"%s\"; messageSender=\"%s\"" % (i, msg.get('subject'), msg.get('from')))
    successCount = parseAttachments(jsonOutputFile, msg)
    if successCount > 0:
      if isTrue(shouldDelete):
        log.info("Deleting successfully parsed DMARC report email; messageIdx=%d; messageSubject=\"%s\"; messageSender=\"%s\"" % (i, msg.get('subject'), msg.get('from')))
        conn.dele(i) 
      success = success + successCount
    else:
      failure = failure + 1
      if isTrue(shouldDeleteFailures):
        log.info("Removing failed email message; it is not a DMARC report; messageIdx=%d; messageSubject=\"%s\"; messageSender=\"%s\"" % (i, msg.get('subject'), msg.get('from')))
        conn.dele(i)
      else:
        log.info("Preserving failed email message; it is not a DMARC report; messageIdx=%d; messageSubject=\"%s\"; messageSender=\"%s\"" % (i, msg.get('subject'), msg.get('from')))

  log.info("DMARC Results; successfulDmarcEmailCount=%d; skippedEmailCount=%d" % (success, failure))
  conn.quit()

def parseAttachments(jsonOutputFile, msg):
  success = 0
  for part in msg.walk():
    name = part.get_filename()
    if name is not None:
      xmls = []
      try:
        data = part.get_payload(decode=True)
        if part.get_content_type() == "application/gzip" or name.endswith(".gzip") or name.endswith(".gz"):
          log.info("Decompressing gzip data")
          xmls.append(gzip.GzipFile(fileobj=io.BytesIO(data)).read())
        elif part.get_content_type() == "application/zip" or name.endswith(".zip"):
          log.info("Decompressing zip data")
          zfile = zipfile.ZipFile(io.BytesIO(data))
          for name in zfile.namelist():
            if fnmatch.fnmatch(name, '*.xml'):
              xmls.append(zfile.read(name))
        else:
          xmls.append(data)
        for xml in xmls:
          if parse(jsonOutputFile, str(xml.decode("utf-8")), msg.get('subject')):
            success = success + 1
      except Exception as e:
        log.warning("Unable to parse attachment; name=\"%s\"; reason=\"%s\"" % (name, str(e)))
  return success

def parseItem(element, tag):
  value = ""
  item = element.find(tag)
  if item is not None:
    value = item.text
  return value

def parse(jsonOutputFile, xml, subject):
  if xml.find("report_metadata") > 0:
    root = ET.fromstring(xml)
    records = []
    report = {}
    match = re.search('.*?Submitter:\\s?([^\\s]*)\\s?', subject)
    if match is not None and len(match.groups()) > 0:
      report['submitter'] = match.group(1)
    else:
      report['submitter'] = "unknown"
    metaData = root.find('report_metadata')
    if metaData is not None:
      report['org_name'] = parseItem(metaData, 'org_name')
      report['org_email'] = parseItem(metaData, 'email')
      report['id'] = parseItem(metaData, 'report_id')
      report['date_start'] = datetime.fromtimestamp(int(metaData.find('date_range').find('begin').text))
      report['date_end'] = datetime.fromtimestamp(int(metaData.find('date_range').find('end').text))
      policyPub = root.find('policy_published')
      if policyPub is not None:
        report['policy_domain'] = parseItem(policyPub, 'domain')
        report['policy_dkim'] = parseItem(policyPub, 'adkim')
        report['policy_spf'] = parseItem(policyPub, 'aspf')
        report['policy_p'] = parseItem(policyPub, 'p')
        report['policy_pct'] = parseItem(policyPub, 'pct')
      for child in root.iter("record"):
        record = dict(report)
        row = child.find('row')
        if row is not None:
          record['source_ip'] = parseItem(row, 'source_ip')
          record['source_domain'] = lookupHostFromIp(record['source_ip'])
          record['count'] = int(parseItem(row, 'count'))
          policy = row.find('policy_evaluated')
          if policy is not None:
            record['policy_disposition'] = parseItem(policy, 'disposition')
            record['policy_dkim'] = parseItem(policy, 'dkim')
            record['policy_spf'] = parseItem(policy, 'spf')
        identifiers = child.find('identifiers')
        if identifiers is not None:
          record['identifier_header_from'] = parseItem(identifiers, 'header_from')
        authResults = child.find('auth_results')
        if authResults is not None:
          dkim = authResults.find('dkim')
          if dkim is not None:
            record['auth_dkim_domain'] = parseItem(dkim, 'domain')
            record['auth_dkim_result'] = parseItem(dkim, 'result')
          spf = authResults.find('spf')
          if spf is not None:
            record['auth_spf_domain'] = parseItem(spf, 'domain')
            record['auth_spf_result'] = parseItem(spf, 'result')
        records.append(record)

      log.info("Writing JSON records to log file")
      with open(jsonOutputFile, 'a') as dmarcLog:
        for record in records:
          output = json.dumps(record, default=json_serial)
          dmarcLog.write(output + "\n")
      return True
    else:
      log.warning("Invalid feedback; missing report_metadata element")
  else:
    log.warning("Skipping attachment that does not appear to conform to a DMARC aggregate report")
  return False

def lookupHostFromIp(ip):
  host = ip
  hosts = socket.gethostbyaddr(ip)
  if len(hosts) > 0:
    host = hosts[0]
    segments = host.split('.')
    if len(segments) > 2:
      host = segments[-2] + "." + segments[-1]

  return host

def json_serial(obj):
  if isinstance(obj, (datetime, date)):
    return obj.isoformat()
  raise TypeError ("Type %s not serializable" % type(obj))

def start(server, username, password, sleepSec, jsonOutputFile, timeout, shouldDelete, shouldDeleteFailures):
  log.info("Starting DMARC to Logstash service; sleepSec=%d; jsonOutputFile=%s; shouldDelete=%d; shouldDeleteFailures=%d" % (sleepSec, jsonOutputFile, shouldDelete, shouldDeleteFailures))
  while True:
    download(server, username, password, jsonOutputFile, timeout, shouldDelete, shouldDeleteFailures)
    log.info("Sleeping until next poll; sleepSec=%d" % (sleepSec))
    time.sleep(sleepSec)

def handle_signal(signal, frame):
  os._exit(0)

def main():
  signal.signal(signal.SIGINT, handle_signal)

  setupLogging()
  parser = argparse.ArgumentParser()
  parser.add_argument('--configFile', help='JSON configuration file')
  args = parser.parse_args()
  
  config = {}
  if args.configFile is not None:
    with open(args.configFile, "r") as fp:
      config = json.load(fp)
  if config.get('json_output_file') is None:
    config['json_output_file'] = 'dmarc.json'
  if config.get('sleep_seconds') is None:
    config['sleep_seconds'] = 300
  if config.get('socket_timeout_seconds') is None:
    config['socket_timeout_seconds'] = 30

  server = os.environ.get('POP3_SERVER', config.get('pop3_server'))
  username = os.environ.get('POP3_USERNAME', config.get('pop3_username'))
  password = os.environ.get('POP3_PASSWORD', config.get('pop3_password'))
  sleepSec = os.environ.get('SLEEP_SECONDS', config.get('sleep_seconds'))
  jsonOutputFile = os.environ.get('JSON_OUTPUT_FILE', config.get('json_output_file'))
  timeout = os.environ.get('SOCKET_TIMEOUT_SECONDS', config.get('socket_timeout_seconds'))
  shouldDelete = os.environ.get('DELETE_MESSAGES', config.get('delete_messages'))
  shouldDeleteFailures = os.environ.get('DELETE_FAILURES', config.get('delete_failures'))

  if not server or not username or not password or not shouldDelete:
    log.error("POP3_SERVER, POP3_USERNAME, POP3_PASSWORD, and DELETE_MESSAGES are required environment variables")
  else:
    start(server, username, password, int(sleepSec), jsonOutputFile, float(timeout), shouldDelete, shouldDeleteFailures)

if __name__ == '__main__':
  sys.exit(main())
