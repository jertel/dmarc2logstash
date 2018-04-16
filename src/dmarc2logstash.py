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

def connect(server, username, password):
  debugLevel = os.environ.get('POP3_DEBUG_LEVEL', "0")
  log.info("Connecting to POP3 server; server=%s; username=%s; debugLevel=%s" % (server, username, debugLevel))
  conn = poplib.POP3_SSL(server)
  conn.set_debuglevel(int(debugLevel))
  conn.user(username)
  conn.pass_(password)
  return conn

def download(server, username, password, jsonOutputFile):
  success = 0
  failure = 0
  conn = connect(server, username, password)
  messages = conn.list()[1]
  log.info("Connected to POP3 server; newMessages=%d" % (len(messages)))
  for i in range(1, len(messages) + 1):
    txt = conn.retr(i)[1]
    msg = parser.Parser().parsestr("\n".join(txt))
    log.info("Reading message; messageIdx=%d; messageSubject=\"%s\"; messageSender=\"%s\"" % (i, msg.get('subject'), msg.get('from')))
    successCount = parseAttachments(jsonOutputFile, msg)
    if successCount > 0:
      log.info("Deleting successfully parsed DMARC report email; messageIdx=%d; messageSubject=\"%s\"; messageSender=\"%s\"" % (i, msg.get('subject'), msg.get('from')))
      conn.dele(i) 
      success = success + successCount
    else:
      log.info("Preserving email message since it is not a DMARC report; messageIdx=%d; messageSubject=\"%s\"; messageSender=\"%s\"" % (i, msg.get('subject'), msg.get('from')))
      failure = failure + 1
  log.info("DMARC Results; successfulDmarcEmailCount=%d; skippedEmailCount=%d" % (success, failure))
  conn.quit()

def parseAttachments(jsonOutputFile, msg):
  success = 0
  for part in msg.walk():
    name = part.get_filename()
    if name is not None:
      xmls = []
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
        if parse(jsonOutputFile, str(xml), msg.get('subject')):
          success = success + 1
  return success

def parse(jsonOutputFile, xml, subject):
  if xml.find("report_metadata") > 0:
    root = ET.fromstring(xml)
    records = []
    report = {}
    match = re.search('.*?Submitter:\\s?([^\\s]*)\\s?', subject)
    if match is not None and match.groups > 0:
      report['submitter'] = match.group(1)
    else:
      report['submitter'] = "unknown"
    metaData = root.find('report_metadata')
    if metaData is not None:
      report['org_name'] = metaData.find('org_name').text
      report['org_email'] = metaData.find('email').text
      report['id'] = metaData.find('report_id').text
      report['date_start'] = datetime.fromtimestamp(int(metaData.find('date_range').find('begin').text))
      report['date_end'] = datetime.fromtimestamp(int(metaData.find('date_range').find('end').text))
      policyPub = root.find('policy_published')
      if policyPub is not None:
        report['policy_domain'] = policyPub.find('domain').text
        report['policy_dkim'] = policyPub.find('adkim').text
        report['policy_spf'] = policyPub.find('aspf').text
        report['policy_p'] = policyPub.find('p').text
        report['policy_pct'] = float(policyPub.find('pct').text)
      for child in root.iter("record"):
        record = dict(report)
        row = child.find('row')
        if row is not None:
          record['source_ip'] = row.find('source_ip').text
          record['count'] = int(row.find('count').text)
          policy = row.find('policy_evaluated')
          if policy is not None:
            record['policy_disposition'] = policy.find('disposition').text
            dkim = policy.find('dkim')
            if dkim is not None:
              record['policy_dkim'] = dkim.text
            spf = policy.find('spf')
            if spf is not None:
              record['policy_spf'] = spf.text
        identifiers = child.find('identifiers')
        if identifiers is not None:
          record['identifier_header_from'] = identifiers.find('header_from').text
        authResults = child.find('auth_results')
        if authResults is not None:
          dkim = authResults.find('dkim')
          if dkim is not None:
            record['auth_dkim_domain'] = dkim.find('domain').text
            record['auth_dkim_result'] = dkim.find('result').text
          spf = authResults.find('spf')
          if spf is not None:
            record['auth_spf_domain'] = spf.find('domain').text
            record['auth_spf_result'] = spf.find('result').text
        records.append(record)

      log.info("Writing JSON records to log file")
      with open(jsonOutputFile, 'a') as dmarcLog:
        for record in records:
          output = json.dumps(record, default=json_serial)
          dmarcLog.write(output + "\n")
      return True
    else:
      log.warn("Invalid feedback; missing report_metadata element")
  else:
    log.warn("Skipping attachment that does not appear to conform to a DMARC aggregate report")
  return False

def json_serial(obj):
  if isinstance(obj, (datetime, date)):
    return obj.isoformat()
  raise TypeError ("Type %s not serializable" % type(obj))

def start(server, username, password, sleepSec, jsonOutputFile):
  log.info("Starting DMARC to Logstash service; sleepSec=%d; jsonOutputFile=%s" % (sleepSec, jsonOutputFile))
  while True:
    download(server, username, password, jsonOutputFile)
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

  server = os.environ.get('POP3_SERVER', config.get('pop3_server'))
  username = os.environ.get('POP3_USERNAME', config.get('pop3_username'))
  password = os.environ.get('POP3_PASSWORD', config.get('pop3_password'))
  sleepSec = os.environ.get('SLEEP_SECONDS', config.get('sleep_seconds'))
  jsonOutputFile = os.environ.get('JSON_OUTPUT_FILE', config.get('json_output_file'))

  if not server or not username or not password:
    log.error("POP3_SERVER, POP3_USERNAME, POP3_PASSWORD, and SLEEP_SECONDS are required environment variables")
  else:
    start(server, username, password, int(sleepSec), jsonOutputFile)

if __name__ == '__main__':
  sys.exit(main())
