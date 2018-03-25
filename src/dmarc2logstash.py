import argparse
from datetime import date, datetime
import gzip
import io
import json
import os
import time
import logging
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
      data = part.get_payload(decode=True)
      if part.get_content_type() == "application/gzip" or name.endswith(".gzip") or name.endswith(".gz"):
        log.info("Decompressing gzip data")
        data = gzip.GzipFile(fileobj=io.BytesIO(data)).read()
      if parse(jsonOutputFile, str(data)):
        success = success + 1
  return success

def parse(jsonOutputFile, xml):
  if xml.find("report_metadata") > 0:
    root = ET.fromstring(xml)
    records = []
    report = {}
    report['org_name'] = root.find('report_metadata').find('org_name').text
    report['org_email'] = root.find('report_metadata').find('email').text
    report['id'] = root.find('report_metadata').find('report_id').text
    report['date_start'] = datetime.fromtimestamp(int(root.find('report_metadata').find('date_range').find('begin').text))
    report['date_end'] = datetime.fromtimestamp(int(root.find('report_metadata').find('date_range').find('end').text))
    report['policy_domain'] = root.find('policy_published').find('domain').text
    report['policy_dkim'] = root.find('policy_published').find('adkim').text
    report['policy_spf'] = root.find('policy_published').find('aspf').text
    report['policy_p'] = root.find('policy_published').find('p').text
    report['policy_pct'] = float(root.find('policy_published').find('pct').text)
    for child in root.iter("record"):
      record = dict(report)
      record['source_ip'] = child.find('row').find('source_ip').text
      record['count'] = int(child.find('row').find('count').text)
      record['policy_disposition'] = child.find('row').find('policy_evaluated').find('disposition').text
      record['policy_dkim'] = child.find('row').find('policy_evaluated').find('dkim').text
      record['policy_spf'] = child.find('row').find('policy_evaluated').find('spf').text
      record['identifier_header_from'] = child.find('identifiers').find('header_from').text
      record['auth_dkim_domain'] = child.find('auth_results').find('dkim').find('domain').text
      record['auth_dkim_result'] = child.find('auth_results').find('dkim').find('result').text
      record['auth_spf_domain'] = child.find('auth_results').find('spf').find('domain').text
      record['auth_spf_result'] = child.find('auth_results').find('spf').find('result').text
      records.append(record)
    log.info("Writing JSON records to log file")
    with open(jsonOutputFile, 'a') as dmarcLog:
      for record in records:
        output = json.dumps(record, default=json_serial)
        dmarcLog.write(output + "\n")
    return True
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
    start(server, username, password, sleepSec, jsonOutputFile)

if __name__ == '__main__':
  sys.exit(main())
