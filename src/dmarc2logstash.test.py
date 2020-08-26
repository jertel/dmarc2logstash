import dmarc2logstash
import unittest

class TestDmarc2Logstash(unittest.TestCase):
  def testLookupHost(self):
    host = dmarc2logstash.lookupHostFromIp('8.8.8.8')
    self.assertEqual(host, 'dns.google')

if __name__ == '__main__':
  unittest.main()