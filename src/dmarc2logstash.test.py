import dmarc2logstash
import unittest

class TestDmarc2Logstash(unittest.TestCase):
  def testLookupHost(self):
    host = dmarc2logstash.lookupHostFromIp('8.8.8.8')
    self.assertEqual(host, 'dns.google')

  def testIsTrue(self):
    self.assertTrue(dmarc2logstash.isTrue(1))
    self.assertTrue(dmarc2logstash.isTrue("1"))
    self.assertTrue(dmarc2logstash.isTrue(True))
    self.assertTrue(dmarc2logstash.isTrue('true'))
    self.assertTrue(dmarc2logstash.isTrue('TRUE'))
    self.assertTrue(dmarc2logstash.isTrue('True'))
    self.assertFalse(dmarc2logstash.isTrue(0))
    self.assertFalse(dmarc2logstash.isTrue(123))
    self.assertFalse(dmarc2logstash.isTrue('sdf'))
    self.assertFalse(dmarc2logstash.isTrue('False'))
    self.assertFalse(dmarc2logstash.isTrue(False))
    self.assertFalse(dmarc2logstash.isTrue('false'))
    self.assertFalse(dmarc2logstash.isTrue('FALSE'))

if __name__ == '__main__':
  unittest.main()