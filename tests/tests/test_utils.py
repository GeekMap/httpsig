#!/usr/bin/env python
import os
import re
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import unittest
import httpsig.utils


class TestUtils(unittest.TestCase):

    def test_get_fingerprint(self):
        with open(os.path.join(os.path.dirname(__file__), 'rsa_public.pem'), 'r') as k:
            key = k.read()
        fingerprint = httpsig.utils.get_fingerprint(key)
        self.assertEqual(fingerprint, "73:61:a2:21:67:e0:df:be:7e:4b:93:1e:15:98:a5:b7")

    def test_generate_message(self):
        HOST = "example.org"
        METHOD = "POST"
        PATH = '/foo'
        HTTP_VERSION = 'HTTP/1.1'
        HEADERS = {
            'Host': 'example.org',
            'Date': 'Tue, 07 Jun 2014 20:51:35 GMT',
            'Content-Type': 'application/json',
            'Digest': 'SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=',
            'Content-Length': 18
        }
        cases = {
            # from draft-01: 3.1.2.  RSA Example
            'request-line host date digest content-length': b'POST /foo HTTP/1.1\nhost: example.org\ndate: Tue, 07 Jun 2014 20:51:35 GMT\ndigest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=\ncontent-length: 18',
            # draft-02
            '(request-line) host date digest content-length': b'(request-line): post /foo\nhost: example.org\ndate: Tue, 07 Jun 2014 20:51:35 GMT\ndigest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=\ncontent-length: 18',
            # draft-03
            '(request-target) host date digest content-length': b'(request-target): post /foo\nhost: example.org\ndate: Tue, 07 Jun 2014 20:51:35 GMT\ndigest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=\ncontent-length: 18'
        }

        for required_headers, result in cases.items():
            assert httpsig.utils.generate_message(
                required_headers=required_headers.split(),
                headers=HEADERS,
                host=HOST,
                method=METHOD,
                path=PATH,
                http_version=HTTP_VERSION) == result, 'header: %s\nexpect: %s\n' % (required_headers, result)
