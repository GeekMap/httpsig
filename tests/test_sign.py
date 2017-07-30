#!/usr/bin/env python
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import json
import unittest

import httpsig.sign as sign
from httpsig.utils import parse_authorization_header


class TestSign(unittest.TestCase):

    def setUp(self):
        self.key_path = os.path.join(os.path.dirname(__file__), 'rsa_private.pem')
        with open(self.key_path, 'rb') as f:
            self.key = f.read()

    def test_default(self):
        hs = sign.HeaderSigner(key_id='Test', secret=self.key, algorithm='rsa-sha256')
        unsigned = {
            'Date': 'Thu, 05 Jan 2012 21:31:40 GMT'
        }
        signed = hs.sign(unsigned)
        self.assertIn('Date', signed)
        self.assertEqual(unsigned['Date'], signed['Date'])
        self.assertIn('Authorization', signed)
        auth = parse_authorization_header(signed['authorization'])
        params = auth[1]
        self.assertIn('keyId', params)
        self.assertIn('algorithm', params)
        self.assertIn('signature', params)
        self.assertEqual(params['keyId'], 'Test')
        self.assertEqual(params['algorithm'], 'rsa-sha256')
        self.assertEqual(params['signature'], 'ATp0r26dbMIxOopqw0OfABDT7CKMIoENumuruOtarj8n/97Q3htHFYpH8yOSQk3Z5zh8UxUym6FYTb5+A0Nz3NRsXJibnYi7brE/4tx5But9kkFGzG+xpUmimN4c3TMN7OFH//+r8hBf7BT9/GmHDUVZT2JzWGLZES2xDOUuMtA=')

    def test_all(self):
        hs = sign.HeaderSigner(key_id='Test', secret=self.key, algorithm='rsa-sha256', headers=[
            '(request-target)',
            'host',
            'date',
            'content-type',
            'content-md5',
            'content-length'
        ])
        unsigned = {
            'Host': 'example.com',
            'Date': 'Thu, 05 Jan 2012 21:31:40 GMT',
            'Content-Type': 'application/json',
            'Content-MD5': 'Sd/dVLAcvNLSq16eXua5uQ==',
            'Content-Length': '18',
        }
        signed = hs.sign(unsigned, method='POST', path='/foo?param=value&pet=dog')

        self.assertIn('Date', signed)
        self.assertEqual(unsigned['Date'], signed['Date'])
        self.assertIn('Authorization', signed)
        auth = parse_authorization_header(signed['authorization'])
        params = auth[1]
        self.assertIn('keyId', params)
        self.assertIn('algorithm', params)
        self.assertIn('signature', params)
        self.assertEqual(params['keyId'], 'Test')
        self.assertEqual(params['algorithm'], 'rsa-sha256')
        self.assertEqual(params['headers'], '(request-target) host date content-type content-md5 content-length')
        self.assertEqual(params['signature'], 'G8/Uh6BBDaqldRi3VfFfklHSFoq8CMt5NUZiepq0q66e+fS3Up3BmXn0NbUnr3L1WgAAZGplifRAJqp2LgeZ5gXNk6UX9zV3hw5BERLWscWXlwX/dvHQES27lGRCvyFv3djHP6Plfd5mhPWRkmjnvqeOOSS0lZJYFYHJz994s6w=')

    def test_PASS_verify_headers_by_draft_version(self):
        testcases = {
            'draft-00': 'request-line',
            'draft-01': 'request-line',
            'draft-02': '(request-line)',
            'draft-03': '(request-target)',
            'draft-04': '(request-target)',
            'draft-05': '(request-target)',
            'draft-06': '(request-target)',
            'draft-07': '(request-target)',
            None: '(request-target)'
        }
        for httpsig_version, header_req in testcases.items():
            hs = sign.HeaderSigner(key_id='Test', secret=self.key, httpsig_version=httpsig_version, headers=[
                header_req,
                'host',
                'date',
                'content-type',
                'content-md5',
                'content-length'
            ])

    def test_FAIL_verify_headers_by_draft_version(self):
        testcases = [
            ('draft-00', '(request-line)'),
            ('draft-00', '(request-target)'),
            ('draft-01', '(request-line)'),
            ('draft-01', '(request-target)'),
            ('draft-02', 'request-line'),
            ('draft-02', '(request-target)'),
            ('draft-03', 'request-line'),
            ('draft-03', '(request-line)'),
            ('draft-04', 'request-line'),
            ('draft-04', '(request-line)'),
            ('draft-05', 'request-line'),
            ('draft-05', '(request-line)'),
            ('draft-06', 'request-line'),
            ('draft-06', '(request-line)'),
            ('draft-07', 'request-line'),
            ('draft-07', '(request-line)'),
            (None, 'request-line'),
            (None, '(request-line)'),
        ]
        for httpsig_version, header_req in testcases:
            try:
                sign.HeaderSigner(key_id='Test', secret=self.key, httpsig_version=httpsig_version, headers=[
                    header_req,
                    'host',
                    'date',
                    'content-type',
                    'content-md5',
                    'content-length'
                ])
                self.fail('Should raise KeyError in (%s, %s)' % (httpsig_version, header_req))
            except KeyError:
                pass
