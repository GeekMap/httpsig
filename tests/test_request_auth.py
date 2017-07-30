#!/usr/bin/env python
import sys
import os
import unittest
import requests

from httpsig.requests_auth import HTTPSignatureAuth


class TestHTTPSignatureAuth(unittest.TestCase):
    def setUp(self):
        private_key_path = os.path.join(os.path.dirname(__file__), 'rsa_private.pem')
        with open(private_key_path, 'rb') as f:
            private_key = f.read()

        public_key_path = os.path.join(os.path.dirname(__file__), 'rsa_public.pem')
        with open(public_key_path, 'rb') as f:
            public_key = f.read()

        self.keyId = "Test"
        self.algorithm = "rsa-sha256"
        self.sign_secret = private_key
        self.verify_secret = public_key

    def test__call_(self):
        auth = HTTPSignatureAuth(
            key_id=self.keyId,
            secret=self.sign_secret,
            algorithm=self.algorithm,
            httpsig_version='draft-07',
            headers=[
                'date'
            ])

        request = requests.Request(
            method='post',
            url='http://example.com/foo?param=value&pet=dog',
            auth=auth,
            headers={
                'host': 'example.com',
                'date': 'Thu, 05 Jan 2012 21:31:40 GMT',
                'content-type': 'application/json',
                'digest': 'SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=',
                'content-length': '18'
            }).prepare()

        assert 'ATp0r26dbMIxOopqw0OfABDT7CKMIoENumuruOtarj8n/97Q3htHFYpH8yOSQk3Z5zh8UxUym6FYTb5+A0Nz3NRsXJibnYi7brE/4tx5But9kkFGzG+xpUmimN4c3TMN7OFH//+r8hBf7BT9/GmHDUVZT2JzWGLZES2xDOUuMtA=' in request.headers['authorization']
