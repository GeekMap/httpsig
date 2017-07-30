#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import unittest
import six
import httpsig.utils


class TestUtils(unittest.TestCase):

    def test_ct_bytes_compare(self):
        if six.PY3:
            test_cases = [
                (b"\xa5Q\x7f\x92q\x8b+\xd5\x83x'^", b"\xa5Q\x7f\x92q\x8b+\xd5\x83x'^", True),
                ('123', '123', True),
                (b'123', '123', True),
                (b'123', b'123', True),
                (b'\xe5\xb0\x8d', '對', True),
                (b'123456', b'123', False)
            ]
        elif six.PY2:
            test_cases = [
                ("\xa5Q\x7f\x92q\x8b+\xd5\x83x'^", "\xa5Q\x7f\x92q\x8b+\xd5\x83x'^", True),
                ('123', '123', True),
                ('123', u'123', True),
                (u'123', u'123', True),
                ('\xe5\xb0\x8d', u'對', True),
                ('123456', '123', False)
            ]

        for case in test_cases:
            self.assertIs(httpsig.utils.ct_bytes_compare(case[0], case[1]), case[2])

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
        good_test_cases = {
            # from draft-01: 3.1.2.  RSA Example
            'request-line host date digest content-length': b'POST /foo HTTP/1.1\nhost: example.org\ndate: Tue, 07 Jun 2014 20:51:35 GMT\ndigest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=\ncontent-length: 18',
            # draft-02
            '(request-line) host date digest content-length': b'(request-line): post /foo\nhost: example.org\ndate: Tue, 07 Jun 2014 20:51:35 GMT\ndigest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=\ncontent-length: 18',
            # draft-03
            '(request-target) host date digest content-length': b'(request-target): post /foo\nhost: example.org\ndate: Tue, 07 Jun 2014 20:51:35 GMT\ndigest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=\ncontent-length: 18'
        }

        for required_headers, result in good_test_cases.items():
            assert httpsig.utils.generate_message(
                required_headers=required_headers.split(),
                headers=HEADERS,
                host=HOST,
                method=METHOD,
                path=PATH,
                http_version=HTTP_VERSION) == result, 'header: %s\nexpect: %s\n' % (required_headers, result)

        exception_test_cases = [
            {'required_headers': ['(request-target)'], 'host': HOST, 'headers': HEADERS, 'exception': KeyError, 'method': '', 'path': '', 'http_version': ''},
            {'required_headers': ['(request-target)'], 'host': HOST, 'headers': HEADERS, 'exception': KeyError, 'method': 'GET', 'path': '', 'http_version': ''},
            {'required_headers': ['(request-target)'], 'host': HOST, 'headers': HEADERS, 'exception': KeyError, 'method': '', 'path': '/', 'http_version': ''},
            {'required_headers': ['(request-line)'], 'host': HOST, 'headers': HEADERS, 'exception': KeyError, 'method': '', 'path': ''},
            {'required_headers': ['(request-line)'], 'host': HOST, 'headers': HEADERS, 'exception': KeyError, 'method': 'GET', 'path': '', 'http_version': ''},
            {'required_headers': ['(request-line)'], 'host': HOST, 'headers': HEADERS, 'exception': KeyError, 'method': '', 'path': '/', 'http_version': ''},
            {'required_headers': ['request-line'], 'host': HOST, 'headers': HEADERS, 'exception': KeyError, 'method': '', 'path': '', 'http_version': ''},
            {'required_headers': ['request-line'], 'host': HOST, 'headers': HEADERS, 'exception': KeyError, 'method': 'GET', 'path': '', 'http_version': ''},
            {'required_headers': ['request-line'], 'host': HOST, 'headers': HEADERS, 'exception': KeyError, 'method': '', 'path': '/', 'http_version': ''},
            {'required_headers': ['request-line'], 'host': HOST, 'headers': HEADERS, 'exception': KeyError, 'method': '', 'path': '', 'http_version': 'HTTP/1.1'},
            {'required_headers': ['request-line'], 'host': HOST, 'headers': HEADERS, 'exception': KeyError, 'method': 'GET', 'path': '', 'http_version': 'HTTP/1.1'},
            {'required_headers': ['request-line'], 'host': HOST, 'headers': HEADERS, 'exception': KeyError, 'method': '', 'path': '/', 'http_version': 'HTTP/1.1'},
            {'required_headers': [], 'host': HOST, 'headers': [], 'exception': KeyError, 'method': '', 'path': '', 'http_version': ''},
            {'required_headers': ['haha'], 'host': HOST, 'headers': [], 'exception': KeyError, 'method': '', 'path': '', 'http_version': ''},
            {'required_headers': ['host'], 'host': '', 'headers': [], 'exception': KeyError, 'method': '', 'path': '', 'http_version': ''}
        ]
        for case in exception_test_cases:
            try:
                httpsig.utils.generate_message(
                    required_headers=case['required_headers'],
                    headers=case['headers'],
                    host=case['host'],
                    method=case['method'],
                    path=case['path'],
                    http_version=case['http_version'])
                self.fail('No exception was raised')
            except Exception as ex:
                self.assertIsInstance(ex, case['exception'], str(case))

    def test_parse_authorization_header(self):
        if six.PY3:
            good_test_cases = [
                (
                    'Signature keyId="Test",algorithm="rsa-sha512",headers="(request-target) host date content-type content-md5 content-length"',
                    ('Signature', httpsig.utils.CaseInsensitiveDict({
                        'keyId': 'Test',
                        'algorithm': 'rsa-sha512',
                        'headers': '(request-target) host date content-type content-md5 content-length'}))
                ),
                (
                    b'Signature keyId="Test",algorithm="rsa-sha512",headers="(request-target) host date content-type content-md5 content-length"',
                    ('Signature', httpsig.utils.CaseInsensitiveDict({
                        'keyId': 'Test',
                        'algorithm': 'rsa-sha512',
                        'headers': '(request-target) host date content-type content-md5 content-length'}))
                ),
                (
                    'Signature keyId="Test",algorithm=,headers="(request-target) host date content-type content-md5 content-length",=123',
                    ('Signature', httpsig.utils.CaseInsensitiveDict({
                        'keyId': 'Test',
                        'headers': '(request-target) host date content-type content-md5 content-length'}))
                ),
                (
                    'Signature keyId="Test", algorithm="rsa-sha512" ,headers="(request-target) host date content-type content-md5 content-length"',
                    ('Signature', httpsig.utils.CaseInsensitiveDict({
                        'keyId': 'Test',
                        'algorithm': 'rsa-sha512',
                        'headers': '(request-target) host date content-type content-md5 content-length'}))
                )
            ]
        elif six.PY2:
            good_test_cases = [
                (
                    'Signature keyId="Test",algorithm="rsa-sha512",headers="(request-target) host date content-type content-md5 content-length"',
                    ('Signature', httpsig.utils.CaseInsensitiveDict({
                        'keyId': 'Test',
                        'algorithm': 'rsa-sha512',
                        'headers': '(request-target) host date content-type content-md5 content-length'}))
                ),
                (
                    u'Signature keyId="Test",algorithm="rsa-sha512",headers="(request-target) host date content-type content-md5 content-length"',
                    ('Signature', httpsig.utils.CaseInsensitiveDict({
                        'keyId': 'Test',
                        'algorithm': 'rsa-sha512',
                        'headers': '(request-target) host date content-type content-md5 content-length'}))
                ),
                (
                    'Signature keyId="Test",algorithm=,headers="(request-target) host date content-type content-md5 content-length",=123',
                    ('Signature', httpsig.utils.CaseInsensitiveDict({
                        'keyId': 'Test',
                        'headers': '(request-target) host date content-type content-md5 content-length'}))
                ),
                (
                    'Signature keyId="Test", algorithm="rsa-sha512" ,headers="(request-target) host date content-type content-md5 content-length"',
                    ('Signature', httpsig.utils.CaseInsensitiveDict({
                        'keyId': 'Test',
                        'algorithm': 'rsa-sha512',
                        'headers': '(request-target) host date content-type content-md5 content-length'}))
                )
            ]

        for case in good_test_cases:
            self.assertEqual(httpsig.utils.parse_authorization_header(case[0]), case[1])

        exception_test_cases = [
            ('Signature-keyId="Test",algorithm="rsa-sha512"', ValueError),
            ('', ValueError),
            (123, AttributeError)
        ]
        for case in exception_test_cases:
            try:
                httpsig.utils.parse_authorization_header(case[0])
                self.fail('No exception was raised.')
            except Exception as ex:
                self.assertIsInstance(ex, case[1])

    def test_get_fingerprint(self):
        with open(os.path.join(os.path.dirname(__file__), 'rsa_public.pem'), 'r') as k:
            key = k.read()
        fingerprint = httpsig.utils.get_fingerprint(key)
        self.assertEqual(fingerprint, "73:61:a2:21:67:e0:df:be:7e:4b:93:1e:15:98:a5:b7")

        test_case = [('ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDFuqGVUQjw8KtwY+JIZx4uGhy2ap4QLjtUOaH/o8vxUeAk7P5Olhxzr2FBnCUjS6iZmuzZzviXI3NhyR2ic661hFlXxkJaEa6DruRakZ6P+uMFPmvE+RsOp0ppcW2uGO5Y8C0OqEMI4NT2E4/LIzM7kmspF7cvJajUa9UQ6ZpKG/YfZpOs6xug8uT+1GCiPC+w/GX2UWtj2kmTUUJZWddSev9kHUDbPl6GwLMmnJ3UB9C7rdNlhupArJAsL+7eAXR9DcV5Fo7kDtFYiZllwRAWVghVjeGyEkSOEEbVCtI+l+V2cFYlta1mPXJQsshKvzYQ25IjnDBnXGg/HpwCppWT httpsig', '99:18:ae:30:be:c4:12:ce:b5:17:2b:56:ee:a9:ab:23')]

        for case in test_case:
            self.assertEqual(httpsig.utils.get_fingerprint(case[0]), case[1])
