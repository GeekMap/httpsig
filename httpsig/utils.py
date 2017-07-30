import re
import hashlib
import base64
from functools import reduce
import six

try:
    # Python 3
    from urllib.request import parse_http_list
except ImportError:  # pragma: no cover
    # Python 2
    from urllib2 import parse_http_list

from Crypto.Hash import SHA, SHA256, SHA512

ALGORITHMS = frozenset(['rsa-sha1', 'rsa-sha256', 'rsa-sha512', 'hmac-sha1', 'hmac-sha256', 'hmac-sha512'])
HASHES = {'sha1': SHA,
          'sha256': SHA256,
          'sha512': SHA512}


class HttpSigException(Exception):
    pass


def ct_bytes_compare(byte_l, byte_r):
    """
    Constant-time string compare.
    http://codahale.com/a-lesson-in-timing-attacks/
    """
    if not isinstance(byte_l, six.binary_type):
        byte_l = byte_l.encode('utf8')
    if not isinstance(byte_r, six.binary_type):
        byte_r = byte_r.encode('utf8')

    if len(byte_l) != len(byte_r):
        return False

    result = reduce(lambda r, b: r | (b[0] ^ b[1]), map(lambda b: (ord(b[0]), ord(b[1])) if six.PY2 else b, zip(byte_l, byte_r)), 0)

    return result == 0


def generate_message(required_headers, headers, host=None, method=None, path=None, http_version=None):
    headers = CaseInsensitiveDict(headers)

    if not required_headers:
        required_headers = ['date']

    signable_list = []
    for header in required_headers:
        header = header.lower()
        if header == '(request-target)':  # draft-03 to draft-07
            if not method or not path:
                raise KeyError('method and path arguments required when using "(request-target)"')
            signable_list.append('%s: %s %s' % (header, method.lower(), path))
        elif header == '(request-line)':  # draft-02
            if not method or not path:
                raise KeyError('method and path arguments required when using "(request-line)"')
            signable_list.append('%s: %s %s' % (header, method.lower(), path))
        elif header == 'request-line':   # draft-00, draft-01
            if not method or not path or not http_version:
                raise KeyError('method, path and http_version arguments required when using "request-line"')
            signable_list.append('%s %s %s' % (method, path, http_version))

        elif header == 'host':
            # 'host' special case due to requests lib restrictions
            # 'host' is not available when adding auth so must use a param
            # if no param used, defaults back to the 'host' header
            if not host:
                if 'host' in headers:
                    host = headers[header]
                else:
                    raise KeyError('missing required header "%s"' % (header))
            signable_list.append('%s: %s' % (header, host))
        else:
            if header not in headers:
                raise KeyError('missing required header "%s"' % (header))

            signable_list.append('%s: %s' % (header, headers[header]))

    signable = '\n'.join(signable_list).encode('ascii')
    return signable


def parse_authorization_header(header):
    if not isinstance(header, six.string_types):
        header = header.decode('ascii')  # HTTP headers cannot be Unicode.

    auth = header.split(' ', 1)
    if len(auth) < 2:
        raise ValueError('Invalid authorization header. (eg. Method key1=value1,key2="value, \"2\"")')

    # Split up any args into a dictionary.
    values = {}
    auth_value = auth[1]

    # This is tricky string magic.  Let urllib do it.
    fields = parse_http_list(auth_value)
    for item in fields:
        # Only include keypairs.
        if '=' in item:
            # Split on the first '=' only.
            key, value = item.split('=', 1)
            if not (len(key) and len(value)):
                continue

            # Unquote values, if quoted.
            if value[0] == '"':
                value = value[1:-1]

            values[key] = value

    # ("Signature", {"headers": "date", "algorithm": "hmac-sha256", ... })
    return (auth[0], CaseInsensitiveDict(values))


def build_signature_template(key_id, algorithm, headers):
    """
    Build the Signature template for use with the Authorization header.

    key_id is the mandatory label indicating to the server which secret to use
    algorithm is one of the six specified algorithms
    headers is a list of http headers to be included in the signing string.

    The signature must be interpolated into the template to get the final Authorization header value.
    """
    param_map = {'keyId': key_id,
                 'algorithm': algorithm,
                 'signature': '%s'}
    if headers:
        headers = [h.lower() for h in headers]
        param_map['headers'] = ' '.join(headers)
    kv_pairs = map('{0[0]}="{0[1]}"'.format, param_map.items())
    kv_string = ','.join(kv_pairs)
    sig_string = 'Signature {0}'.format(kv_string)
    return sig_string


# based on http://stackoverflow.com/a/2082169/151401
class CaseInsensitiveDict(dict):
    def __init__(self, d=None, **kwargs):
        super(CaseInsensitiveDict, self).__init__(**kwargs)
        if d:
            self.update((k.lower(), v) for k, v in six.iteritems(d))

    def __setitem__(self, key, value):
        super(CaseInsensitiveDict, self).__setitem__(key.lower(), value)

    def __getitem__(self, key):
        return super(CaseInsensitiveDict, self).__getitem__(key.lower())

    def __contains__(self, key):
        return super(CaseInsensitiveDict, self).__contains__(key.lower())


# currently busted...
def get_fingerprint(key):
    """
    Takes an ssh public key and generates the fingerprint.

    See: http://tools.ietf.org/html/rfc4716 for more info
    """
    if key.startswith('ssh-rsa'):
        key = key.split(' ')[1]
    else:
        regex = r'\-{4,5}[\w|| ]+\-{4,5}'
        key = re.split(regex, key)[1]

    key = key.replace('\n', '')
    key = key.strip().encode('ascii')
    key = base64.b64decode(key)
    fp_plain = hashlib.md5(key).hexdigest()
    return ':'.join(a + b for a, b in zip(fp_plain[::2], fp_plain[1::2]))
