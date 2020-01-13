import hashlib
import hmac
import json

from custombase64 import base64url_decode, base64url_encode


class JWT:

    def __init__(self, encoded, key=None):
        pieces = encoded.split('.')

        if len(pieces) < 2:
            raise Exception('Token must have a point')

        header_ = pieces[0]
        payload_ = pieces[1]

        header = base64url_decode(header_.encode('utf-8'))
        payload = base64url_decode(payload_.encode('utf-8'))

        self.json_header = json.loads(header)
        self.json_payload = json.loads(payload)

        self.alg = self.json_header['alg']

        if len(pieces) > 2:
            self.initial_signature = pieces[2]
            # self.signature_ = base64url_decode(self.signature_.encode('utf-8'))

        self.key = key
        # print('[*] signature : {} ({} len)'.format(signature, len(signature)))

    def __str__(self):
        return '[jwt:header={},payload={}, signature={})]'.format(self.header(), self.payload(), self.signature())

    def encoded(self):
        signature = self.signature()
        if signature is not None and len(signature) > 0:
            signature = '.' + signature
        return '{}.{}{}'.format(base64url_encode(self.header().encode()).decode(), base64url_encode(self.payload().encode()).decode(),
                                signature)

    def signature_plain(self, to_sign):
        return to_sign

    def signature_RS256(self, to_sign):
        m = hashlib.sha256()
        return hmac.new(self.key, to_sign, hashlib.sha256).digest()

    def signature(self, recalculate=False):
        if recalculate:
            to_sign = (base64url_encode(self.header) + b'.' + base64url_encode(self.payload))
            return self.switcher(str(self.alg), to_sign)
        else:
            return self.initial_signature

    def switcher(self, param, to_sign):
        sw = {
            'RS256': self.signature_RS256,
            'plain': self.signature_plain
        }
        f = sw[param]
        return f(to_sign)

    def header(self):
        return json.dumps(self.json_header)

    def payload(self):
        return json.dumps(self.json_payload)
