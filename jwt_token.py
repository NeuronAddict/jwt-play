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



        if len(pieces) > 2:
            self.initial_encoded_signature = pieces[2]
            # self.signature_ = base64url_decode(self.signature_.encode('utf-8'))

        self.key = key

        # print('[*] signature : {} ({} len)'.format(signature, len(signature)))

    def __str__(self):
        return '[jwt:header={},payload={}, signature={})]'.format(self.header(), self.payload(), self.signature())

    def encoded(self):
        signature = self.signature()
        if signature is not None and len(signature) > 0:
            signature = base64url_encode(signature).decode()
        else:
            signature = ''
        return '{}.{}.{}'.format(base64url_encode(self.header().encode()).decode(),
                                 base64url_encode(self.payload().encode()).decode(),
                                 signature)

    # noinspection PyMethodMayBeStatic
    def signature_none(self, to_sign, key):
        return ''

    def signature_RS256(self, to_sign, key):
        m = hashlib.sha256()
        return hmac.new(key, to_sign, hashlib.sha256).digest()

    def signature(self, key=None):
        """
        Signature (encoded)
        :param key:
        :return: binary signature
        """
        to_sign = base64url_encode(self.header().encode()) + b'.' + base64url_encode(self.payload().encode())
        if key is not None:
            return self.switcher(str(self.json_header['alg']), to_sign, key)
        else:
            if self.key is not None:
                return self.switcher(str(self.json_header['alg']), to_sign, self.key)
            return base64url_decode(self.initial_encoded_signature.encode())

    def switcher(self, param, to_sign, key):
        sw = {
            'RS256': self.signature_RS256,
            'none': self.signature_none
        }
        f = sw[param]
        return f(to_sign, key)

    def header(self):
        return json.dumps(self.json_header)

    def payload(self):
        return json.dumps(self.json_payload)

    def test_key(self, key):
        return hmac.compare_digest(self.signature(key), self.signature())
