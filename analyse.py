#! /usr/bin/env python3

import argparse
import hmac
import sys
import base64
import hashlib


def base64url_decode(encoded_bytes):
    rem = len(encoded_bytes) % 4

    if rem > 0:
        encoded_bytes += b'=' * (4 - rem)

    return base64.urlsafe_b64decode(encoded_bytes)


def base64url_encode(raw_bytes):
    return base64.urlsafe_b64encode(raw_bytes).replace(b'=', b'')


parser = argparse.ArgumentParser('Analyse a jwt')
parser.add_argument('jwt')
parser.add_argument('dict')
args = parser.parse_args()

jwt = args.jwt
pieces = jwt.split('.')


if len(pieces) < 2:
    raise Exception('Token must have a point')

header_ = pieces[0]
payload_ = pieces[1]

header = base64url_decode(header_.encode('utf-8'))
payload = base64url_decode(payload_.encode('utf-8'))

print('[*] header : {}'.format(header))
print('[*] payload : {}'.format(payload))


if len(pieces) == 2:
    print('[-] no signature', file=sys.stderr)
    quit()

signature_ = pieces[2]
signature = base64url_decode(signature_.encode('utf-8'))

print('[*] signature : {} ({} len)'.format(signature, len(signature)))

m = hashlib.sha256()

tosign = (base64url_encode(header) + b'.' + base64url_encode(payload))
print('[*] tosign : {}'.format(tosign))


def testkey(key):
    hashh = hmac.new(key, tosign, hashlib.sha256).digest()
    # print('[*] get hash : {} ({} len)'.format(hashh, len(hashh)))
    if hmac.compare_digest(hashh, signature):
        print('[+] key found : {}'.format(key.decode('utf-8')))
        quit()


with open(args.dict, 'rt') as f:
    i = 0
    for line in f:
        i += 1
        testkey(bytes(line.rstrip('\n'), 'utf-8'))
    print('[-] key not found in {} keys in dict'.format(i))
