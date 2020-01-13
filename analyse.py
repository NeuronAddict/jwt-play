#! /usr/bin/env python3

import argparse
import hmac
import sys
import hashlib

from custombase64 import base64url_decode, base64url_encode
from jwt_token import JWT

parser = argparse.ArgumentParser('Analyse a jwt')
parser.add_argument('jwt')
parser.add_argument('--dict')
args = parser.parse_args()

strjwt = args.jwt

print(strjwt)
jwt = JWT(strjwt)
print(jwt)
print()
print(jwt.encoded())
jwt.json_header['alg'] = 'plain'

print()
print()

print(jwt)
print()
print(jwt.encoded())



# def testkey(key):
#     hashh = hmac.new(key, tosign, hashlib.sha256).digest()
#     # print('[*] get hash : {} ({} len)'.format(hashh, len(hashh)))
#     if hmac.compare_digest(hashh, signature):
#         print('[+] key found : {}'.format(key.decode('utf-8')))
#         quit()
#
#
# if args.dict:
#     with open(args.dict, 'rt') as f:
#         i = 0
#         for line in f:
#             i += 1
#             testkey(bytes(line.rstrip('\n'), 'utf-8'))
#         print('[-] key not found in {} keys in dict'.format(i))
