#! /usr/bin/env python3

import argparse

from jwt_token import JWT

parser = argparse.ArgumentParser('Analyse a jwt')
parser.add_argument('jwt')
parser.add_argument('--dict')
args = parser.parse_args()

strjwt = args.jwt

print(strjwt)
jwt = JWT(strjwt, key='')
jwt.json_header['alg'] = 'none'

print()
print()

print(jwt)
print()
print(jwt.encoded())

if args.dict:
    with open(args.dict, 'rt') as f:
        i = 0
        for line in f:
            i += 1
            jwt.test_key(bytes(line.rstrip('\n'), 'utf-8'))
        print('[-] key not found in {} keys in dict'.format(i))
