# https://python-jose.readthedocs.io/en/latest/jws/index.html#examples
from jose import jws
from Crypto.PublicKey import RSA
from os.path import isfile
import time

from hashlib import sha256

header = {
    'iss': 'ipa/oou',
    'aud': 'ipa/oou',
    'iat': '2018-01-01T11:00:00Z',
    'exp': '2018-01-01T12:00:00Z',
    'jti': 'the header id',
    'sub': 'the message id',
    'b_hash': 'my-body-hash'
}


def create_key(fpath):
    if isfile(fpath + ".key"):
        return
    key = RSA.generate(2048)
    with open(fpath + ".key", 'wb') as fh:
        fh.write(key.exportKey("PEM"))

    with open(fpath + ".pub", 'wb') as fh:
        fh.write(key.publickey().exportKey('PEM'))


def verify(fpath, hdr):
    pk = open(fpath).read()
    try:
        jws.verify(hdr, pk, algorithms='RS256')
    except:
        raise


def sign_header(fpath, hdr, x5c=False):
    with open(fpath) as fh:
        k = fh.read()

    return jws.sign(hdr, k, algorithm='RS256')


def hash_body(body):
    return sha256(body).hexdigest()


def cli(url="http://localhost:8080/ping", data=None):
    """A simple client validating Non-Repudiation header."""
    import requests
    h = {
        'iss': 'client',
        'aud': url,
        'sub': 'document_id',
        'exp': int(time.time() + 10)
    }
    if data:
        h['b_hash'] = hash_body(data)
    headers = {
        'Non-Repudiation': sign_header('client.key', h)
    }
    res = requests.get(url, headers=headers)
    print(res.headers)
    print(res.content)
    print("verify Non-Repudiation")
    verify('server.pub', res.headers['Non-Repudiation'])
    print(res)
