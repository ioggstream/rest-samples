# https://python-jose.readthedocs.io/en/latest/jws/index.html#examples
from jose import jws
from os.path import isfile
import time
from hashlib import sha256
import OpenSSL
from cert import extract_public_key, load_private_key, serialize_key
from cryptography.hazmat.primitives.asymmetric import rsa, ec
import yaml


def get_algorithm(key):
    keymap = {
        rsa.RSAPublicKey: 'RS256',
        ec.EllipticCurvePublicKey: 'ES256',
        rsa.RSAPrivateKey: 'RS256',
        ec.EllipticCurvePrivateKey: 'ES256'
    }
    for k, v in keymap.items():
        if isinstance(key, k):
            return v
    raise NotImplementedError("Key algorithm not supported", key)


def verify(cert_path, token):
    with open(cert_path, 'rb') as fp:
        return verify_s(fp.read(), token)


def verify_s(stream, token):
    public_key = extract_public_key(stream)
    public_key_as_string = serialize_key(public_key).decode('ascii')
    return jws.verify(token, public_key_as_string, algorithms=get_algorithm(public_key))


def sign_header(fpath, claim):
    with open(fpath, 'rb') as fh:
        k = fh.read()
    return jws.sign(claim, k, algorithm=get_algorithm(load_private_key(fpath)))


def test_sign_verify():
    from tempfile import mktemp
    from cert import create_key
    from os import unlink
    h = {'a': 1}

    for algorithm in ('RSA', 'ECDSA'):
        try:
            f = mktemp()
            create_key(f, algorithm=algorithm)
            token = sign_header(f + '.key', h)
            yield verify, f + '.pem', token
        finally:
            unlink(f + ".pem")
            unlink(f + ".key")
            unlink(f + ".pub")


def hash_body(body):
    return sha256(body).hexdigest()


def cli(url="http://localhost:8080/ping", data=None):
    """A simple client validating Non-Repudiation header."""
    import requests
    header = {
        'iss': 'ipa/oou',
        'aud': 'ipa/oou',
        'iat': int(time.time()),
        'exp': int(time.time() + 10),
        'jti': 'the header id',
        'sub': 'the message id',
        'date': '2018-01-01T12:00:00Z',
        'b_hash': 'my-body-hash'
    }

    if data:
        header['b_hash'] = hash_body(data)
    headers = {
        'Non-Repudiation': sign_header('client.key', header)
    }
    res = requests.get(url, headers=headers)
    print(res.headers)
    print(res.content)
    print("verify Non-Repudiation")
    non_repudiation = res.headers['Non-Repudiation']
    claims = yaml.load(jws.get_unverified_claims(non_repudiation))
    x5c = claims['x5c']
    if x5c:
        cert = f'-----BEGIN CERTIFICATE-----\n{x5c}\n-----END CERTIFICATE-----'.encode('ascii')
    else:
        cert = open('server.pub', 'rb').read()
    verify_s(cert, non_repudiation)
    print(res)

def test_cli():
    ret = cli(data={"hello": "world"})
