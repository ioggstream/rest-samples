# https://python-jose.readthedocs.io/en/latest/jws/index.html#examples
from jose import jws
from Crypto.PublicKey import RSA
from os.path import isfile
import time
from cryptography import x509
from cryptography.hazmat.backends import default_backend

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


from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

import OpenSSL

def generate_ecdsa_key(key_curve='secp256r1'):
    key_curve = key_curve.lower()
    if ('secp256r1' == key_curve):
        key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    elif ('secp384r1' == key_curve):
        key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    elif ('secp521r1' == key_curve):
        key = ec.generate_private_key(ec.SECP521R1(), default_backend())
    else:
        raise NotImplementedError('Unsupported key curve: ' + key_curve)
    key_pem = key.private_bytes(encoding=Encoding.PEM, format=PrivateFormat.TraditionalOpenSSL, encryption_algorithm=NoEncryption())
    return OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key_pem)


def create_key(fpath, algorithm='ECDSA'):
    if isfile(fpath + ".key"):
        return
    if algorithm == 'ECDSA':
        f = generate_ecdsa_key
    elif algorithm == 'RSA':
        f = lambda : RSA.generate(2048).exportKey("PEM")
    else:
        raise NotImplementedError("Allowed algorithms: RSA, ECDSA")
    
    with open(fpath + ".key", 'wb') as fh:
        fh.write(f())

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


def get_certificate_from_pem(pem_file):
    backend = default_backend()
    with open(pem_file, 'rb') as f:
        crt_data = f.read()
        return x509.load_pem_x509_certificate(crt_data, backend)
    

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
