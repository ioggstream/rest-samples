from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, PublicFormat, load_pem_private_key
from cryptography import x509
from os.path import isfile
from socket import gethostname
from cryptography.hazmat.primitives.serialization import load_pem_public_key


def generate_ecdsa_key(key_curve='secp256r1'):
    key_curve = key_curve.upper()
    if not key_curve.startswith('SEC'):
        raise ValueError("Not a curve: " + key_curve)
    if not hasattr(ec, key_curve):
        raise NotImplementedError('Unsupported key curve: ' + key_curve)

    gen_curve = getattr(ec, key_curve)
    key = ec.generate_private_key(gen_curve(), default_backend())
    return key


def generate_rsa_key(key_size=2048):
    return rsa.generate_private_key(key_size=key_size, public_exponent=65537, backend=default_backend())


def serialize_key(key):
    if hasattr(key, 'private_bytes'):
        return key.private_bytes(
            encoding=Encoding.PEM, format=PrivateFormat.TraditionalOpenSSL, encryption_algorithm=NoEncryption())
    elif hasattr(key, 'public_bytes'):
        return key.public_bytes(encoding=Encoding.PEM, format=PublicFormat.SubjectPublicKeyInfo)
    else:
        raise NotImplementedError("Can't detect key type.")


def create_key(fpath, algorithm='ECDSA'):
    if isfile(fpath + ".key"):
        return
    if algorithm == 'ECDSA':
        f = generate_ecdsa_key
    elif algorithm == 'RSA':
        f = generate_rsa_key
    else:
        raise NotImplementedError("Allowed algorithms: RSA, ECDSA")

    key = f()
    with open(fpath + ".key", 'wb') as fh:
        fh.write(serialize_key(key))

    with open(fpath + ".pub", 'wb') as fh:
        fh.write(serialize_key(key.public_key()))

    with open(fpath + ".pem", 'wb') as fh:
        fh.write(create_self_signed_cert(key))


def test_key():
    from tempfile import TemporaryFile, mktemp

    k_path = mktemp()
    for algorithm in ('ECDSA', 'RSA'):
        create_key(k_path, algorithm)
        assert(isfile(k_path + ".key"))
        load_private_key(k_path + ".key")
        assert(isfile(k_path + ".pub"))
        assert(isfile(k_path + ".pem"))


def load_private_key(key_file):
    with open(key_file, 'rb') as fh:
        key_data = fh.read()
    key = load_pem_private_key(
        key_data, password=None, backend=default_backend())
    return key


def create_self_signed_cert(key):
    """
    self-signed cert and keypair and write them into that directory.
    """
    ca_key = generate_rsa_key(key_size=4096)

    name = x509.Name([
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CA"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, gethostname())
    ])
    alt_names = x509.SubjectAlternativeName([
        # best practice seem to be to include the hostname in the SAN,
        # which *SHOULD* mean COMMON_NAME is ignored.
        x509.DNSName(gethostname()),
    ])
    # path_len=0 means this cert can only sign itself, not other certs.
    basic_contraints = x509.BasicConstraints(ca=True, path_length=0)
    now = datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1000)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=10 * 365))
        .add_extension(basic_contraints, False)
        .add_extension(alt_names, False)
        .sign(ca_key, hashes.SHA256(), default_backend())
    )
    return cert.public_bytes(encoding=serialization.Encoding.PEM)


def extract_public_key(pem_data):
    cert = x509.load_pem_x509_certificate(pem_data, default_backend())
    return cert.public_key()


def cert_to_string(cert_pem):
    return cert_pem.replace('\n', '').split("-----")[2]
