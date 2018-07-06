from base64 import encodebytes, decodebytes
from hashlib import sha256
from struct import pack, unpack
import logging
logging.basicConfig(level=100)
log = logging.getLogger()


MOCK_MSG = b'When I grow up, I want to be a watermelon'

header_41 = b'\x00\x00\x00\x00\x00\x00\x00\x29'
header_16 = b'\x00\x00\x00\x00\x00\x00\x00\x10'
MOCK_ENCODED_MSG_41 = header_41 + MOCK_MSG
MOCK_ENCODED_MSG_41_HASH = b"dcRDgR2GM35DluAV13PzgnG6-pvQwPywfFvAu1UeFrs"

MOCK_ENCODED_MSG_16_HASH = b'IVa9shfs0nyKEhHqtB3WVNANJ2Njm5KjQLjRtnbkYJ4'
MOCK_ENCODED_MSG_16 = header_16 + (
    b'When I grow up, ' 
    b'8I[\xa6Re<\xaf\x91\xbf\xa2M+\xaay\xff\x9dy!\xaa\x0f\xa1\x9a>\xd9\xe9V/\xb3\x90\xeb@' # b'OElbplJlPK-Rv6JNK6p5_515IaoPoZo-2elWL7OQ60A'
    b'I want to be a w' 
    b'\x88\xf3)\x9a\x011\x1c\xfa\xdb\x11}\xffF\xfc\x0f\xe1\xddz}iJ\xe2_\xbe\xa7\xbeOR\xef\xca\xc8\xdd' # base64url_decode(b'iPMpmgExHPrbEX3_RvwP4d16fWlK4l--p75PUu_KyN0') 
    b'atermelon'
)



MSG_TEST = {
    16: [MOCK_ENCODED_MSG_16, MOCK_ENCODED_MSG_16_HASH],
    41: [MOCK_ENCODED_MSG_41, MOCK_ENCODED_MSG_41_HASH]
}


#
# Basic functions.
#

def base64url_encode(s):
    return encodebytes(s).split(b"=")[0].replace(b"+", b"-").replace(b'/', b'_')


def base64url_decode(s):
    return decodebytes(s.replace(b'-', b'+').replace(b'_', b'/') + b'===')


def mi_sha(x):
    return base64url_encode(sha256(x).digest())


def bin_sha(x):
    return sha256(x).digest()


def proof(chunk, prev_hash=None):
    if prev_hash:
        return bin_sha(chunk + prev_hash + b'\x01')
    return bin_sha(chunk + b'\x00')

#
# Decode
#

def test_get_block_size():
    for expected_block_size, data in MSG_TEST.items():
        encoded_msg, _ = data
        ret = get_block_size(encoded_msg)
        assert ret == expected_block_size, ret


def get_block_size(msg):
    l = msg[:8]
    return unpack('!q', l)[0]

def pack_block_size(l):
    return pack('!q', l)


def test_mi_decode_chunk():
    msg = mi_decode_chunk(MOCK_ENCODED_MSG_16, MOCK_ENCODED_MSG_16_HASH)
    ret = b''.join(msg)
    assert ret == MOCK_MSG


def mi_decode_chunk(msg, proof_0):
    """Decode a MICE encoded msg.

        param: msg - an encoded msg
        param: proof_0  - the binary sha256 of the proof
    """
    proof_0 = base64url_decode(proof_0)
    l = get_block_size(msg)
    for x in range(8, len(msg), l + 32):
        chunk = msg[x:x + l]
        proof_next = msg[x + l:x + l + 32]
        assert proof(chunk, proof_next) == proof_0, "Invalid proof"
        proof_0 = proof_next
        log.warning(chunk)
        yield chunk

def mi_decode(msg, proof_0):
    return b''.join(mi_decode_chunk(msg, proof_0))

#
# Encode
#

def test_split_msg_single():
    msg = MOCK_MSG
    testcases = {
        41: (MOCK_MSG, [MOCK_MSG]),
        16: (MOCK_MSG, [ b'atermelon', b'I want to be a w', b'When I grow up, ' ]),
    }
    for block_size, data in testcases.items():
       inputs, expected = data
       ret = list(mi_split_e(inputs, block_size))
       assert ret == expected


def mi_split_e(msg, bl):
    header = pack('!q', bl)
    l = len(msg)
    r = l % bl
    x = 8
    if r:
        yield msg[-r:]
    interval = list(range(l - r, 0, -bl))
    log.warning(interval)
    for x in interval:
        log.warning(x)
        yield msg[x - bl:x]


def test_mi_encode_in_chunks_41():
    msg, hash_ = MSG_TEST[41]
    bs, msg = get_block_size(msg), msg[8:]
    for x in mi_encode_in_chunks(msg, 41):
        pass
    assert base64url_encode(x) == hash_, base64url_encode(x)


def mi_encode_in_chunks(msg, l):
    prev_proof = None
    res = []
    mi_split_rev = mi_split_e(msg, l)
    log.warning(mi_split_rev)

    for chunk in mi_split_rev:
        prev_proof = proof(chunk, prev_proof)
        res.append(chunk)
        res.append(prev_proof)
    return res

def test_mi_encode():
    for block_size, data in MSG_TEST.items():
        expected_msg, expected_hash = data
        msg, header = mi_encode(MOCK_MSG, block_size)
        assert expected_hash == header
        assert expected_msg == msg

def mi_encode(msg, l):
    chunks = mi_encode_in_chunks(msg, l)
    mi_header, *chunks = reversed(chunks)
    return pack_block_size(l) + b''.join(chunks), base64url_encode(mi_header)
    

def test_roundtrip():
    for m in [
        (b'''La vispa teresa\navea tra l'erbetta'''),
        open("/data/Pictures/20091226/26122009.jpg", "rb").read()
    ]:
        e_data, hdr = mi_encode(m, 1024)
        data = mi_decode(e_data, hdr)
        print(mi_sha(data), mi_sha(m))
        assert data == m
        




