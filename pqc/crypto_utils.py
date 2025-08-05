from nacl.signing import SigningKey
from nacl.encoding import HexEncoder

def generate_pqc_keys():
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key
    return verify_key.encode(encoder=HexEncoder), signing_key.encode(encoder=HexEncoder)

def sign_message(private_key_bytes, message_bytes):
    signing_key = SigningKey(private_key_bytes, encoder=HexEncoder)
    signed = signing_key.sign(message_bytes)
    return signed.signature.hex()


def verify_signature(public_key_bytes, message_bytes, signature_hex):
    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignatureError

    verify_key = VerifyKey(public_key_bytes, encoder=HexEncoder)
    try:
        verify_key.verify(message_bytes, bytes.fromhex(signature_hex))
        return True
    except BadSignatureError:
        return False
