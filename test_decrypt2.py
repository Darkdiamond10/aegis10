import base64
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import os

AEGIS_AES_KEY_BYTES = 32
AEGIS_HKDF_SALT_BYTES = 32
AEGIS_PSK_B64 = "Rz9kX3BhcnRuZXJzX2luX2NyaW1lX0xPX2FuZF9FTkk="
AEGIS_HKDF_INFO = b"aegis-nightshade-v1"

psk_raw = base64.b64decode(AEGIS_PSK_B64)
hkdf_salt = b'\xAA' * AEGIS_HKDF_SALT_BYTES

hkdf_master = HKDF(
    algorithm=hashes.SHA256(),
    length=AEGIS_AES_KEY_BYTES,
    salt=hkdf_salt,
    info=AEGIS_HKDF_INFO,
    backend=default_backend()
)
master_key = hkdf_master.derive(psk_raw)

session_info = b"aegis-session-key-v1-init"
hkdf_session = HKDF(
    algorithm=hashes.SHA256(),
    length=AEGIS_AES_KEY_BYTES,
    salt=hkdf_salt,
    info=session_info,
    backend=default_backend()
)
session_key = hkdf_session.derive(master_key)

print(f"Session key: {session_key.hex()}")

# Try encrypting a simple beacon format
C2_MAGIC = 0xAE610C2D
C2_MSG_BEACON = 0x01
seq = 0
node_id = b'\x00'*16

env_aad = struct.pack("<IIII12s16s16s", C2_MAGIC, C2_MSG_BEACON, 0, seq, b'\x00'*12, b'\x00'*16, node_id)
print(f"Env length: {len(env_aad)}")
print(f"Env AAD Hex: {env_aad.hex()}")

iv = struct.pack(">I", 0) + os.urandom(8)
print(f"IV: {iv.hex()}")

aesgcm = AESGCM(session_key)
ciphertext_and_tag = aesgcm.encrypt(iv, b"", env_aad)

tag = ciphertext_and_tag[-16:]

print(f"Tag: {tag.hex()}")

# Construct envelope to parse in python code
env = struct.pack("<IIII12s16s16s", C2_MAGIC, C2_MSG_BEACON, 0, seq, iv, tag, node_id)

data = env

aad_env = bytearray(data[:60])
aad_env[16:28] = b'\x00' * 12
aad_env[28:44] = b'\x00' * 16

try:
    aesgcm.decrypt(iv, ciphertext_and_tag, bytes(aad_env))
    print("Success")
except Exception as e:
    print(f"Fail: {e}")
