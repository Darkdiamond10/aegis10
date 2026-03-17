import sys
sys.path.append('c2_server')
from server_crypto import SERVER_CRYPTO
print(f"Master key: {SERVER_CRYPTO.master_key.hex()}")
print(f"Session key: {SERVER_CRYPTO.session_key.hex()}")
