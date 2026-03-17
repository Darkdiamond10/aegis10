with open("c2_server/server.py", "r") as f:
    content = f.read()

# We need to insert the beacon logic back
new_beacon = r"""
        if env and ct:
            # We must decrypt the beacon to mathematically progress the server's AES-GCM sequence!
            # The client used the envelope WITH ZERO IV AND TAG as AAD.
            aad_env = bytearray(data[:ENVELOPE_SIZE])

            # offsets: iv is bytes 16 to 28, tag is bytes 28 to 44
            aad_env[16:28] = b'\x00' * 12 # iv
            aad_env[28:44] = b'\x00' * 16 # tag

            try:
                # Decrypting automatically increments SERVER_CRYPTO counters to match the client
                decrypted_task = SERVER_CRYPTO.decrypt(ct, env["iv"], env["tag"], bytes(aad_env))
                log_print(f"  └─ Decrypted Beacon Payload ({len(decrypted_task)} bytes)", Colors.CYAN)
            except Exception as e:
                log_print(f"  └─ Failed to decrypt beacon: {e}", Colors.FAIL)

        # The server also responds to beacons with an encrypted response if it has tasks!
"""

with open("c2_server/server.py", "w") as f:
    f.write(content)
