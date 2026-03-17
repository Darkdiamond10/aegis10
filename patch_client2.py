with open("c2_comms/c2_client.c", "r") as f:
    content = f.read()

# Replace all occurrences of `aegis_c2_envelope_t aad_env;` so there are no variable re-declarations.
content = content.replace("aegis_c2_envelope_t aad_env;", "{ aegis_c2_envelope_t aad_env;")
content = content.replace("ct_buf, env.iv, env.tag);\n  if (rc != AEGIS_OK)", "ct_buf, env.iv, env.tag); }\n  if (rc != AEGIS_OK)")
content = content.replace("ct_buf, env.iv, env.tag);\n  AEGIS_ZERO(fp_buf, sizeof(fp_buf));", "ct_buf, env.iv, env.tag); }\n  AEGIS_ZERO(fp_buf, sizeof(fp_buf));")

with open("c2_comms/c2_client.c", "w") as f:
    f.write(content)
