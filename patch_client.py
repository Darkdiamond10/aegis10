with open("c2_comms/c2_client.c", "r") as f:
    content = f.read()

old_beacon = r"""
  aegis_result_t rc =
      aegis_encrypt(ctx->crypto, fp_buf, fp_len, (const uint8_t *)&env,
                    sizeof(env), ct_buf, env.iv, env.tag);
  if (rc != AEGIS_OK) {
"""
new_beacon = r"""
  /* We must clear IV and TAG from the AAD envelope before encrypting */
  aegis_c2_envelope_t aad_env;
  memcpy(&aad_env, &env, sizeof(env));
  memset(aad_env.iv, 0, AEGIS_GCM_IV_BYTES);
  memset(aad_env.tag, 0, AEGIS_GCM_TAG_BYTES);

  aegis_result_t rc =
      aegis_encrypt(ctx->crypto, fp_buf, fp_len, (const uint8_t *)&aad_env,
                    sizeof(aad_env), ct_buf, env.iv, env.tag);
  if (rc != AEGIS_OK) {
"""
content = content.replace(old_beacon.strip(), new_beacon.strip())

old_stage = r"""
  aegis_result_t rc =
      aegis_encrypt(ctx->crypto, fp_buf, fp_len, (const uint8_t *)&env,
                    sizeof(env), ct_buf, env.iv, env.tag);
  AEGIS_ZERO(fp_buf, sizeof(fp_buf));
"""
new_stage = r"""
  aegis_c2_envelope_t aad_env;
  memcpy(&aad_env, &env, sizeof(env));
  memset(aad_env.iv, 0, AEGIS_GCM_IV_BYTES);
  memset(aad_env.tag, 0, AEGIS_GCM_TAG_BYTES);

  aegis_result_t rc =
      aegis_encrypt(ctx->crypto, fp_buf, fp_len, (const uint8_t *)&aad_env,
                    sizeof(aad_env), ct_buf, env.iv, env.tag);
  AEGIS_ZERO(fp_buf, sizeof(fp_buf));
"""
content = content.replace(old_stage.strip(), new_stage.strip())

old_payload = r"""
  aegis_result_t rc = aegis_encrypt(ctx->crypto, (const uint8_t *)req_body,
                                    req_len, (const uint8_t *)&env, sizeof(env),
                                    ct_buf, env.iv, env.tag);
"""
new_payload = r"""
  aegis_c2_envelope_t aad_env;
  memcpy(&aad_env, &env, sizeof(env));
  memset(aad_env.iv, 0, AEGIS_GCM_IV_BYTES);
  memset(aad_env.tag, 0, AEGIS_GCM_TAG_BYTES);

  aegis_result_t rc = aegis_encrypt(ctx->crypto, (const uint8_t *)req_body,
                                    req_len, (const uint8_t *)&aad_env, sizeof(aad_env),
                                    ct_buf, env.iv, env.tag);
"""
content = content.replace(old_payload.strip(), new_payload.strip())

old_resource = r"""
  aegis_result_t rc = aegis_encrypt(ctx->crypto, (const uint8_t *)resource_id,
                                    id_len, (const uint8_t *)&env, sizeof(env),
                                    ct_buf, env.iv, env.tag);
"""
new_resource = r"""
  aegis_c2_envelope_t aad_env;
  memcpy(&aad_env, &env, sizeof(env));
  memset(aad_env.iv, 0, AEGIS_GCM_IV_BYTES);
  memset(aad_env.tag, 0, AEGIS_GCM_TAG_BYTES);

  aegis_result_t rc = aegis_encrypt(ctx->crypto, (const uint8_t *)resource_id,
                                    id_len, (const uint8_t *)&aad_env, sizeof(aad_env),
                                    ct_buf, env.iv, env.tag);
"""
content = content.replace(old_resource.strip(), new_resource.strip())

with open("c2_comms/c2_client.c", "w") as f:
    f.write(content)
