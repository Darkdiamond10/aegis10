with open("c2_comms/c2_client.c", "r") as f:
    content = f.read()

old_beacon = r"""
  aegis_result_t rc =
      aegis_encrypt(ctx->crypto, fp_buf, fp_len, (const uint8_t *)&env,
                    sizeof(env), ct_buf, env.iv, env.tag);
"""
new_beacon = r"""
  aegis_c2_envelope_t aad_env_b;
  memcpy(&aad_env_b, &env, sizeof(env));
  memset(aad_env_b.iv, 0, AEGIS_GCM_IV_BYTES);
  memset(aad_env_b.tag, 0, AEGIS_GCM_TAG_BYTES);

  aegis_result_t rc =
      aegis_encrypt(ctx->crypto, fp_buf, fp_len, (const uint8_t *)&aad_env_b,
                    sizeof(aad_env_b), ct_buf, env.iv, env.tag);
"""
content = content.replace(old_beacon.strip(), new_beacon.strip())

old_stage = r"""
  aegis_result_t rc =
      aegis_encrypt(ctx->crypto, fp_buf, fp_len, (const uint8_t *)&env,
                    sizeof(env), ct_buf, env.iv, env.tag);
"""
new_stage = r"""
  aegis_c2_envelope_t aad_env_s;
  memcpy(&aad_env_s, &env, sizeof(env));
  memset(aad_env_s.iv, 0, AEGIS_GCM_IV_BYTES);
  memset(aad_env_s.tag, 0, AEGIS_GCM_TAG_BYTES);

  aegis_result_t rc =
      aegis_encrypt(ctx->crypto, fp_buf, fp_len, (const uint8_t *)&aad_env_s,
                    sizeof(aad_env_s), ct_buf, env.iv, env.tag);
"""
content = content.replace(old_stage.strip(), new_stage.strip())

old_payload = r"""
  aegis_result_t rc = aegis_encrypt(ctx->crypto, (const uint8_t *)req_body,
                                    req_len, (const uint8_t *)&env, sizeof(env),
                                    ct_buf, env.iv, env.tag);
"""
new_payload = r"""
  aegis_c2_envelope_t aad_env_p;
  memcpy(&aad_env_p, &env, sizeof(env));
  memset(aad_env_p.iv, 0, AEGIS_GCM_IV_BYTES);
  memset(aad_env_p.tag, 0, AEGIS_GCM_TAG_BYTES);

  aegis_result_t rc = aegis_encrypt(ctx->crypto, (const uint8_t *)req_body,
                                    req_len, (const uint8_t *)&aad_env_p, sizeof(aad_env_p),
                                    ct_buf, env.iv, env.tag);
"""
content = content.replace(old_payload.strip(), new_payload.strip())

old_resource = r"""
  aegis_result_t rc = aegis_encrypt(ctx->crypto, (const uint8_t *)resource_id,
                                    id_len, (const uint8_t *)&env, sizeof(env),
                                    ct_buf, env.iv, env.tag);
"""
new_resource = r"""
  aegis_c2_envelope_t aad_env_r;
  memcpy(&aad_env_r, &env, sizeof(env));
  memset(aad_env_r.iv, 0, AEGIS_GCM_IV_BYTES);
  memset(aad_env_r.tag, 0, AEGIS_GCM_TAG_BYTES);

  aegis_result_t rc = aegis_encrypt(ctx->crypto, (const uint8_t *)resource_id,
                                    id_len, (const uint8_t *)&aad_env_r, sizeof(aad_env_r),
                                    ct_buf, env.iv, env.tag);
"""
content = content.replace(old_resource.strip(), new_resource.strip())

with open("c2_comms/c2_client.c", "w") as f:
    f.write(content)
