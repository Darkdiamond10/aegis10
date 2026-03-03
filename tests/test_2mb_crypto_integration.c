#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <assert.h>
#include <pthread.h>

#include "../c2_comms/crypto.h"
#include "../common/config.h"
#include "../common/types.h"
#include "../nexus_auditor/ipc_protocol.h"
#include "../common/logging.h"

#define PAYLOAD_SIZE (2 * 1024 * 1024) // 2MB
#define CHUNK_SIZE (64 * 1024) // 64KB
#define MAX_CHUNKS ((PAYLOAD_SIZE + CHUNK_SIZE - 1) / CHUNK_SIZE)

// Let's stub out Beta node internals so we can link directly
// In the C file for beta_node, these were static. We can use a trick or define our own equivalent arrays.
// Actually, I'll compile with beta_node.c included and just redefine the command handler if needed,
// OR since beta_node.c is in the makefile, its `handle_alpha_command` and `g_chunks` are static.
// The easiest way to access static functions/vars in C is just to `#include` the C file directly.
#include "../nexus_auditor/beta_node.c"

int main() {
    printf("[*] Starting AEGIS 2MB Cryptography Integration Test (Alpha/Beta State Machine Verification)\n");

    // Setup environment
    setenv("HOME", "/tmp", 1);
    aegis_log_ctx_t *g_log = aegis_log_init("/tmp/aegis_test.log", 0);
    g_beta_log = g_log; // Ensure beta_node's internal logging works

    // Initialize Alpha/Beta Crypto Contexts (same PSK for both)
    aegis_crypto_ctx_t alpha_crypto;
    aegis_crypto_init(&alpha_crypto, NULL);
    g_beta_crypto = &alpha_crypto;

    uint8_t *original_payload = mmap(NULL, PAYLOAD_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    uint8_t *reassembled_payload = mmap(NULL, PAYLOAD_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    for (size_t i = 0; i < PAYLOAD_SIZE; i++) {
        original_payload[i] = (uint8_t)(i ^ 0xBB);
    }

    printf("[Alpha] Chunking and distributing 2MB payload to Beta node (CMD_DISTRIBUTE_CHUNK)...\n");

    // Arrays to hold IVs and Tags for decryption later
    uint8_t original_ivs[MAX_CHUNKS][AEGIS_GCM_IV_BYTES];
    uint8_t original_tags[MAX_CHUNKS][AEGIS_GCM_TAG_BYTES];

    // Simulate Alpha sending commands to Beta
    for (uint32_t i = 0; i < MAX_CHUNKS; i++) {
        size_t offset = i * CHUNK_SIZE;
        size_t len = CHUNK_SIZE;
        if (offset + len > PAYLOAD_SIZE) {
            len = PAYLOAD_SIZE - offset;
        }

        size_t cmd_size = sizeof(ipc_distribute_chunk_t) + len + 16;
        ipc_distribute_chunk_t *cmd = malloc(cmd_size);
        cmd->chunk_id = i;
        cmd->total_chunks = MAX_CHUNKS;
        cmd->chunk_len = len;

        uint8_t aad[] = "CHUNK_AAD";
        aegis_encrypt(&alpha_crypto, original_payload + offset, len, aad, sizeof(aad), cmd->data, cmd->chunk_iv, cmd->chunk_tag);

        // Save IVs/Tags
        memcpy(original_ivs[i], cmd->chunk_iv, AEGIS_GCM_IV_BYTES);
        memcpy(original_tags[i], cmd->chunk_tag, AEGIS_GCM_TAG_BYTES);

        // Directly inject into Beta's command handler
        aegis_ipc_header_t hdr;
        memset(&hdr, 0, sizeof(hdr));
        hdr.magic = IPC_MAGIC;
        hdr.command = CMD_DISTRIBUTE_CHUNK;
        hdr.payload_len = cmd_size;

        handle_alpha_command(&hdr, (uint8_t *)cmd, cmd_size);
        free(cmd);
    }

    printf("[Beta] All chunks stored in internal registry.\n");
    printf("[*] Simulating NanoMachine Fetching and Sequential Reassembly into mmap (PROT_EXEC)...\n");

    int fail_count = 0;

    // Fetch and reassemble from Beta's storage
    for (uint32_t i = 0; i < MAX_CHUNKS; i++) {
        bool found = false;

        pthread_mutex_lock(&g_chunk_mutex);
        for (int j = 0; j < MAX_STORED_CHUNKS; j++) {
            if (g_chunks[j].occupied && g_chunks[j].chunk_id == i) {
                found = true;

                size_t offset = i * CHUNK_SIZE;

                // Decrypt from Beta's storage to reassembled memory using saved original IVs
                uint8_t aad[] = "CHUNK_AAD";

                // Use a fresh context representing NanoMachine's state
                aegis_crypto_ctx_t nano_crypto;
                aegis_crypto_init(&nano_crypto, NULL);

                aegis_result_t res = aegis_decrypt_no_advance(&nano_crypto, g_chunks[j].data, g_chunks[j].data_len, aad, sizeof(aad), original_ivs[i], original_tags[i], reassembled_payload + offset);

                if (res != AEGIS_OK) {
                    printf("[-] Decryption failed for chunk %u (rc=%d)\n", i, res);
                    fail_count++;
                }

                aegis_crypto_destroy(&nano_crypto);
                break;
            }
        }
        pthread_mutex_unlock(&g_chunk_mutex);

        if (!found) {
            printf("[-] Missing chunk %u in Beta storage!\n", i);
            fail_count++;
        }
    }

    if (fail_count == 0 && memcmp(original_payload, reassembled_payload, PAYLOAD_SIZE) == 0) {
        printf("[+] Full 2MB Payload State Machine Reassembly and Decryption Successful!\n");
    } else {
        printf("[-] Reassembly mismatch or decryption failure! Fails: %d\n", fail_count);
        return 1;
    }

    // Sequential Integrity (Dropped Chunk Test)
    printf("[*] Testing Sequential Integrity (Dropped/Corrupted Chunk)...\n");

    // Modify one chunk in Beta's storage to simulate corruption or out-of-order drop
    pthread_mutex_lock(&g_chunk_mutex);
    for (int j = 0; j < MAX_STORED_CHUNKS; j++) {
        if (g_chunks[j].occupied && g_chunks[j].chunk_id == 5) {
            // Flip a bit
            g_chunks[j].data[10] ^= 0xFF;

            // Try decrypting the tampered chunk
            size_t offset = 5 * CHUNK_SIZE;
            uint8_t aad[] = "CHUNK_AAD";

            aegis_crypto_ctx_t nano_crypto;
            aegis_crypto_init(&nano_crypto, NULL);

            aegis_result_t res = aegis_decrypt_no_advance(&nano_crypto, g_chunks[j].data, g_chunks[j].data_len, aad, sizeof(aad), original_ivs[5], original_tags[5], reassembled_payload + offset);

            if (res == AEGIS_ERR_AUTH) {
                printf("[+] Sequential Integrity check passed: Corruption/Skip correctly flagged by NanoMachine's vault!\n");
            } else {
                printf("[-] Sequential Integrity check failed! Decrypt returned %d instead of %d\n", res, AEGIS_ERR_AUTH);
                fail_count++;
            }

            aegis_crypto_destroy(&nano_crypto);
            break;
        }
    }
    pthread_mutex_unlock(&g_chunk_mutex);

    // Cleanup Beta storage
    for (int i = 0; i < MAX_STORED_CHUNKS; i++) {
        if (g_chunks[i].occupied && g_chunks[i].data) {
            free(g_chunks[i].data);
            g_chunks[i].occupied = false;
        }
    }

    munmap(original_payload, PAYLOAD_SIZE);
    munmap(reassembled_payload, PAYLOAD_SIZE);
    aegis_crypto_destroy(&alpha_crypto);
    aegis_log_finalize(g_log);

    if (fail_count == 0) {
        printf("[+] All Beta/Alpha state machine and sequential integrity tests passed successfully!\n");
        return 0;
    } else {
        return 1;
    }
}
