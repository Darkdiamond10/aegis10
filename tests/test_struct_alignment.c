#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <assert.h>

#include "../common/types.h"
#include "../common/config.h"
#include "../nexus_auditor/ipc_protocol.h"

#define PAYLOAD_SIZE (2 * 1024 * 1024)

#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "[FAIL] %s:%d: %s\n", __FILE__, __LINE__, msg); \
            exit(EXIT_FAILURE); \
        } \
    } while (0)

void test_struct_alignment_and_sequencing() {
    printf("[*] Starting Structure-Only Alignment & Sequencing Diagnostic...\n");

    // 1. Generate 2MB raw plaintext payload
    uint8_t *original_payload = malloc(PAYLOAD_SIZE);
    TEST_ASSERT(original_payload != NULL, "Failed to allocate 2MB payload");

    // Fill with a repeating pattern to make debugging obvious
    for (size_t i = 0; i < PAYLOAD_SIZE; i++) {
        original_payload[i] = (uint8_t)(i & 0xFF);
    }

    // 2. Metadata Overhead Check
    printf("    -> Validating Metadata Overhead...\n");
    size_t ipc_header_sz = sizeof(aegis_ipc_header_t);
    size_t chunk_header_sz = sizeof(ipc_distribute_chunk_t);
    size_t total_header_sz = ipc_header_sz + chunk_header_sz;

    printf("       | IPC Header Size: %zu bytes\n", ipc_header_sz);
    printf("       | Chunk Header Size: %zu bytes\n", chunk_header_sz);
    printf("       | Total Overhead: %zu bytes\n", total_header_sz);
    printf("       | Max IPC Msg Size: %d bytes\n", AEGIS_IPC_MAX_MSG_SIZE);

    // Calculate maximum safe payload data per chunk
    size_t max_chunk_data_len = AEGIS_IPC_MAX_MSG_SIZE - total_header_sz;
    printf("       | Available Payload space per chunk: %zu bytes\n", max_chunk_data_len);

    TEST_ASSERT(total_header_sz < AEGIS_IPC_MAX_MSG_SIZE, "Headers are larger than the max IPC message size!");

    size_t total_chunks = (PAYLOAD_SIZE + max_chunk_data_len - 1) / max_chunk_data_len;
    printf("       | Total chunks needed for 2MB: %zu\n", total_chunks);

    // 3. Set up Target mmap Vault (The "Territory")
    printf("    -> Allocating Alpha/Beta Target mmap Vault...\n");
    uint8_t *vault_map = mmap(NULL, PAYLOAD_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    TEST_ASSERT(vault_map != MAP_FAILED, "Failed to mmap vault");

    // Simulate IPC transfer buffer
    uint8_t *ipc_tx_buffer = malloc(AEGIS_IPC_MAX_MSG_SIZE);
    TEST_ASSERT(ipc_tx_buffer != NULL, "Failed to allocate IPC TX buffer");

    // 4. Sequencing & Reassembly Loop
    printf("    -> Beginning Structured IPC Distribution Simulation...\n");
    for (size_t i = 0; i < total_chunks; i++) {
        size_t current_chunk_len = max_chunk_data_len;
        size_t payload_offset = i * max_chunk_data_len;

        if (payload_offset + current_chunk_len > PAYLOAD_SIZE) {
            current_chunk_len = PAYLOAD_SIZE - payload_offset;
        }

        // --- SENDER SIDE (Alpha Node Structure Wrapping) ---
        // We use pointers into the ipc_tx_buffer to mimic exact memory layouts on the wire
        aegis_ipc_header_t *tx_ipc_hdr = (aegis_ipc_header_t *)ipc_tx_buffer;
        tx_ipc_hdr->magic = IPC_MAGIC;
        tx_ipc_hdr->command = 0x07; // Arbitrary, say CMD_DISTRIBUTE_CHUNK
        tx_ipc_hdr->payload_len = chunk_header_sz + current_chunk_len;
        // Skipping IV/TAG since this is struct-only (no crypto)

        ipc_distribute_chunk_t *tx_chunk_hdr = (ipc_distribute_chunk_t *)(ipc_tx_buffer + ipc_header_sz);
        tx_chunk_hdr->chunk_id = i;
        tx_chunk_hdr->total_chunks = total_chunks;
        tx_chunk_hdr->chunk_len = current_chunk_len;

        uint8_t *tx_data_ptr = ipc_tx_buffer + total_header_sz;
        memcpy(tx_data_ptr, original_payload + payload_offset, current_chunk_len);

        // --- WIRE TRANSMISSION (IPC SOCKET) ---
        // (Simulated by directly passing ipc_tx_buffer to the receiver)

        // --- RECEIVER SIDE (Beta Node Reassembly) ---
        aegis_ipc_header_t *rx_ipc_hdr = (aegis_ipc_header_t *)ipc_tx_buffer;
        TEST_ASSERT(rx_ipc_hdr->magic == IPC_MAGIC, "IPC Magic mismatch!");

        ipc_distribute_chunk_t *rx_chunk_hdr = (ipc_distribute_chunk_t *)(ipc_tx_buffer + ipc_header_sz);

        // Verify state sequencing matches
        TEST_ASSERT(rx_chunk_hdr->chunk_id == i, "State Machine Sequencing Failure: Chunk ID mismatch");
        TEST_ASSERT(rx_chunk_hdr->total_chunks == total_chunks, "Total chunks mismatch");

        uint8_t *rx_data_ptr = ipc_tx_buffer + total_header_sz;

        // 5. Memory Alignment (Offset Mapping into Territory)
        size_t map_offset = rx_chunk_hdr->chunk_id * max_chunk_data_len;

        // Log the first and last chunk to keep terminal output manageable but informative
        if (i == 0 || i == total_chunks - 1) {
            printf("       [Chunk %u/%u] Wire Payload Len: %u | Writing to Vault Offset: 0x%08zX\n",
                   rx_chunk_hdr->chunk_id, rx_chunk_hdr->total_chunks, rx_chunk_hdr->chunk_len, map_offset);
        }

        // Write directly to mmap territory
        memcpy(vault_map + map_offset, rx_data_ptr, rx_chunk_hdr->chunk_len);
    }

    printf("    -> All %zu chunks reassembled.\n", total_chunks);

    // 6. Final Integrity Validation
    printf("    -> Validating 2MB Memory Alignment against Original Territory...\n");
    int cmp = memcmp(original_payload, vault_map, PAYLOAD_SIZE);

    if (cmp != 0) {
        // If it failed, let's find exactly where the misalignment happened
        for (size_t i = 0; i < PAYLOAD_SIZE; i++) {
            if (original_payload[i] != vault_map[i]) {
                printf("       [!] ALIGNMENT CORRUPTION at Offset 0x%08zX: Expected 0x%02X, Got 0x%02X\n",
                       i, original_payload[i], vault_map[i]);
                break;
            }
        }
        TEST_ASSERT(cmp == 0, "Structural Memory Alignment Corrupted!");
    } else {
        printf("       [+] The Map matches the Territory perfectly. Zero misalignment.\n");
    }

    munmap(vault_map, PAYLOAD_SIZE);
    free(original_payload);
    free(ipc_tx_buffer);

    printf("[+] Structure-Only Integration Test Passed.\n");
}

int main() {
    printf("========================================================\n");
    printf("  AEGIS STRUCTURAL & PROTOCOL DIAGNOSTIC                \n");
    printf("========================================================\n\n");

    test_struct_alignment_and_sequencing();

    return 0;
}