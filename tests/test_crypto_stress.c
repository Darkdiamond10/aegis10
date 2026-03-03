#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <assert.h>
#include "../c2_comms/crypto.h"
#include "../common/config.h"

// 2MB payload size as requested by LO
#define PAYLOAD_SIZE (2 * 1024 * 1024)

// Macro to assist with tests
#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "[FAIL] %s:%d: %s\n", __FILE__, __LINE__, msg); \
            exit(EXIT_FAILURE); \
        } \
    } while (0)

void test_2mb_mmap_and_decryption() {
    printf("[*] Starting 2MB memory allocation & decryption stress test...\n");

    aegis_crypto_ctx_t ctx;
    aegis_result_t res = aegis_crypto_init(&ctx, NULL);
    TEST_ASSERT(res == AEGIS_OK, "Crypto init failed");

    // 1. Allocate 2MB plaintext buffer and fill with patterned data
    uint8_t *plaintext = malloc(PAYLOAD_SIZE);
    TEST_ASSERT(plaintext != NULL, "Failed to allocate plaintext buffer");
    for (size_t i = 0; i < PAYLOAD_SIZE; i++) {
        plaintext[i] = (uint8_t)(i & 0xFF);
    }

    // 2. Allocate ciphertext buffer
    uint8_t *ciphertext = malloc(PAYLOAD_SIZE);
    TEST_ASSERT(ciphertext != NULL, "Failed to allocate ciphertext buffer");

    uint8_t iv[AEGIS_GCM_IV_BYTES];
    uint8_t tag[AEGIS_GCM_TAG_BYTES];
    uint8_t aad[] = "test-aad-2mb-stress";

    // 3. Encrypt the 2MB payload
    printf("    -> Encrypting 2MB payload...\n");
    res = aegis_encrypt(&ctx, plaintext, PAYLOAD_SIZE, aad, sizeof(aad), ciphertext, iv, tag);
    TEST_ASSERT(res == AEGIS_OK, "Encryption failed");

    // Save current msg_counter to verify aegis_decrypt_no_advance works correctly
    uint64_t msg_counter_before = ctx.msg_counter;

    // 4. Memory Mapping for execution buffer (simulating Loader/NanoMachine)
    printf("    -> Allocating mmap (PROT_READ | PROT_WRITE | PROT_EXEC)...\n");
    void *exec_buf = mmap(NULL, PAYLOAD_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    TEST_ASSERT(exec_buf != MAP_FAILED, "mmap allocation failed");

    // 5. Decrypt directly into the mmap'd executable buffer using no_advance
    printf("    -> Decrypting into executable memory...\n");
    res = aegis_decrypt_no_advance(&ctx, ciphertext, PAYLOAD_SIZE, aad, sizeof(aad), iv, tag, (uint8_t*)exec_buf);
    TEST_ASSERT(res == AEGIS_OK, "Decryption (no advance) failed");

    // 6. Verify counter wasn't advanced
    TEST_ASSERT(ctx.msg_counter == msg_counter_before, "msg_counter advanced during no_advance decryption!");

    // 7. Verify integrity of the decrypted data
    printf("    -> Verifying data integrity...\n");
    int cmp = memcmp(plaintext, exec_buf, PAYLOAD_SIZE);
    TEST_ASSERT(cmp == 0, "Decrypted data does not match original plaintext");

    // Clean up
    munmap(exec_buf, PAYLOAD_SIZE);
    free(plaintext);
    free(ciphertext);
    aegis_crypto_destroy(&ctx);

    printf("[+] 2MB mmap and decryption test passed.\n");
}

void test_forgery() {
    printf("[*] Starting cryptographic forgery test (AEAD integrity)...\n");

    aegis_crypto_ctx_t ctx;
    aegis_result_t res = aegis_crypto_init(&ctx, NULL);
    TEST_ASSERT(res == AEGIS_OK, "Crypto init failed");

    uint8_t plaintext[] = "This is a highly sensitive payload that must not be tampered with.";
    size_t pt_len = sizeof(plaintext);
    uint8_t ciphertext[128];
    uint8_t decrypted[128];

    uint8_t iv[AEGIS_GCM_IV_BYTES];
    uint8_t tag[AEGIS_GCM_TAG_BYTES];
    uint8_t aad[] = "forgery-test-aad";

    // Encrypt
    res = aegis_encrypt(&ctx, plaintext, pt_len, aad, sizeof(aad), ciphertext, iv, tag);
    TEST_ASSERT(res == AEGIS_OK, "Encryption failed");

    // Tamper with the ciphertext
    printf("    -> Deliberately tampering with ciphertext...\n");
    ciphertext[10] ^= 0x42; // Flip some bits

    // Attempt to decrypt
    printf("    -> Attempting to decrypt tampered ciphertext...\n");
    res = aegis_decrypt_no_advance(&ctx, ciphertext, pt_len, aad, sizeof(aad), iv, tag, decrypted);

    // It MUST fail
    TEST_ASSERT(res == AEGIS_ERR_AUTH, "Forgery test FAILED! Tampered ciphertext was accepted!");

    // Also try tampering with the AAD
    ciphertext[10] ^= 0x42; // Revert ciphertext tampering
    aad[3] ^= 0x01; // Tamper AAD
    printf("    -> Attempting to decrypt with tampered AAD...\n");
    res = aegis_decrypt_no_advance(&ctx, ciphertext, pt_len, aad, sizeof(aad), iv, tag, decrypted);
    TEST_ASSERT(res == AEGIS_ERR_AUTH, "Forgery test FAILED! Tampered AAD was accepted!");

    aegis_crypto_destroy(&ctx);
    printf("[+] Forgery test passed (tampering correctly rejected).\n");
}

int main() {
    printf("========================================================\n");
    printf("  AEGIS CRYPTO STRESS & FORGERY TESTS (2MB PAYLOAD)     \n");
    printf("========================================================\n\n");

    test_2mb_mmap_and_decryption();
    printf("\n");
    test_forgery();

    printf("\n========================================================\n");
    printf("  ALL CRYPTO STRESS TESTS PASSED SUCCESSFULLY           \n");
    printf("========================================================\n");

    return 0;
}
