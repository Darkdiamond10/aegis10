#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <assert.h>

#include "../c2_comms/crypto.h"
#include "../common/config.h"
#include "../common/types.h"

#define PAYLOAD_SIZE (2 * 1024 * 1024) // 2MB

// Dummy AAD for the test
const uint8_t TEST_AAD[] = "AEGIS_C2_HEADER_MAGIC_TEST";
#define TEST_AAD_LEN (sizeof(TEST_AAD) - 1)

void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    printf("[*] Starting AEGIS 2MB Cryptography Stress Test (NanoMachine Integration)\n");

    // 1. Allocate 2MB mock payload using mmap (PROT_READ | PROT_WRITE | PROT_EXEC)
    printf("[*] Allocating 2MB payload using mmap with RWX permissions...\n");
    uint8_t *payload = mmap(NULL, PAYLOAD_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (payload == MAP_FAILED) {
        perror("[-] mmap payload failed");
        return 1;
    }

    uint8_t *ciphertext = mmap(NULL, PAYLOAD_SIZE + 16, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ciphertext == MAP_FAILED) {
        perror("[-] mmap ciphertext failed");
        return 1;
    }

    uint8_t *decrypted = mmap(NULL, PAYLOAD_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (decrypted == MAP_FAILED) {
        perror("[-] mmap decrypted failed");
        return 1;
    }

    // Fill payload with mock data (pseudo-random)
    for (size_t i = 0; i < PAYLOAD_SIZE; i++) {
        payload[i] = (uint8_t)(i ^ 0xAA);
    }

    // 2. Initialize Crypto Context
    printf("[*] Initializing Crypto Context...\n");
    aegis_crypto_ctx_t ctx;
    aegis_result_t res = aegis_crypto_init(&ctx, NULL);
    if (res != AEGIS_OK) {
        printf("[-] aegis_crypto_init failed with code %d\n", res);
        return 1;
    }

    uint8_t iv[AEGIS_GCM_IV_BYTES];
    uint8_t tag[AEGIS_GCM_TAG_BYTES];

    // 3. Encrypt the 2MB Payload
    printf("[*] Encrypting 2MB payload...\n");
    res = aegis_encrypt(&ctx, payload, PAYLOAD_SIZE, TEST_AAD, TEST_AAD_LEN, ciphertext, iv, tag);
    if (res != AEGIS_OK) {
        printf("[-] aegis_encrypt failed with code %d\n", res);
        return 1;
    }
    printf("[+] Encryption successful.\n");
    print_hex("[+] IV", iv, AEGIS_GCM_IV_BYTES);
    print_hex("[+] Tag", tag, AEGIS_GCM_TAG_BYTES);

    // 4. Decrypt the Payload simulating NanoMachine (aegis_decrypt_no_advance)
    printf("[*] Decrypting 2MB payload using aegis_decrypt_no_advance...\n");
    res = aegis_decrypt_no_advance(&ctx, ciphertext, PAYLOAD_SIZE, TEST_AAD, TEST_AAD_LEN, iv, tag, decrypted);
    if (res != AEGIS_OK) {
        printf("[-] aegis_decrypt_no_advance failed with code %d\n", res);
        return 1;
    }
    printf("[+] Decryption successful.\n");

    // 5. Verify byte-for-byte integrity
    printf("[*] Verifying byte-for-byte integrity...\n");
    if (memcmp(payload, decrypted, PAYLOAD_SIZE) != 0) {
        printf("[-] Integrity check failed! Decrypted payload does not match original.\n");
        return 1;
    }
    printf("[+] Integrity check passed! The 2MB payload perfectly matches.\n");

    // 6. Forgery Test
    printf("[*] Starting Forgery Test...\n");
    // Modify one byte of the ciphertext
    size_t tamper_offset = PAYLOAD_SIZE / 2;
    uint8_t original_byte = ciphertext[tamper_offset];
    ciphertext[tamper_offset] ^= 0xFF; // Flip bits

    printf("[*] Tampered with ciphertext at offset %zu (0x%02x -> 0x%02x). Attempting decryption...\n",
           tamper_offset, original_byte, ciphertext[tamper_offset]);

    // Clear decrypted buffer before test
    memset(decrypted, 0, PAYLOAD_SIZE);

    res = aegis_decrypt_no_advance(&ctx, ciphertext, PAYLOAD_SIZE, TEST_AAD, TEST_AAD_LEN, iv, tag, decrypted);
    if (res == AEGIS_ERR_AUTH) {
        printf("[+] Forgery Test Passed! Tag verification failed properly (AEGIS_ERR_AUTH).\n");
    } else {
        printf("[-] Forgery Test Failed! Decryption returned code %d instead of AEGIS_ERR_AUTH.\n", res);
        return 1;
    }

    // Cleanup
    aegis_crypto_destroy(&ctx);
    munmap(payload, PAYLOAD_SIZE);
    munmap(ciphertext, PAYLOAD_SIZE + 16);
    munmap(decrypted, PAYLOAD_SIZE);

    printf("[+] All stress tests passed successfully! NanoMachine crypto is ready.\n");
    return 0;
}