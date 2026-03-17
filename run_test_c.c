#include <stdio.h>
#include "c2_comms/crypto.h"
#include "c2_comms/c2_client.h"

int main() {
    aegis_crypto_ctx_t crypto;
    aegis_crypto_init(&crypto, AEGIS_PSK_B64);
    printf("Master key: ");
    for(int i=0; i<32; i++) printf("%02x", crypto.master_key[i]);
    printf("\nSession key: ");
    for(int i=0; i<32; i++) printf("%02x", crypto.session_key[i]);
    printf("\n");
    return 0;
}
