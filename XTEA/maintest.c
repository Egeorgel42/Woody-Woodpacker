#include <stdio.h>
#include <stdint.h>
#include <string.h>

void xtea_encipher(unsigned int num_rounds, uint32_t tocipher[2], uint32_t const key[4]);

// 2. Prototype de ta fonction ASM (Doit correspondre au nom dans le .s)
extern void xtea_decrypt_block(uint32_t v[2], uint32_t const key[4]);

void print_hex(const char *label, uint32_t v[2]) {
    printf("%s: 0x%08X 0x%08X\n", label, v[0], v[1]);
}

int main() {
    // defined raw key for testing (128 bits)
    uint32_t key[4] = {0x12345678, 0x9ABCDEF0, 0xDEADBEEF, 0xCAFEBABE};
    
    // Original data (64 bits / 8 octets) - Exemple "HI WOODY"
    uint32_t original[2] = {0x4948, 0x59444F4F};
    uint32_t data[2];

    // Copy to preserve original
    memcpy(data, original, sizeof(original));

    printf("=== STARTING XTEA CIPHERING ===\n");
    print_hex("Original ", data);

    // --- Ciphering ---
    xtea_encipher(32, data, key);
    print_hex("Crypted ", data);

    // compare to check crypting
    if (memcmp(data, original, sizeof(original)) == 0) {
        printf("ERROR : Crypting failed, nothing happened !\n");
        return 1;
    }

    // --- Deciphering ---
    xtea_decrypt_block(data, key);
    print_hex("Deciphered ", data);

    // --- CHECKS ---
    if (memcmp(data, original, sizeof(original)) == 0)
        printf("\nSUCCESS : Algorithm is reversible\n");
    else
        printf("\nFAILURE : Deciphered and pre-cipher data are not the same !\n");

    return 0;
}