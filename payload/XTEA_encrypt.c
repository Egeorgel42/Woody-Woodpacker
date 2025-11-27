
#include <stdint.h>

// Encipher using XTEA block cipher algorithm 
// working on 32bits packets

void xtea_encipher(unsigned int num_rounds, uint32_t tocipher[2], uint32_t const key[4])
{
	unsigned int 	i;
	uint32_t 		v0 = tocipher[0];
	uint32_t		v1 = tocipher[1];
	uint32_t		sum = 0;
	uint32_t		delta = 0x9E3779B9; // Part of golden ratio to counter salt attacks

	for (i = 0; i < num_rounds; i++) {
		// shuffle v0 using v1
		v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
		// 'increment' sum
		sum += delta;
		// shuffle v1 using new v0, and use an other part of sum to pick the key part, for even more random
		v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
	}
	tocipher[0] = v0;
	tocipher[1] = v1;
}

