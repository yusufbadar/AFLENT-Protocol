#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include <sys/mman.h>
#include <math.h>
#include <sys/stat.h>
#include <errno.h>

typedef struct {
    unsigned int array_num;
    unsigned int frag_num;
    unsigned int frag_length;
    unsigned int endianness;
    unsigned int last;
    int payload_offset;
} packet_info_t;

void print_packet(unsigned char packet[])
{
	unsigned int header = ((unsigned int)packet[0] << 16) | ((unsigned int)packet[1] << 8) | (unsigned int)packet[2];
	
	unsigned int array_num = (header >> 18) & 0x3f;
	unsigned int frag_num = (header >> 13) & 0x1F;
	unsigned int length = (header >> 3) & 0x3FF;
	unsigned int encrypted = (header >> 2) & 0x1;
	unsigned int endianness = (header >> 1) & 0x1;
	unsigned int last = header & 0x1;

	printf("Array Number: %d\n", array_num);
	printf("Fragment Number: %x\n", frag_num);
	printf("Length: %x\n", length);
	printf("Encrypted: %x\n", encrypted);
	printf("Endianness: %x\n", endianness);
	printf("Last: %x\n", last);

	printf("Data:");
	int payload_start = 3;
	for (unsigned int i = 0; i < length; i++) {
		int offset = payload_start + i * 4;
		unsigned int value;
		if (endianness == 0) {
			value = ((unsigned int)packet[offset] << 24) | ((unsigned int)packet[offset+1] << 16) | ((unsigned int)packet[offset+2] << 8) | ((unsigned int)packet[offset + 3]);

		} else {
			value = ((unsigned int)packet[offset+3] << 24) | ((unsigned int)packet[offset+2] << 16) | ((unsigned int)packet[offset+1] << 8) | ((unsigned int)packet[offset]);
		}
        printf("%s%x", i == 0 ? "" : " ", value);
	}
	printf("\n");

}

unsigned char* build_packets(int data[], int data_length, int max_fragment_size, int endianness, int array_number)
{
	int ints_per_fragment = max_fragment_size/4;
	if (ints_per_fragment <= 0) {
		ints_per_fragment = 1;
	}

	int num_fragments = (data_length + ints_per_fragment - 1)/ints_per_fragment;
	int total_packets_bytes = num_fragments * 3 + data_length * 4;

	unsigned char *packet_buffer = malloc(total_packets_bytes);
	if (packet_buffer == NULL) {
		return NULL;
	}

	int offset = 0;
	int data_index = 0;

	for (int frag = 0; frag < num_fragments; frag++) {
		int frag_int_count = (data_length - data_index < ints_per_fragment) ? (data_length - data_index) : ints_per_fragment;
		
		int last = (frag == num_fragments - 1) ? 1 : 0;

		unsigned int header = ((unsigned int)array_number << 18) | ((unsigned int)frag << 13) | ((unsigned int)frag_int_count << 3) | (0 << 2) | ((unsigned int)endianness << 1) | ((unsigned int)last);

		packet_buffer[offset] = (header >> 16) & 0xFF;
		packet_buffer[offset + 1] = (header >> 8) & 0xFF;
		packet_buffer[offset + 2] = header & 0xFF;
		offset += 3;

		for (int i = 0; i < frag_int_count; i++) {
			int value = data[data_index++];
			if (endianness == 0) {
				packet_buffer[offset] = (value >> 24) & 0xFF;
				packet_buffer[offset + 1] = (value >> 16) & 0xFF;
				packet_buffer[offset + 2] = (value >> 8) & 0xFF;
				packet_buffer[offset + 3] = value & 0xFF;
			} else {
				packet_buffer[offset] = value & 0xFF;
				packet_buffer[offset + 1] = (value >> 8) & 0xFF;
				packet_buffer[offset + 2] = (value >> 16) & 0xFF;
				packet_buffer[offset + 3] = (value >> 24) & 0xFF;
			}
			offset += 4;
		} 
	}
	return packet_buffer;
}

int** create_arrays(unsigned char packets[], int array_count, int *array_lengths) {
    int info_capacity = 10;
    packet_info_t *info = malloc(info_capacity * sizeof(packet_info_t));
    int info_count = 0;

    int *expected_fragments = malloc(array_count * sizeof(int));
    int *fragments_seen = calloc(array_count, sizeof(int));
    for (int i = 0; i < array_count; i++) {
        expected_fragments[i] = -1; 
        array_lengths[i] = 0;
    }
    
    int pos = 0;
    while (1) {
        unsigned int header = ((unsigned int)packets[pos] << 16) | ((unsigned int)packets[pos+1] << 8) | (unsigned int)packets[pos+2];
        unsigned int array_num = (header >> 18) & 0x3F;
        unsigned int frag_num = (header >> 13) & 0x1F;
        unsigned int frag_length = (header >> 3)  & 0x3FF;
        unsigned int endianness = (header >> 1)  & 0x1;
        unsigned int last = header & 0x1;
        
        if (info_count >= info_capacity) {
            info_capacity *= 2;
            info = realloc(info, info_capacity * sizeof(packet_info_t));
        }
        info[info_count].array_num = array_num;
        info[info_count].frag_num = frag_num;
        info[info_count].frag_length = frag_length;
        info[info_count].endianness = endianness;
        info[info_count].payload_offset = pos + 3;
        info_count++;
        
        fragments_seen[array_num]++;
        array_lengths[array_num] += frag_length;
        if (last == 1)
            expected_fragments[array_num] = frag_num + 1;
        
        pos += 3 + (frag_length * 4);
        
        int all_done = 1;
        for (int i = 0; i < array_count; i++) {
            if (expected_fragments[i] == -1 || fragments_seen[i] < expected_fragments[i]) {
                all_done = 0;
                break;
            }
        }
        if (all_done)
            break;
    }
    free(fragments_seen);
    
    int **result = malloc(array_count * sizeof(int *));
    for (int a = 0; a < array_count; a++) {
        result[a] = malloc(array_lengths[a] * sizeof(int));
    }
    int *insert_index = calloc(array_count, sizeof(int));
    
    for (int a = 0; a < array_count; a++) {
        for (unsigned int frag = 0; frag < (unsigned int)expected_fragments[a]; frag++) {
            for (int i = 0; i < info_count; i++) {
                if (info[i].array_num == (unsigned int)a && info[i].frag_num == frag) {
                    for (unsigned int j = 0; j < info[i].frag_length; j++) {
                        int payload_index = info[i].payload_offset + j * 4;
                        unsigned int value;
                        if (info[i].endianness == 0)
                            value = ((unsigned int)packets[payload_index] << 24) | ((unsigned int)packets[payload_index+1] << 16) | ((unsigned int)packets[payload_index+2] << 8) | ((unsigned int)packets[payload_index+3]);
                        else
                            value = ((unsigned int)packets[payload_index+3] << 24) | ((unsigned int)packets[payload_index+2] << 16) | ((unsigned int)packets[payload_index+1] << 8) | ((unsigned int)packets[payload_index]);
                        result[a][insert_index[a]++] = value;
                    }
                    break;
                }
            }
        }
    }
    
    free(info);
    free(insert_index);
    free(expected_fragments);
    return result;
}

#define EXPANDED_KEYS_LENGTH 32

typedef uint64_t sbu_key_t;
typedef uint32_t block_t;
typedef block_t(*permute_func_t)(block_t);

block_t table[] = { 
    0x6a09e667, 0xbb67ae84, 0x3c6ef372, 0xa54ff539, 0x510e527f, 0x9b05688b, 0x1f83d9ab, 0x5be0cd18, 
    0xcbbb9d5c, 0x629a2929, 0x91590159, 0x152fecd8, 0x67332667, 0x8eb44a86, 0xdb0c2e0c, 0x47b5481d, 
    0xae5f9156, 0xcf6c85d2, 0x2f73477d, 0x6d1826ca, 0x8b43d456, 0xe360b595, 0x1c456002, 0x6f196330, 
    0xd94ebeb0, 0x0cc4a611, 0x261dc1f2, 0x5815a7bd, 0x70b7ed67, 0xa1513c68, 0x44f93635, 0x720dcdfd, 
    0xb467369d, 0xca320b75, 0x34e0d42e, 0x49c7d9bd, 0x87abb9f1, 0xc463a2fb, 0xec3fc3f2, 0x27277f6c, 
    0x610bebf2, 0x7420b49e, 0xd1fd8a32, 0xe4773593, 0x092197f5, 0x1b530c95, 0x869d6342, 0xeee52e4e, 
    0x11076689, 0x21fba37b, 0x43ab9fb5, 0x75a9f91c, 0x86305019, 0xd7cd8173, 0x07fe00ff, 0x379f513f, 
    0x66b651a8, 0x764ab842, 0xa4b06be0, 0xc3578c14, 0xd2962a52, 0x1e039f40, 0x857b7bed, 0xa29bf2de
};

// ----------------- Bitwise Functions ----------------- //

uint8_t rotl(uint8_t x, uint8_t shamt) {
    shamt %= 8;
    return (x << shamt) | (x >> (8 - shamt));
}

uint8_t rotr(uint8_t x, uint8_t shamt) {
    shamt %= 8;
    return (x >> shamt) | (x << (8 - shamt));
}

block_t reverse(block_t x) {
    block_t y = 0;
    for (int i = 0; i < 32; i++) {
        y |= ((x >> i) & 1) << (31 - i);
    }
    return y;
}

block_t shuffle4(block_t x) {
    block_t high = (x >> 16) & 0xFFFF;
    block_t low  = x & 0xFFFF;
    block_t result = 0;
    for (int i = 3; i >= 0; i--) {
        block_t segHigh = (high >> (i * 4)) & 0xF;
        block_t segLow  = (low  >> (i * 4)) & 0xF;
        int posHigh = (i * 2) + 1;
        int posLow  = (i * 2);
        result |= segHigh << (posHigh * 4);
        result |= segLow  << (posLow  * 4);
    }
    return result;
}

block_t unshuffle4(block_t x) {
    block_t high = 0, low = 0;
    for (int i = 0; i < 4; i++) {
        int posHigh = (i * 2) + 1;
        int posLow  = (i * 2);
        block_t segHigh = (x >> (posHigh * 4)) & 0xF;
        block_t segLow  = (x >> (posLow * 4)) & 0xF;
        high |= segHigh << ((3 - i) * 4);
        low  |= segLow  << ((3 - i) * 4);
    }
    return (high << 16) | low;
}

block_t shuffle1(block_t x) {
    uint16_t high = (x >> 16) & 0xFFFF;
    uint16_t low  = x & 0xFFFF;
    block_t result = 0;
    for (int i = 15; i >= 0; i--) {
        block_t bitHigh = (high >> i) & 1;
        block_t bitLow  = (low >> i) & 1;
        result |= (bitHigh << ((i * 2) + 1));
        result |= (bitLow  << (i * 2));
    }
    return result;
}

block_t unshuffle1(block_t x) {
    uint16_t high = 0, low = 0;
    for (int i = 15; i >= 0; i--) {
        block_t bitHigh = (x >> ((i * 2) + 1)) & 1;
        block_t bitLow  = (x >> (i * 2)) & 1;
        high |= bitHigh << i;
        low  |= bitLow  << i;
    }
    return ((block_t)high << 16) | low;
}

uint8_t nth_byte(block_t x, uint8_t i) {
    return (x >> (i * 8)) & 0xFF;
}

// ----------------- Encryption Functions ----------------- //

uint8_t scramble_op(block_t B, int i, block_t keyA, block_t keyB) {
    uint8_t b0 = nth_byte(B, i);
    uint8_t b1 = nth_byte(B, (i + 3) % 4);
    uint8_t b2 = nth_byte(B, (i + 2) % 4);
    uint8_t b3 = nth_byte(B, (i + 1) % 4);
    uint8_t keyA_byte = nth_byte(keyA, i);
    uint8_t keyB_byte = nth_byte(keyB, i);
    uint8_t result = b0 ^ (b1 & b2) ^ ((uint8_t)(~b1) & b3) ^ keyA_byte ^ keyB_byte;
    static uint8_t rot_table[4] = {2, 3, 5, 7};
    return rotl(result, rot_table[i]);
}

uint8_t mash_op(block_t B, int i, block_t *keys) {
    uint8_t index = nth_byte(B, (i + 3) % 4);
    block_t key = keys[index % EXPANDED_KEYS_LENGTH];
    return nth_byte(B, i) ^ nth_byte(key, i);
}

void sbu_expand_keys(sbu_key_t key, block_t *S) {
    S[0] = (uint32_t)(key & 0xFFFFFFFF);
    S[1] = (uint32_t)(key >> 32);
    for (int i = 2; i < 32; i++) {
        uint32_t idx = (S[i - 1] ^ S[i - 2]) % 32;
        S[i] = table[idx] ^ S[i - 1];
    }
    for (int i = 29; i >= 0; i--) {
        uint32_t idx = (S[i + 1] ^ S[i + 2]) % 32;
        S[i] = table[idx] ^ S[i];
    }
}
    

block_t scramble(block_t x, block_t *keys, uint32_t round, permute_func_t op)
{
    block_t keyA = keys[round];
    block_t keyB = keys[EXPANDED_KEYS_LENGTH - 1 - round];
    x = op(x);
    uint8_t b0 = scramble_op(x, 0, keyA, keyB);
    uint8_t b1 = scramble_op(x, 1, keyA, keyB);
    uint8_t b2 = scramble_op(x, 2, keyA, keyB);
    uint8_t b3 = scramble_op(x, 3, keyA, keyB);
    block_t result = ((block_t)b3 << 24) | ((block_t)b2 << 16) | ((block_t)b1 << 8) | b0;
    return result;
}

block_t mash(block_t x, block_t *keys)
{
    uint8_t b0 = mash_op(x, 0, keys);
    uint8_t b1 = mash_op(x, 1, keys);
    uint8_t b2 = mash_op(x, 2, keys);
    uint8_t b3 = mash_op(x, 3, keys);
    block_t result = ((block_t)b3 << 24) | ((block_t)b2 << 16) | ((block_t)b1 << 8) | b0;
    return result;
}

block_t sbu_encrypt_block(block_t plain_text, block_t *expanded_keys)
{
    block_t R01 = scramble(plain_text, expanded_keys, 0, reverse);
    block_t R02 = scramble(R01, expanded_keys, 1, shuffle1);
    block_t R03 = scramble(R02, expanded_keys, 2, shuffle4);
    block_t R04 = scramble(R03, expanded_keys, 3, reverse);
    block_t R05 = mash(R04, expanded_keys);
    block_t R06 = scramble(R05, expanded_keys, 4, reverse);
    block_t R07 = scramble(R06, expanded_keys, 5, shuffle1);
    block_t R08 = scramble(R07, expanded_keys, 6, shuffle4);
    block_t R09 = scramble(R08, expanded_keys, 7, reverse);
    block_t R10 = mash(R09, expanded_keys);
    block_t R11 = scramble(R10, expanded_keys, 8, reverse);
    block_t R12 = scramble(R11, expanded_keys, 9, shuffle1);
    block_t R13 = scramble(R12, expanded_keys, 10, shuffle4);
    block_t R14 = scramble(R13, expanded_keys, 11, reverse);
    block_t R15 = mash(R14, expanded_keys);
    block_t R16 = scramble(R15, expanded_keys, 12, reverse);
    block_t R17 = scramble(R16, expanded_keys, 13, shuffle1);
    block_t R18 = scramble(R17, expanded_keys, 14, shuffle4);
    block_t R19 = scramble(R18, expanded_keys, 15, reverse);
    return R19;
}

uint8_t r_scramble_op(block_t B, int i, block_t keyA, block_t keyB) {
    static uint8_t r_rot_table[4] = {7, 5, 3, 2};
    uint8_t shift = r_rot_table[i];
    uint8_t b_current = rotr(nth_byte(B, i), shift);
    uint8_t b_prev1   = rotr(nth_byte(B, (i + 3) % 4), shift);
    uint8_t b_prev2   = rotr(nth_byte(B, (i + 2) % 4), shift);
    uint8_t b_prev3   = rotr(nth_byte(B, (i + 1) % 4), shift);
    return b_current ^ (b_prev1 & b_prev2) ^ ((uint8_t)(~b_prev1) & b_prev3) ^ nth_byte(keyA, i) ^ nth_byte(keyB, i);
}

block_t r_scramble(block_t x, block_t *keys, uint32_t round, permute_func_t op)
{
    block_t keyA = keys[round];
    block_t keyB = keys[EXPANDED_KEYS_LENGTH - 1 - round];
    uint8_t b3 = r_scramble_op(x, 3, keyA, keyB);
    uint8_t b2 = r_scramble_op(x, 2, keyA, keyB);
    uint8_t b1 = r_scramble_op(x, 1, keyA, keyB);
    uint8_t b0 = r_scramble_op(x, 0, keyA, keyB);
    block_t combined = ((block_t)b3 << 24) | ((block_t)b2 << 16) | ((block_t)b1 << 8) | b0;
    combined = op(combined);
    return combined;
}

block_t r_mash(block_t x, block_t *keys)
{
    return mash(x, keys);
}

block_t sbu_decrypt_block(block_t cipher_text, block_t *expanded_keys)
{
    block_t R01 = r_scramble(cipher_text, expanded_keys, 15, reverse);
    block_t R02 = r_scramble(R01, expanded_keys, 14, unshuffle4);
    block_t R03 = r_scramble(R02, expanded_keys, 13, unshuffle1);
    block_t R04 = r_scramble(R03, expanded_keys, 12, reverse);
    block_t R05 = r_mash(R04, expanded_keys);
    block_t R06 = r_scramble(R05, expanded_keys, 11, reverse);
    block_t R07 = r_scramble(R06, expanded_keys, 10, unshuffle4);
    block_t R08 = r_scramble(R07, expanded_keys, 9, unshuffle1);
    block_t R09 = r_scramble(R08, expanded_keys, 8, reverse);
    block_t R10 = r_mash(R09, expanded_keys);
    block_t R11 = r_scramble(R10, expanded_keys, 7, reverse);
    block_t R12 = r_scramble(R11, expanded_keys, 6, unshuffle4);
    block_t R13 = r_scramble(R12, expanded_keys, 5, unshuffle1);
    block_t R14 = r_scramble(R13, expanded_keys, 4, reverse);
    block_t R15 = r_mash(R14, expanded_keys);
    block_t R16 = r_scramble(R15, expanded_keys, 3, reverse);
    block_t R17 = r_scramble(R16, expanded_keys, 2, unshuffle4);
    block_t R18 = r_scramble(R17, expanded_keys, 1, unshuffle1);
    block_t R19 = r_scramble(R18, expanded_keys, 0, reverse);
    return R19;
}

void sbu_encrypt(uint8_t *plaintext_input, block_t *encrypted_output, size_t pt_len, uint32_t *expanded_keys)
{
    size_t num_blocks = (pt_len + 3) / 4;
    for (size_t i = 0; i < num_blocks; i++) {
        block_t block = 0;
        for (int j = 0; j < 4; j++) {
            size_t index = i * 4 + j;
            uint8_t byte = (index < pt_len) ? plaintext_input[index] : 0;
            block |= ((block_t)byte) << (8 * j);
        }
        encrypted_output[i] = sbu_encrypt_block(block, (block_t *)expanded_keys);
    }
}

void sbu_decrypt(block_t *encrypted_input, char *plaintext_output, size_t pt_len, uint32_t *expanded_keys)
{
    size_t num_blocks = (pt_len + 3) / 4;
    size_t out_index = 0;
    for (size_t i = 0; i < num_blocks; i++) {
        block_t block = sbu_decrypt_block(encrypted_input[i], (block_t *)expanded_keys);
        for (int j = 0; j < 4 && out_index < pt_len; j++) {
            plaintext_output[out_index++] = (char)((block >> (8 * j)) & 0xFF);
        }
    }
}

// ----------------- Utility Functions ----------------- //