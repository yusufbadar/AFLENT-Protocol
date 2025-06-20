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
    int payload_changed;
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
		int changed = payload_start + i * 4;
		unsigned int value;
		if (endianness == 0) {
			value = ((unsigned int)packet[changed] << 24) | ((unsigned int)packet[changed+1] << 16) | ((unsigned int)packet[changed+2] << 8) | ((unsigned int)packet[changed + 3]);

		} else {
			value = ((unsigned int)packet[changed+3] << 24) | ((unsigned int)packet[changed+2] << 16) | ((unsigned int)packet[changed+1] << 8) | ((unsigned int)packet[changed]);
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

	int changed = 0;
	int data_index = 0;

	for (int frag = 0; frag < num_fragments; frag++) {
		int frag_int_count = (data_length - data_index < ints_per_fragment) ? (data_length - data_index) : ints_per_fragment;
		
		int last = (frag == num_fragments - 1) ? 1 : 0;

		unsigned int header = ((unsigned int)array_number << 18) | ((unsigned int)frag << 13) | ((unsigned int)frag_int_count << 3) | (0 << 2) | ((unsigned int)endianness << 1) | ((unsigned int)last);

		packet_buffer[changed] = (header >> 16) & 0xFF;
		packet_buffer[changed + 1] = (header >> 8) & 0xFF;
		packet_buffer[changed + 2] = header & 0xFF;
		changed += 3;

		for (int i = 0; i < frag_int_count; i++) {
			int value = data[data_index++];
			if (endianness == 0) {
				packet_buffer[changed] = (value >> 24) & 0xFF;
				packet_buffer[changed + 1] = (value >> 16) & 0xFF;
				packet_buffer[changed + 2] = (value >> 8) & 0xFF;
				packet_buffer[changed + 3] = value & 0xFF;
			} else {
				packet_buffer[changed] = value & 0xFF;
				packet_buffer[changed + 1] = (value >> 8) & 0xFF;
				packet_buffer[changed + 2] = (value >> 16) & 0xFF;
				packet_buffer[changed + 3] = (value >> 24) & 0xFF;
			}
			changed += 4;
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
        info[info_count].payload_changed = pos + 3;
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
                        int payload_index = info[i].payload_changed + j * 4;
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


uint8_t rot_table[4]  = {2, 3, 5, 7};
uint8_t r_rot_table[4] = {7, 5, 3, 2};

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

unsigned char rotl(unsigned char x, unsigned char shamt)
{
    return (unsigned char)((x << shamt) | (x >> (8 - shamt)));
}

unsigned char rotr(unsigned char x, unsigned char shamt)
{
    return (unsigned char)((x >> shamt) | (x << (8 - shamt)));
}

block_t rotr32(block_t x, unsigned char shamt)
{
    return (x >> shamt) | (x << (32 - shamt));
}

block_t reverse(block_t x)
{
    block_t r = 0;
    for (int i = 0; i < 32; i++) {
        r |= ((x >> i) & 1) << (31 - i);
    }
    return r;
}

block_t shuffle4(block_t x)
{
    unsigned int a = (x >> 28) & 0xF;
    unsigned int b = (x >> 24) & 0xF;
    unsigned int c = (x >> 20) & 0xF;
    unsigned int d = (x >> 16) & 0xF;
    unsigned int e = (x >> 12) & 0xF;
    unsigned int f = (x >> 8)  & 0xF;
    unsigned int g = (x >> 4)  & 0xF;
    unsigned int h = x & 0xF;
    return (a << 28) | (e << 24) | (b << 20) | (f << 16) | (c << 12) | (g << 8) | (d << 4) | h;
}

block_t unshuffle4(block_t x)
{
    unsigned int a = (x >> 28) & 0xF;
    unsigned int e = (x >> 24) & 0xF;
    unsigned int b = (x >> 20) & 0xF;
    unsigned int f = (x >> 16) & 0xF;
    unsigned int c = (x >> 12) & 0xF;
    unsigned int g = (x >> 8) & 0xF;
    unsigned int d = (x >> 4) & 0xF;
    unsigned int h = x & 0xF;
    return (a << 28) | (b << 24) | (c << 20) | (d << 16) | (e << 12) | (f << 8) | (g << 4) | h;
}

block_t shuffle1(block_t x)
{
    unsigned int L = x & 0xFFFF;
    unsigned int U = (x >> 16) & 0xFFFF;
    block_t res = 0;
    for (int i = 0; i < 16; i++) {
        int shift = 2 * (15 - i);
        res |= ((unsigned int)((U >> (15 - i)) & 1)) << (shift + 1);
        res |= ((unsigned int)((L >> (15 - i)) & 1)) << shift;
    }
    return res;
}

block_t unshuffle1(block_t x)
{
    unsigned int L = 0, U = 0;
    for (int i = 0; i < 16; i++) {
        int shift = 2 * (15 - i);
        U |= ((x >> (shift + 1)) & 1) << (15 - i);
        L |= ((x >> shift) & 1) << (15 - i);
    }
    return ((block_t)U << 16) | L;
}

unsigned char nth_byte(block_t x, unsigned char n)
{
    return (unsigned char)((x >> (8 * (n % 4))) & 0xFF);
}

// ----------------- Encryption Functions ----------------- //

block_t scramble(block_t x, block_t *keys, uint32_t round, permute_func_t op)
{
    (void) x;
    (void) keys;
    (void) round;
    (void) op;
    return 0;
}

block_t mash(block_t x, block_t *keys)
{
    (void) x;
    (void) keys;
    return 0;
}

block_t sbu_encrypt_block(block_t plain_text, block_t *expanded_keys)
{
    (void) plain_text;
    (void) expanded_keys;

    return 0;
}

block_t r_scramble(block_t x, block_t *keys, uint32_t round, permute_func_t op)
{
    (void) x;
    (void) keys;
    (void) round;
    (void) op;

    return 0;
}

block_t r_mash(block_t x, block_t *keys)
{
    (void) x;
    (void) keys;
    return 0;
}

block_t sbu_decrypt_block(block_t cipher_text, block_t *expanded_keys)
{
    (void) cipher_text;
    (void) expanded_keys;
    return 0;
}

void sbu_encrypt(uint8_t *plaintext_input, block_t *encrypted_output, size_t pt_len, uint32_t *expanded_keys)
{
    (void) plaintext_input;
    (void) encrypted_output;
    (void) pt_len;
    (void) expanded_keys;
}

void sbu_decrypt(block_t *encrypted_input, char *plaintext_output, size_t pt_len, uint32_t *expanded_keys)
{
    (void) encrypted_input;
    (void) plaintext_output;
    (void) pt_len;
    (void) expanded_keys;
}
void sbu_expand_keys(sbu_key_t key, unsigned int *S)
{
    S[0] = (unsigned int)(key & 0xFFFFFFFFULL);
    S[1] = (unsigned int)((key >> 32) & 0xFFFFFFFFULL);

    for (int i = 2; i < EXPANDED_KEYS_LENGTH; i++) {
        unsigned int temp = S[i - 1] ^ S[i - 2];
        S[i] = table[temp % 64] ^ S[i - 1];
    }
    for (int i = EXPANDED_KEYS_LENGTH - 3; i >= 0; i--) {
        unsigned int temp = S[i + 1] ^ S[i + 2];
        S[i] = table[temp % 64] ^ S[i];
    }
}
