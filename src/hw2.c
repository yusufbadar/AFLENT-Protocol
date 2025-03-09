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

#define HEADER_SIZE 4
#define MAX_PACKET_SIZE 256

int total_packets_bytes = 0;

struct packet_info {
	int array_number;
	int frag_number;
	int frag_length;
	int endianness;
	int payload_offset;
};

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
	total_packets_bytes = num_fragments * 3 + data_length * 4;

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

int convert_bytes_to_int(unsigned char *data, int is_little_endian) {
    int value;
    if (is_little_endian) {
        value = (data[3] << 24) | (data[2] << 16) | (data[1] << 8) | data[0];
    } else {
        value = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
    }
    return value;
}

int** create_arrays(unsigned char packets[], int array_count, int *array_lengths) {
    int **arrays = (int**)calloc(array_count, sizeof(int*));
    int *temp_sizes = (int*)calloc(array_count, sizeof(int));
    int i = 0;
    while (i < MAX_PACKET_SIZE) {  
        if (i + HEADER_SIZE > MAX_PACKET_SIZE) break; 

        int array_num = packets[i];
        int length = packets[i + 3];

        i += HEADER_SIZE;
        
        if (array_num >= array_count) {
            i += length * 4;
            continue;
        }

        temp_sizes[array_num] += length;
    }

    for (int j = 0; j < array_count; j++) {
        if (temp_sizes[j] > 0) {
            arrays[j] = (int*)calloc(temp_sizes[j], sizeof(int));
            array_lengths[j] = temp_sizes[j];
        }
    }
    
    int *current_positions = (int*)calloc(array_count, sizeof(int));
    i = 0;
    while (i < MAX_PACKET_SIZE) {
        if (i + HEADER_SIZE > MAX_PACKET_SIZE) break;

        int array_num = packets[i];
        int frag_num = packets[i + 1];
        unsigned char flags = packets[i + 2];
        int length = packets[i + 3];
        int is_little_endian = flags & 1;

        i += HEADER_SIZE;
        
        if (array_num >= array_count || !arrays[array_num]) {
            i += length * 4;
            continue;
        }

        for (int j = 0; j < length; j++) {
            arrays[array_num][current_positions[array_num]++] = convert_bytes_to_int(&packets[i], is_little_endian);
            i += 4;
        }
    }

    free(temp_sizes);
    free(current_positions);
    return arrays;
}


//Encryption Code:

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

uint8_t rotl(uint8_t x, uint8_t shamt)
{
	(void) x;
	(void) shamt;
    return 0;
}

uint8_t rotr(uint8_t x, uint8_t shamt)
{
	(void) x;
	(void) shamt;
    return 0;
}

block_t reverse(block_t x)
{
	(void) x;
    return 0;
}

block_t shuffle4(block_t x)
{
	(void) x;
    return 0;
}

block_t unshuffle4(block_t x)
{
	(void) x;
    return 0;
}

block_t shuffle1(block_t x)
{
	(void) x;
    return 0;
}

block_t unshuffle1(block_t x)
{
	(void) x;
    return 0;
}

uint8_t nth_byte(block_t x, uint8_t n)
{
	(void) x;
	(void) n;
    return 0;
}

// ----------------- Encryption Functions ----------------- //

void sbu_expand_keys(sbu_key_t key, block_t *expanded_keys)
{
	(void) key;
	(void) expanded_keys;
}

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

// ----------------- Utility Functions ----------------- //