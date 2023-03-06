#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_PASSWORD_LENGTH 15
#define RAINBOW_TABLE_SIZE 50000

typedef unsigned int uint32;
typedef unsigned long long uint64;

// A5/3 parameters
const uint32 R1 = 0x87654321;
const uint32 R2 = 0xabcdef01;
const uint32 R3 = 0x12345678;

// A5/3 key schedule
void A53_key_schedule(uint32 key[4], uint32 frame_number) {
    uint32 R1_, R2_, R3_;
    uint32 key_stream[4];
    uint32 i;

    R1_ = key[3] ^ frame_number;
    R2_ = key[2];
    R3_ = key[1];

    for (i = 0; i < 32; i++) {
        key_stream[i / 8] <<= 1;
        key_stream[i / 8] |= (R1_ & 0x01);
        R1_ ^= ((R1_ << 13) | (R2_ >> 19)) ^ ((R1_ << 23) | (R3_ >> 9));
        R3_ ^= R2_ ^ (R2_ << 5);
        R2_ = ((R2_ << 8) | (R2_ >> 24)) ^ R1_ ^ R3_;
    }
}

// A5/3 encryption
void A53_encrypt(uint32 key[4], uint32 frame_number, uint32 *plaintext, uint32 *ciphertext) {
    uint32 i;

    A53_key_schedule(key, frame_number);
    for (i = 0; i < 4; i++) {
        ciphertext[i] = plaintext[i] ^ key[i];
    }
}

// Hash function
uint32 hash(uint32 *plaintext) {
    uint32 i, h = 0;

    for (i = 0; i < 4; i++) {
        h ^= plaintext[i];
    }

    return h;
}

// Password reduction function
void reduce(uint32 *hash_value, uint32 *password) {
    uint32 i;

    for (i = 0; i < 4; i++) {
        password[i] = hash_value[i] % 10;
        hash_value[i] /= 10;
    }
}

// Rainbow table generation
void generate_rainbow_table(uint32 start, uint32 end) {
    uint32 i, j, k;
    uint32 plaintext[4];
    uint32 ciphertext[4];
    uint32 hash_value;
    uint32 password[MAX_PASSWORD_LENGTH];
    uint32 *chain;
    uint32 key[4] = {0, 0, 0, 0};
    uint64 index;
    uint64 chain_length;
    FILE *fp;

    chain = (uint32 *) malloc(RAINBOW_TABLE_SIZE * sizeof(uint32));

    fp = fopen("rainbow_table.bin", "wb");
    if (fp == NULL) {
        printf("Error: could not open rainbow_table.bin for writing.\n");
        return;
    }

    srand(time(NULL));

    for (i = start; i < end; i++) {
        // Generate random plaintext
        for (j = 0; j < 4; j++) {
            plaintext[j] = rand();
        }

        // Generate random key
 for (j = 0; j < 4; j++) {
        key[j] = rand();
    }

    // Encrypt plaintext
    A53_encrypt(key, i, plaintext, ciphertext);

    // Compute hash value
    hash_value = hash(ciphertext);

    // Reduce hash value to a password
    reduce(&hash_value, password);

    // Generate chain
    for (j = 0; j < MAX_PASSWORD_LENGTH; j++) {
        A53_encrypt(key, j, password, ciphertext);
        hash_value = hash(ciphertext);
        reduce(&hash_value, password);
    }

    // Save last hash value of chain to rainbow table
    index = ((uint64) hash_value * RAINBOW_TABLE_SIZE) / 0xFFFFFFFF;
    chain_length = rand() % (MAX_PASSWORD_LENGTH * 2) + MAX_PASSWORD_LENGTH;
    chain[0] = hash_value;
    for (j = 1; j < chain_length; j++) {
        A53_encrypt(key, j + MAX_PASSWORD_LENGTH, password, ciphertext);
        hash_value = hash(ciphertext);
        reduce(&hash_value, password);
        chain[j] = hash_value;
    }
    fwrite(&chain[chain_length - 1], sizeof(uint32), 1, fp);
}

fclose(fp);
free(chain);

}

int main() {
    generate_rainbow_table(0, 100000);
    return 0;
}
