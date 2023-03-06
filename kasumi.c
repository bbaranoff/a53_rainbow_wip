#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include "kasumi.h"

#define MAX_PASSWORD_LENGTH 16
#define MAX_CHAIN_LENGTH 1000
#define TABLE_SIZE 1600000000
#define HASH_LENGTH 8

typedef struct {
    uint8_t key[KASUMI_KEY_SIZE];
    uint8_t iv[KASUMI_IV_SIZE];
} RainbowChain;

void generate_random_password(uint8_t* password, int length) {
    for (int i = 0; i < length; i++) {
        password[i] = rand() % 256;
    }
}

void compute_hash(uint8_t* input, uint8_t* output) {
    kasumi_key_schedule_t schedule;
    uint8_t block[KASUMI_BLOCK_SIZE];

    memset(block, 0, KASUMI_BLOCK_SIZE);
    memcpy(block, input, HASH_LENGTH);
    kasumi_key_schedule(input, schedule);
    kasumi_encrypt(block, schedule);

    memcpy(output, block, HASH_LENGTH);
}

void reduce_hash(uint8_t* input, uint8_t* output, int index) {
    for (int i = 0; i < HASH_LENGTH; i++) {
        output[i] = input[(index + i) % HASH_LENGTH];
    }
}

void compute_chain(uint8_t* password, int length, RainbowChain* chain) {
    kasumi_key_schedule_t schedule;
    uint8_t block[KASUMI_BLOCK_SIZE];

    memcpy(chain->key, password, KASUMI_KEY_SIZE);
    memset(chain->iv, 0, KASUMI_IV_SIZE);
    kasumi_key_schedule(chain->key, schedule);

    for (int i = 0; i < MAX_CHAIN_LENGTH; i++) {
        kasumi_encrypt(chain->iv, schedule);
        memcpy(block, chain->iv, KASUMI_BLOCK_SIZE);
        kasumi_encrypt(block, schedule);
        reduce_hash(block, chain->key, i);
    }
}

int main() {
    RainbowChain chain;
    uint8_t password[MAX_PASSWORD_LENGTH];
    uint8_t hash[HASH_LENGTH];
    uint8_t target_hash[HASH_LENGTH] = {0x4f, 0x02, 0x08, 0x06, 0x92, 0xfd, 0xa2, 0x23};
    uint8_t* hash_table = (uint8_t*) malloc(TABLE_SIZE);
    int chain_length = 100;
    int password_length = 8;
    int found = 0;
    srand(time(NULL));

    printf("Starting rainbow table generation...\n");

    for (int i = 0; i < TABLE_SIZE; i += HASH_LENGTH) {
        generate_random_password(password, password_length);
        compute_chain(password, password_length, &chain);
        memcpy(hash_table + i, chain.key, HASH_LENGTH);
    }

    printf("Rainbow table generation completed!\n");
    printf("Starting cracking...\n");

    for (int i = 0; i < TABLE_SIZE && !found; i += HASH_LENGTH) {
       memcpy(hash, hash_table + i, HASH_LENGTH);

        for (int j = 0; j < chain_length && !found; j++) {
            reduce_hash(hash, password, j);
            compute_chain(password, password_length, &chain);
            compute_hash(chain.key, hash);

            if (memcmp(hash, target_hash, HASH_LENGTH) == 0) {
                found = 1;
                printf("Password found: ");
                for (int k = 0; k < password_length; k++) {
                    printf("%02x", password[k]);
                }
                printf("\n");
            }
        }
    }

    if (!found) {
         printf("Password not found :(\n");
    }

    free(hash_table);
    return 0;
}
