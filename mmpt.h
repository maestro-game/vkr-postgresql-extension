#ifndef MMPT_H
#define MMPT_H

void insert(uint8_t *root, uint8_t key[], size_t key_len, uint16_t hash_len);
uint8_t *get_value(uint8_t *root, uint8_t key[], uint32_t key_len, uint16_t hash_len);
uint8_t *merkle_proof(uint8_t *root, uint8_t key[], uint32_t key_len, uint16_t in_hash_len);
uint8_t *validate_all(uint8_t *root, uint16_t in_hash_len);

#endif