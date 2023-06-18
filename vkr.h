#ifndef VKR_H
#define VKR_H

#include <stdbool.h>
#include <stdint.h>

void mylog(int16_t num);
void mylog_s(char *str);

bool validate_hash(uint8_t input[], uint16_t input_len, uint8_t expected[]);
bool validate_value_hash(uint8_t hash[]);

uint8_t *get_node_by_hash(uint8_t hash[], bool is_root);

uint8_t *save_node(uint8_t content[], uint16_t content_len, bool is_root);
uint8_t *save_node_with_value(uint8_t content[], uint16_t content_len, bool is_root, uint8_t *hash_place);

#endif