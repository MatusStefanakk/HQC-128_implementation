#include <stdlib.h>
#include <string.h>
#include "g2fx.h"
#include "parameters.h"
#include "api.h"
// Implementácie funkcií
void set_bit(uint8_t *poly, uint64_t pos, uint8_t value) {
    uint64_t byte_pos = pos / 8;
    uint8_t bit_pos = pos % 8;
    if (value) {
        poly[byte_pos] |= (1 << bit_pos);
    } else {
        poly[byte_pos] &= ~(1 << bit_pos);
    }
}

uint8_t get_bit(const uint8_t *poly, uint64_t pos) {
    uint64_t byte_pos = pos / 8;
    uint8_t bit_pos = pos % 8;
    return (poly[byte_pos] >> bit_pos) & 1;
}

void vect_mul(uint64_t *o, const uint64_t *v1, const uint64_t *v2) {
    uint8_t *tmp = (uint8_t *)malloc(2 * VEC_N_SIZE_BYTES);
    if (!tmp) return;
    memset(tmp, 0, 2 * VEC_N_SIZE_BYTES);  
    
    for (uint64_t i = 0; i < PARAM_N; i++) {
        if (get_bit((uint8_t *)v1, i)) {
            for (uint64_t j = 0; j < PARAM_N; j++) {
                if (get_bit((uint8_t *)v2, j)) {
                    uint64_t pos = i + j;
                    set_bit(tmp, pos, get_bit(tmp, pos) ^ 1);
                }
            }
        }
    }

    for (uint64_t i = 2 * PARAM_N - 2; i >= PARAM_N; i--) {
        if (get_bit(tmp, i)) {
            set_bit(tmp, i, 0);
            set_bit(tmp, i - PARAM_N, get_bit(tmp, i - PARAM_N) ^ 1);
        }
    }

    memcpy(o, tmp, VEC_N_SIZE_64 * sizeof(uint64_t));
    free(tmp);
}