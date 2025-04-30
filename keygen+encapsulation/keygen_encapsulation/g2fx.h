#ifndef VECT_MUL_H
#define VECT_MUL_H

#include <stdint.h>


// Deklarácia pomocných funkcií
void set_bit(uint8_t *poly, uint64_t pos, uint8_t value);
uint8_t get_bit(const uint8_t *poly, uint64_t pos);

// Deklarácia hlavnej funkcie na násobenie vektorov
void vect_mul(uint64_t *o, const uint64_t *v1, const uint64_t *v2);
#endif // VECT_MUL_H