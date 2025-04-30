/**
 * @file vector.cpp
 * @brief Implementation of vectors sampling and some utilities for the HQC scheme
 */

#include "vector.h"
#include "parameters.h"
#include "shake_prng.h"
#include <stdlib.h>  // For malloc, free
#include <string.h>  // For memset
#include <stdint.h>  // Standard integer types
#include <stdio.h>   //printf
#include "esp_heap_caps.h"

/**
 * @brief Compares two vectors
 *
 * @param[in] v1 Pointer to an array that is first vector
 * @param[in] v2 Pointer to an array that is second vector
 * @param[in] size Integer that is the size of the vectors
 * @returns 0 if the vectors are equals and a negative/positive value otherwise
 */
 uint8_t vect_compare(const uint8_t *v1, const uint8_t *v2, uint32_t size) {
    uint64_t r = 0;

    for (size_t i = 0; i < size; i++) {
        r |= v1[i] ^ v2[i];
    }

    r = (~r + 1) >> 63;
    return (uint8_t) r;
}


/**
 * @brief Generates a random vector
 *
 * This function generates a random binary vector. It uses the the prng function.
 *
 * @param[in] v Pointer to an array
 * @param[in] size_v Size of v
 */
void vect_set_random_from_prng(uint64_t *v, uint32_t size_v) {
    shake_prng((uint8_t *)v, size_v * sizeof(uint64_t));
}


/**
 * @brief Generates a vector of a given Hamming weight
 *
 * Implementation of Algorithm 5 in https://eprint.iacr.org/2021/1631.pdf
 *
 * @param[in] ctx Pointer to the context of the seed expander
 * @param[in] v Pointer to an array
 * @param[in] weight Integer that is the Hamming weight
 */


static inline uint32_t compare_u32(const uint32_t v1, const uint32_t v2) {
    return 1 ^ (((v1 - v2) | (v2 - v1)) >> 31);
}



void vect_set_random_fixed_weight(seedexpander_state *ctx, uint64_t *v, uint16_t weight) {
    uint32_t *rand_u32 = (uint32_t *)heap_caps_malloc(weight * sizeof(uint32_t), MALLOC_CAP_8BIT);
    uint32_t *support = (uint32_t *)heap_caps_malloc(weight * sizeof(uint32_t), MALLOC_CAP_8BIT);
    uint32_t *index_tab = (uint32_t *)heap_caps_malloc(weight * sizeof(uint32_t), MALLOC_CAP_8BIT);
    uint64_t *bit_tab = (uint64_t *)heap_caps_malloc(weight * sizeof(uint64_t), MALLOC_CAP_8BIT);

    // Check for allocation failures
    if (!rand_u32 || !support || !index_tab || !bit_tab) {
        free(rand_u32); free(support); free(index_tab); free(bit_tab);
        return; 
    }

    memset(rand_u32, 0, weight * sizeof(uint32_t));
    memset(support, 0, weight * sizeof(uint32_t));
    memset(index_tab, 0, weight * sizeof(uint32_t));
    memset(bit_tab, 0, weight * sizeof(uint64_t));

    // Generate random numbers
    seedexpander(ctx, (uint8_t *)rand_u32, 4 * weight);

    // Step 1: Compute support array
    for (size_t i = 0; i < weight; ++i) {
        support[i] = i + rand_u32[i] % (PARAM_N - i);
    }

    // Step 2: Ensure unique indices
    for (int32_t i = weight - 1; i > 0; i--) {
        uint32_t found = 0;
        for (size_t j = i + 1; j < weight; ++j) {
            found |= compare_u32(support[j], support[i]);
        }
        uint32_t mask = -found;
        support[i] = (mask & i) ^ (~mask & support[i]);
    }

    // Step 3: Compute bit positions
    for (size_t i = 0; i < weight; i++) {
        index_tab[i] = support[i] >> 6;
        int32_t pos = support[i] & 0x3F;
        bit_tab[i] = ((uint64_t)1) << pos;
    }

    // Step 4: Set the values in v[]
    uint64_t val = 0;
    for (uint32_t i = 0; i < VEC_N_SIZE_64; i++) {
        val = 0;
        for (uint32_t j = 0; j < weight; j++) {
            uint32_t tmp = i - index_tab[j];
            int val1 = 1 ^ ((tmp | -tmp) >> 31);
            uint64_t mask = -val1;
            val |= (bit_tab[j] & mask);
        }
        v[i] |= val;
    }

    // Free dynamically allocated memory
    free(rand_u32);
    free(support);
    free(index_tab);
    free(bit_tab);
}


/**
 * @brief Generates a random vector of dimension <b>PARAM_N</b>
 *
 * This function generates a random binary vector of dimension <b>PARAM_N</b>. It generates a random
 * array of bytes using the seedexpander function, and drop the extra bits using a mask.
 *
 * @param[in] v Pointer to an array
 * @param[in] ctx Pointer to the context of the seed expander
 */
void vect_set_random(seedexpander_state *ctx, uint64_t *v) {
    seedexpander(ctx, (uint8_t *)v, VEC_N_SIZE_BYTES);

    v[VEC_N_SIZE_64 - 1] &= BITMASK(PARAM_N, 64);
}


/**
 * @brief Adds two vectors
 *
 * @param[out] o Pointer to an array that is the result
 * @param[in] v1 Pointer to an array that is the first vector
 * @param[in] v2 Pointer to an array that is the second vector
 * @param[in] size Integer that is the size of the vectors
 */
void vect_add(uint64_t *o, const uint64_t *v1, const uint64_t *v2, uint32_t size) {
    for (uint32_t i = 0 ; i < size ; ++i) {
        o[i] = v1[i] ^ v2[i];
    }
}



/**
 * @brief Resize a vector so that it contains <b>size_o</b> bits
 *
 * @param[out] o Pointer to the output vector
 * @param[in] size_o Integer that is the size of the output vector in bits
 * @param[in] v Pointer to the input vector
 * @param[in] size_v Integer that is the size of the input vector in bits
 */
 void vect_resize(uint64_t *o, uint32_t size_o, const uint64_t *v, uint32_t size_v) {
    uint64_t mask = 0x7FFFFFFFFFFFFFFF;
    int8_t val = 0;
    if (size_o < size_v) {

        if (size_o % 64) {
            val = 64 - (size_o % 64);
        }

        memcpy(o, v, VEC_N1N2_SIZE_BYTES);

        for (int8_t i = 0 ; i < val ; ++i) {
            o[VEC_N1N2_SIZE_64 - 1] &= (mask >> i);
        }
    } else {
        memcpy(o, v, CEIL_DIVIDE(size_v, 8));
    }
}

/**
 * @brief Prints a given number of bytes
 *
 * @param[in] v Pointer to an array of bytes
 * @param[in] size Integer that is number of bytes to be displayed
 */
 void vect_print(const uint64_t *v, const uint32_t size) {
    if(size == VEC_K_SIZE_BYTES) {
        uint8_t tmp [VEC_K_SIZE_BYTES] = {0};
        memcpy(tmp, v, VEC_K_SIZE_BYTES);
        for (uint32_t i = 0; i < VEC_K_SIZE_BYTES; ++i) {
            printf("%02x", tmp[i]);
        }
    } else if (size == VEC_N_SIZE_BYTES) {
        uint8_t tmp [VEC_N_SIZE_BYTES] = {0};
        memcpy(tmp, v, VEC_N_SIZE_BYTES);
        for (uint32_t i = 0; i < VEC_N_SIZE_BYTES; ++i) {
            printf("%02x", tmp[i]);
        }
    } else if (size == VEC_N1N2_SIZE_BYTES) {
        uint8_t tmp [VEC_N1N2_SIZE_BYTES] = {0};
        memcpy(tmp, v, VEC_N1N2_SIZE_BYTES);
        for (uint32_t i = 0; i < VEC_N1N2_SIZE_BYTES; ++i) {
            printf("%02x", tmp[i]);
        }
    }  else if (size == VEC_N1_SIZE_BYTES) {
        uint8_t tmp [VEC_N1_SIZE_BYTES] = {0};
        memcpy(tmp, v, VEC_N1_SIZE_BYTES);
        for (uint32_t i = 0; i < VEC_N1_SIZE_BYTES; ++i) {
            printf("%02x", tmp[i]);
        }
    }
}
