/**
 * @file hqc.cpp
 * @brief Implementation of hqc.h
 */

#include "hqc.h"
#include "parameters.h"
#include "shake_prng.h"
#include <stdint.h>
#include "vector.h"
#include "parsing.h"
#include "g2fx.h"
#include "code.h"
#include <stdlib.h>
#include <string.h>
#include "esp_heap_caps.h"
#include <Arduino.h>
/**
 * @brief Keygen of the HQC_PKE IND_CPA scheme
 *
 * The public key is composed of the syndrome <b>s</b> as well as the <b>seed</b> used to generate the vector <b>h</b>.
 *
 * The secret key is composed of the <b>seed</b> used to generate vectors <b>x</b> and  <b>y</b>.
 * As a technicality, the public key is appended to the secret key in order to respect NIST API.
 *
 * @param[out] pk String containing the public key
 * @param[out] sk String containing the secret key
 */

 void hqc_pke_keygen(unsigned char* pk, unsigned char* sk) {
    seedexpander_state sk_seedexpander;
    uint8_t *sk_seed = (uint8_t *)heap_caps_malloc(SEED_BYTES, MALLOC_CAP_8BIT);
    memset(sk_seed, 0, SEED_BYTES);

    shake_prng(sk_seed, SEED_BYTES);
    seedexpander_init(&sk_seedexpander, sk_seed, SEED_BYTES);

    seedexpander_state pk_seedexpander;
    uint8_t *pk_seed = (uint8_t *)heap_caps_malloc(SEED_BYTES, MALLOC_CAP_8BIT);
    memset(pk_seed, 0, SEED_BYTES);

    shake_prng(pk_seed, SEED_BYTES);
    seedexpander_init(&pk_seedexpander, pk_seed, SEED_BYTES);

    //-- Compute secret key (X)
    uint64_t *x = (uint64_t *)heap_caps_malloc(VEC_N_SIZE_64 * sizeof(uint64_t), MALLOC_CAP_8BIT);
    memset(x, 0, VEC_N_SIZE_64 * sizeof(uint64_t));
    vect_set_random_fixed_weight(&sk_seedexpander, x, PARAM_OMEGA);
    
    //-- Compute secret key (Y)
    uint64_t *y = (uint64_t *)heap_caps_malloc(VEC_N_SIZE_64 * sizeof(uint64_t), MALLOC_CAP_8BIT);
    memset(y, 0, VEC_N_SIZE_64 * sizeof(uint64_t));
    vect_set_random_fixed_weight(&sk_seedexpander, y, PARAM_OMEGA);

    //-- Compute public key
    uint64_t *h = (uint64_t *)heap_caps_malloc(VEC_N_SIZE_64 * sizeof(uint64_t), MALLOC_CAP_8BIT);
    memset(h, 0, VEC_N_SIZE_64 * sizeof(uint64_t));
    vect_set_random(&pk_seedexpander, h);

    uint64_t *s = (uint64_t *)heap_caps_malloc(VEC_N_SIZE_64 * sizeof(uint64_t), MALLOC_CAP_8BIT);
    memset(s, 0, VEC_N_SIZE_64 * sizeof(uint64_t));
    vect_mul(s, y, h);
    heap_caps_free(y);
    heap_caps_free(h); 

    vect_add(s, x, s, VEC_N_SIZE_64);
    heap_caps_free(x);

    //-- Parse keys to string
    hqc_public_key_to_string(pk, pk_seed, s);
    heap_caps_free(pk_seed);
    heap_caps_free(s);

    hqc_secret_key_to_string(sk, sk_seed, pk);

    // Uvoľnenie pamäte
    heap_caps_free(sk_seed);    
}


void hqc_pke_encrypt(uint64_t *u, uint64_t *v, uint64_t *m, unsigned char *theta, const unsigned char *pk) {
    seedexpander_state seedexpander;

    // Create seed_expander from theta
    seedexpander_init(&seedexpander, theta, SEED_BYTES);

    // Retrieve h and s from public key
    uint64_t *h = (uint64_t *)heap_caps_malloc(VEC_N_SIZE_64 * sizeof(uint64_t), MALLOC_CAP_8BIT);
    uint64_t *s = (uint64_t *)heap_caps_malloc(VEC_N_SIZE_64 * sizeof(uint64_t), MALLOC_CAP_8BIT);
    memset(h, 0, VEC_N_SIZE_64 * sizeof(uint64_t));
    memset(s, 0, VEC_N_SIZE_64 * sizeof(uint64_t));
    hqc_public_key_from_string(h, s, pk);

    // Generate r1, r2 and e
    uint64_t *r1 = (uint64_t *)heap_caps_malloc(VEC_N_SIZE_64 * sizeof(uint64_t), MALLOC_CAP_8BIT);
    memset(r1, 0, VEC_N_SIZE_64 * sizeof(uint64_t));
    vect_set_random_fixed_weight(&seedexpander, r1, PARAM_OMEGA_R);
    
    uint64_t *r2 = (uint64_t *)heap_caps_malloc(VEC_N_SIZE_64 * sizeof(uint64_t), MALLOC_CAP_8BIT);
    memset(r2, 0, VEC_N_SIZE_64 * sizeof(uint64_t));
    vect_set_random_fixed_weight(&seedexpander, r2, PARAM_OMEGA_R);

    uint64_t *e = (uint64_t *)heap_caps_malloc(VEC_N_SIZE_64 * sizeof(uint64_t), MALLOC_CAP_8BIT);
    memset(e, 0, VEC_N_SIZE_64 * sizeof(uint64_t));
    vect_set_random_fixed_weight(&seedexpander, e, PARAM_OMEGA_E);

    // Compute u = r1 + r2.h
    vect_mul(u, r2, h);
    if (h) {
        heap_caps_free(h);
    } else {
        printf("Failed to free: h (pointer is NULL)\n");
    }

    vect_add(u, r1, u, VEC_N_SIZE_64);
    if (r1) {
        heap_caps_free(r1);
    } else {
        printf("Failed to free: r1 (pointer is NULL)\n");
    }

    // Compute v = m.G by encoding the message
    code_encode(v, m);

    uint64_t *tmp1 = (uint64_t *)heap_caps_malloc(VEC_N_SIZE_64 * sizeof(uint64_t), MALLOC_CAP_8BIT);
    memset(tmp1, 0, VEC_N_SIZE_64 * sizeof(uint64_t));
    vect_resize(tmp1, PARAM_N, v, PARAM_N1N2);

    // Compute v = m.G + s.r2 + e
    uint64_t *tmp2 = (uint64_t *)heap_caps_malloc(VEC_N_SIZE_64 * sizeof(uint64_t), MALLOC_CAP_8BIT);
    memset(tmp2, 0, VEC_N_SIZE_64 * sizeof(uint64_t));
    vect_mul(tmp2, r2, s);
    // Safely free memory and check for NULL before freeing
    if (s) {
        heap_caps_free(s);
    } else {
        printf("Failed to free: s (pointer is NULL)\n");
    }
    
    if (r2) {
        heap_caps_free(r2);
    } else {
        printf("Failed to free: r2 (pointer is NULL)\n");
    }


    vect_add(tmp2, e, tmp2, VEC_N_SIZE_64);
    if (e) {
        heap_caps_free(e);
    } else {
        printf("Failed to free: e (pointer is NULL)\n");
    }

    vect_add(tmp2, tmp1, tmp2, VEC_N_SIZE_64);
    if (tmp1) {
        heap_caps_free(tmp1);
    } else {
        printf("Failed to free: tmp1 (pointer is NULL)\n");
    }

    vect_resize(v, PARAM_N1N2, tmp2, PARAM_N);
    if (tmp2 != NULL) {
        printf("freeing tmp2?");
        heap_caps_free(tmp2);
    } else {
        printf("tmp2 is NULL, skipping free\n");
    }
}


/**
 * @brief Decryption of the HQC_PKE IND_CPA scheme
 *
 * @param[out] m Vector representing the decrypted message
 * @param[in] u Vector u (first part of the ciphertext)
 * @param[in] v Vector v (second part of the ciphertext)
 * @param[in] sk String containing the secret key
 */
void hqc_pke_decrypt(uint64_t *m, const uint64_t *u, const uint64_t *v, const unsigned char *sk) {
    uint64_t *x = (uint64_t *)heap_caps_malloc(VEC_N_SIZE_64 * sizeof(uint64_t), MALLOC_CAP_8BIT);
    uint64_t *y = (uint64_t *)heap_caps_malloc(VEC_N_SIZE_64 * sizeof(uint64_t), MALLOC_CAP_8BIT);
    uint8_t *pk = (uint8_t *)heap_caps_malloc(PUBLIC_KEY_BYTES, MALLOC_CAP_8BIT);
    uint64_t *tmp1 = (uint64_t *)heap_caps_malloc(VEC_N_SIZE_64 * sizeof(uint64_t), MALLOC_CAP_8BIT);
    uint64_t *tmp2 = (uint64_t *)heap_caps_malloc(VEC_N_SIZE_64 * sizeof(uint64_t), MALLOC_CAP_8BIT);

    memset(x, 0, VEC_N_SIZE_64 * sizeof(uint64_t));
    memset(y, 0, VEC_N_SIZE_64 * sizeof(uint64_t));
    memset(pk, 0, PUBLIC_KEY_BYTES);
    memset(tmp1, 0, VEC_N_SIZE_64 * sizeof(uint64_t));
    memset(tmp2, 0, VEC_N_SIZE_64 * sizeof(uint64_t));

    // Retrieve x, y, pk from secret key
    hqc_secret_key_from_string(x, y, pk, sk);
    // Compute v - u.y
    vect_resize(tmp1, PARAM_N, v, PARAM_N1N2);
    vect_mul(tmp2, y, u);
    vect_add(tmp2, tmp1, tmp2, VEC_N_SIZE_64);

    // Compute m by decoding v - u.y
    code_decode(m, tmp2);

    heap_caps_free(x);
    heap_caps_free(y);
    heap_caps_free(pk);
    heap_caps_free(tmp1);
    heap_caps_free(tmp2);
}
