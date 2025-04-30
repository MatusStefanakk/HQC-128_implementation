#include "api.h"
#include "hqc.h"
#include "parameters.h"
#include "lib/fips202.h"
#include "vector.h"
#include "parsing.h"
#include "shake_ds.h"

#include <stdint.h>
#include <string.h>
#include <stdlib.h>  // For malloc, free

#include <stdio.h>
#include <esp_heap_caps.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <Arduino.h>


/**
 * @brief Keygen of the HQC_KEM IND_CAA2 scheme
 *
 * The public key is composed of the syndrome <b>s</b> as well as the seed used to generate the vector <b>h</b>.
 *
 * The secret key is composed of the seed used to generate vectors <b>x</b> and <b>y</b>.
 * As a technicality, the public key is appended to the secret key in order to respect NIST API.
 *
 * @param[out] pk String containing the public key
 * @param[out] sk String containing the secret key
 * @returns 0 if keygen is successful
 */
int crypto_kem_keypair(unsigned char *pk, unsigned char *sk) {
    #ifdef VERBOSE
        printf("\n\n\n\n### KEYGEN ###");
    #endif

    hqc_pke_keygen(pk, sk);
    return 0;
}

/**
 * @brief Decapsulation of the HQC_KEM IND_CAA2 scheme
 *
 * @param[out] ss String containing the shared secret
 * @param[in] ct String containing the cipĥertext
 * @param[in] sk String containing the secret key
 * @returns 0 if decapsulation is successful, -1 otherwise
 */
int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk) {
    uint8_t result;
    uint8_t *pk = (uint8_t *)heap_caps_malloc(PUBLIC_KEY_BYTES, MALLOC_CAP_8BIT);
    uint64_t *m = (uint64_t *)heap_caps_malloc(VEC_K_SIZE_64 * sizeof(uint64_t), MALLOC_CAP_8BIT);
    uint8_t *theta = (uint8_t *)heap_caps_malloc(SHAKE256_512_BYTES, MALLOC_CAP_8BIT);
    uint64_t *u2 = (uint64_t *)heap_caps_malloc(VEC_N_SIZE_64 * sizeof(uint64_t), MALLOC_CAP_8BIT);
    uint64_t *v2 = (uint64_t *)heap_caps_malloc(VEC_N1N2_SIZE_64 * sizeof(uint64_t), MALLOC_CAP_8BIT);
    uint8_t *d2 = (uint8_t *)heap_caps_malloc(SHAKE256_512_BYTES, MALLOC_CAP_8BIT);
    uint8_t *mc = (uint8_t *)heap_caps_malloc((VEC_K_SIZE_BYTES + VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES), MALLOC_CAP_8BIT);
    uint64_t *salt = (uint64_t *)heap_caps_malloc(SALT_SIZE_64 * sizeof(uint64_t), MALLOC_CAP_8BIT);
    uint8_t *tmp = (uint8_t *)heap_caps_malloc((VEC_K_SIZE_BYTES + SALT_SIZE_BYTES + SEED_BYTES), MALLOC_CAP_8BIT);
    uint64_t *u = (uint64_t *)heap_caps_malloc(VEC_N_SIZE_64 * sizeof(uint64_t), MALLOC_CAP_8BIT);
    uint64_t *v = (uint64_t *)heap_caps_malloc(VEC_N1N2_SIZE_64 * sizeof(uint64_t), MALLOC_CAP_8BIT);
    uint8_t *d = (uint8_t *)heap_caps_malloc(SHAKE256_512_BYTES, MALLOC_CAP_8BIT);
    shake256incctx shake256state;

    // Retrieving u, v and d from ciphertext
    hqc_ciphertext_from_string(u, v , d, salt, ct);

    // Retrieving pk from sk
    memcpy(pk, sk + SEED_BYTES, PUBLIC_KEY_BYTES);

    // Decryting
    hqc_pke_decrypt(m, u, v, sk);
    
    // Computing theta
    memcpy(tmp, m, VEC_K_SIZE_BYTES);
    memcpy(tmp + VEC_K_SIZE_BYTES, pk, SEED_BYTES);
    memcpy(tmp + VEC_K_SIZE_BYTES + SEED_BYTES, salt, SALT_SIZE_BYTES);

    shake256_512_ds(&shake256state, theta, tmp, VEC_K_SIZE_BYTES + SEED_BYTES + SALT_SIZE_BYTES, G_FCT_DOMAIN);

    // Encrypting m'
    hqc_pke_encrypt(u2, v2, m, theta, pk);

    // Computing d'
    shake256_512_ds(&shake256state, d2, (uint8_t *) m, VEC_K_SIZE_BYTES, H_FCT_DOMAIN);

    // Computing shared secret
    memcpy(mc, m, VEC_K_SIZE_BYTES);
    memcpy(mc + VEC_K_SIZE_BYTES, u, VEC_N_SIZE_BYTES);
    memcpy(mc + VEC_K_SIZE_BYTES + VEC_N_SIZE_BYTES, v, VEC_N1N2_SIZE_BYTES);
    shake256_512_ds(&shake256state, ss, mc, VEC_K_SIZE_BYTES + VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES, K_FCT_DOMAIN);

    // Abort if c != c' or d != d'
    result = vect_compare((uint8_t *)u, (uint8_t *)u2, VEC_N_SIZE_BYTES);
    result |= vect_compare((uint8_t *)v, (uint8_t *)v2, VEC_N1N2_SIZE_BYTES);
    result |= vect_compare(d, d2, SHAKE256_512_BYTES);

    result = (uint8_t) (-((int16_t) result) >> 15);

    for (size_t i = 0 ; i < SHARED_SECRET_BYTES ; i++) {
        ss[i] &= ~result;
    }

    heap_caps_free(u);
    heap_caps_free(v);
    heap_caps_free(d);
    heap_caps_free(pk);
    heap_caps_free(m);
    heap_caps_free(theta);
    heap_caps_free(u2);
    heap_caps_free(v2);
    heap_caps_free(d2);
    heap_caps_free(mc);
    heap_caps_free(salt);
    heap_caps_free(tmp);

    return -(result & 1);
}


/**
 * @brief Encapsulation of the HQC_KEM IND_CAA2 scheme
 *
 * @param[out] ct String containing the ciphertext
 * @param[out] ss String containing the shared secret
 * @param[in] pk String containing the public key
 * @returns 0 if encapsulation is successful
 */
int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk) {
    shake256incctx *shake256state = (shake256incctx *)heap_caps_malloc(sizeof(shake256incctx), MALLOC_CAP_8BIT);
    if (!shake256state) {
        printf("Failed to allocate shake256state!\n");
        return -1;
    }

    // Allocate necessary memory at the start using heap_caps_malloc
    uint8_t *theta = (uint8_t *)heap_caps_malloc(SHAKE256_512_BYTES, MALLOC_CAP_8BIT);
    uint64_t *m = (uint64_t *)heap_caps_malloc(VEC_K_SIZE_64 * sizeof(uint64_t), MALLOC_CAP_8BIT);
    uint64_t *salt = (uint64_t *)heap_caps_malloc(SALT_SIZE_64 * sizeof(uint64_t), MALLOC_CAP_8BIT);
    uint8_t *tmp = (uint8_t *)heap_caps_malloc(VEC_K_SIZE_BYTES + SEED_BYTES + SALT_SIZE_BYTES, MALLOC_CAP_8BIT);

    if (!theta || !m || !salt || !tmp) {
        printf("First Memory allocation failed!\n");
        heap_caps_free(shake256state);
        heap_caps_free(theta);
        heap_caps_free(m);
        heap_caps_free(salt);
        heap_caps_free(tmp);
        return -1;
    }
    // Compute m and theta
    vect_set_random_from_prng(m, VEC_K_SIZE_64);
    vect_set_random_from_prng(salt, SALT_SIZE_64);
    
    memcpy(tmp, m, VEC_K_SIZE_BYTES);
    memcpy(tmp + VEC_K_SIZE_BYTES, pk, SEED_BYTES);
    memcpy(tmp + VEC_K_SIZE_BYTES + SEED_BYTES, salt, SALT_SIZE_BYTES);

    shake256_512_ds(shake256state, theta, tmp, VEC_K_SIZE_BYTES + SEED_BYTES + SALT_SIZE_BYTES, G_FCT_DOMAIN);

    heap_caps_free(tmp); 

    // Allocate encryption-related memory
    uint64_t *u = (uint64_t *)heap_caps_malloc(VEC_N_SIZE_64 * sizeof(uint64_t), MALLOC_CAP_8BIT);
    uint64_t *v = (uint64_t *)heap_caps_malloc(VEC_N1N2_SIZE_64 * sizeof(uint64_t), MALLOC_CAP_8BIT);
    uint8_t *d = (uint8_t *)heap_caps_malloc(SHAKE256_512_BYTES, MALLOC_CAP_8BIT);

    if (!u || !v || !d) {
        printf("Second Memory allocation failed!\n");
        heap_caps_free(shake256state);
        heap_caps_free(theta);
        heap_caps_free(m);
        heap_caps_free(salt);
        heap_caps_free(u);
        heap_caps_free(v);
        heap_caps_free(d);
        return -1;
    }

    // Encrypt message
    hqc_pke_encrypt(u, v, m, theta, pk);

    //Cipher text to string 
    // u is copied here, cuz it truncate for some reason later in code
    memcpy(ct, u, VEC_N_SIZE_BYTES);
    heap_caps_free(theta);


    shake256_512_ds(shake256state, d, (uint8_t *)m, VEC_K_SIZE_BYTES, H_FCT_DOMAIN);


    // Computing shared secret 
    uint8_t *mc = (uint8_t *)heap_caps_malloc(VEC_K_SIZE_BYTES + VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES, MALLOC_CAP_8BIT);
    if (!mc) {
        printf("Third Memory allocation failed!\n");
        heap_caps_free(shake256state);
        heap_caps_free(theta);
        heap_caps_free(m);
        heap_caps_free(salt);
        heap_caps_free(u);
        heap_caps_free(v);
        heap_caps_free(d);
        return -1;
    }

    memset(mc, 0, VEC_K_SIZE_BYTES + VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES);
    memcpy(mc, m, VEC_K_SIZE_BYTES);
    memcpy(mc + VEC_K_SIZE_BYTES, u, VEC_N_SIZE_BYTES);

    heap_caps_free(m);
    
    //Cipher text to string    
    memcpy(ct + VEC_N_SIZE_BYTES, v, VEC_N1N2_SIZE_BYTES);
    memcpy(ct + VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES, d, SHAKE256_512_BYTES);
    memcpy(ct + VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES + SHAKE256_512_BYTES, salt, SALT_SIZE_BYTES);

    heap_caps_free(salt);
    heap_caps_free(u);
    heap_caps_free(v);
    heap_caps_free(d);

    
    memcpy(mc + VEC_K_SIZE_BYTES + VEC_N_SIZE_BYTES, v, VEC_N1N2_SIZE_BYTES);

    // Compute shared secret
    shake256_512_ds(shake256state, ss, mc, VEC_K_SIZE_BYTES + VEC_N_SIZE_BYTES + VEC_N1N2_SIZE_BYTES, K_FCT_DOMAIN);

    // Free all allocated memory at the end
    heap_caps_free(shake256state);
    heap_caps_free(mc);

    return 0;
}



