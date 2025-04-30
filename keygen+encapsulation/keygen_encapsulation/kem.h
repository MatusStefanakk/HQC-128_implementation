#ifndef HQC_H
#define HQC_H

/**
 * @file hqc.h
 * @brief Functions of the HQC_PKE IND_CPA scheme
 */

#include <stdint.h>

void hqc_pke_keygen(unsigned char* pk, unsigned char* sk);
int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);


#endif