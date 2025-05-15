#include <stdio.h>
#include "api.h"
#include "parameters.h"
#include <stdlib.h>  // For malloc, free
#include "shake_prng.h"
#include "vector.h"
#include <string.h>
#include <stdint.h>
#include <esp_heap_caps.h> 
#include <time.h>

//set the seed from hqc-128_kat.req
const char *seedString = "42C667A186390F26C8F024D31D5FE3D20145BC2FCCF26C865E20DF7626CEF09E4D9EADD263D95EDE934A74B3721EAAB0";

void testing(){
    uint8_t seed[48];
    hexStringToByteArray(seedString, seed, 48);
    shake_prng_init(seed, NULL, 48, 0);
}

void hexStringToByteArray(const char *hexString, uint8_t *byteArray, size_t length) {
    for (size_t i = 0; i < length; i++) {
        sscanf(hexString + 2 * i, "%2hhx", &byteArray[i]);
    }
}

struct timespec start,end;

// Custom task for key pair generation
TaskHandle_t keygen_encapsulationTaskHandle;

void keygen_encapsulationTask(void *pvParameters) {
    Serial.println("\nStarting Keygen with encpasulation task...");

    // Allocate memory for pk and sk on the heap
    unsigned char *pk = (unsigned char *)heap_caps_malloc(PUBLIC_KEY_BYTES, MALLOC_CAP_8BIT);
    unsigned char *sk = (unsigned char *)heap_caps_malloc(SECRET_KEY_BYTES, MALLOC_CAP_8BIT);
    unsigned char *ct = (unsigned char *)heap_caps_malloc(CIPHERTEXT_BYTES, MALLOC_CAP_8BIT);
    unsigned char *key1 = (unsigned char *)heap_caps_malloc(SHARED_SECRET_BYTES, MALLOC_CAP_8BIT);

    // Check allocation
    if (!pk || !sk) {
        Serial.println("Memory allocation failed for pk or sk!");
        heap_caps_free(pk);
        heap_caps_free(sk);
        vTaskDelete(NULL);
    }

    //Generate key pair
    clock_gettime(CLOCK_MONOTONIC, &start);
    crypto_kem_keypair(pk, sk);
    clock_gettime(CLOCK_MONOTONIC, &end);
    double time_ms = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1000000.0;
    Serial.printf("čas [keygen]: %.3f ms\n",time_ms);
    time_ms = 0.0;

    //main function call
    //Serial.println("Starting encapsulation in main?");
    clock_gettime(CLOCK_MONOTONIC, &start);
    crypto_kem_enc(ct, key1, pk);
    clock_gettime(CLOCK_MONOTONIC, &end);
    time_ms = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1000000.0;
    Serial.printf("čas [encapsulation]: %.3f ms\n",time_ms);
    time_ms = 0.0;


    Serial.println("\n ************************************************************************* ");
    
    Serial.println("sk: ");
    for(int i = 0 ; i < SECRET_KEY_BYTES ; ++i) Serial.printf("%02X", sk[i]);

    Serial.println("\n\npk: ");
    for(int i = 0 ; i < PUBLIC_KEY_BYTES ; ++i) Serial.printf("%02X", pk[i]);

    Serial.println("\n\nsecret1 (ss): ");
    for (int i = 0; i < SHARED_SECRET_BYTES; ++i) Serial.printf("%02X", key1[i]);

    Serial.println("\n\nciphertext (ct): "); 
    for(int i = 0 ; i < CIPHERTEXT_BYTES ; ++i) Serial.printf("%02X", ct[i]);

    // Cleanup
    heap_caps_free(pk);
    heap_caps_free(sk);
    heap_caps_free(ct);
    heap_caps_free(key1);

    vTaskDelete(NULL); // End the task
}

void setup() {
    Serial.begin(9600);
    
    //Comment this if u dont want to use KATs seed for generation
    //testing(); //for testing

    delay(5000); // Allow time for the serial monitor to connect

    xTaskCreatePinnedToCore(keygen_encapsulationTask, "keygen_encapsulationTask", 65536, NULL, 1, &keygen_encapsulationTaskHandle, 1);
}

void loop(){}

