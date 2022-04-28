/*
 * Copyright (C) 2008, 2009, 2010 Kaspar Schleiser <kaspar@schleiser.de>
 * Copyright (C) 2013 INRIA
 * Copyright (C) 2013 Ludwig Knüpfer <ludwig.knuepfer@fu-berlin.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       Default application that shows a lot of functionality of RIOT
 *
 * @author      Kaspar Schleiser <kaspar@schleiser.de>
 * @author      Oliver Hahm <oliver.hahm@inria.fr>
 * @author      Ludwig Knüpfer <ludwig.knuepfer@fu-berlin.de>
 *
 * @}
 */

#include <stdio.h>
#include <string.h>

#include "thread.h"
#include "shell.h"
#include "shell_commands.h"

#ifdef MODULE_NETIF
#include "net/gnrc/pktdump.h"
#include "net/gnrc.h"
#endif

#include <sodium.h>
//#include <gcrypt.h>
//#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/random.h>
#include <xtimer.h>

#define SODIUM 0
#define GCRYPT 0
#define WOLFCRYPT 1

//void ecdsaWolfcryptTest(void);

static const uint32_t ecdsaTestMessage[] = { 0x65637572, 0x20612073, 0x68206F66, 0x20686173, 0x69732061, 0x68697320, 0x6F2C2054, 0x48616C6C};

#if SODIUM
void ecdsaSodiumTest() {
	int ret __attribute__((unused));
	
	// Init
	if(sodium_init() == -1){
            puts("Couldn't initialize sodium");
        }
        // Keygen
        unsigned char pk[crypto_sign_PUBLICKEYBYTES];
        unsigned char sk[crypto_sign_SECRETKEYBYTES];
        crypto_sign_keypair(pk, sk);
       
        // Create Signature
	unsigned int message_len = sizeof(ecdsaTestMessage)/sizeof(ecdsaTestMessage[0]); 
        unsigned char signature[crypto_sign_BYTES];
        unsigned long long signature_len;
	ret = crypto_sign_detached(signature, &signature_len,
            (unsigned char*)ecdsaTestMessage, message_len, sk);
	if (ret != 0){
	    puts("Libsodium signature generation failed");
	}

        ret = crypto_sign_verify_detached(signature, (unsigned char*)ecdsaTestMessage,
                                message_len, pk);
	if (ret != 0){
	    puts("Libsodium signature verification failed");
	}
}
#endif

#if GCRYPT
void ecdsaGcryptTest() {
	int ret __attribute__((unused));

	if(!gcry_check_version("1.8.5")){
            puts("Couldn't initialize libgcrypt");
        }
	// Setup
	gcry_sexp_t key_spec, key, pub_key, priv_key, signature; //data ;
        gcry_mpi_t mpi_k = NULL;
	gcry_md_hd_t hd;
        int rc;
	size_t length = 32;
	uint8_t digest[length];
        //char *msg =  "Hallo Welt!";
	const char *template = "(data (flags raw)(hash %s %b))";

	
 
	rc = gcry_md_open(&hd, GCRY_MD_SHA256, GCRY_MD_FLAG_SECURE);
	if ((rc = gcry_mpi_scan (&mpi_k, GCRYMPI_FMT_USG, digest, length, NULL))){ 
            printf("error converting MPI: %s\n", gcry_strerror(rc));
    	}

	gcry_md_write(hd, ecdsaTestMessage, sizeof(ecdsaTestMessage)/sizeof(ecdsaTestMessage[0]));
	/*	
        rc = gcry_sexp_build(&data, NULL, "(data (flags raw) (value %m))", mpi_k);
        if (rc) {
            printf("converting data for encryption failed: %s\n", gcry_strerror(rc));
        }
*/
        // Keygen

        rc = gcry_sexp_new(&key_spec, "(genkey (ecc (curve \"Ed25519\")))", 0, 1);
        rc = gcry_pk_genkey(&key, key_spec);      
        if (rc) {
            printf("error creating S-expression: %s\n", gcry_strerror(rc));
        }
	rc = gcry_pk_testkey(key);
        if (rc) {
            printf("error testing key: %s\n", gcry_strerror(rc));
        }
	gcry_sexp_release(key_spec);
        pub_key = gcry_sexp_find_token(key, "public-key", 0);
        if (!pub_key) {
            printf("public part missing in key\n");
        }
        priv_key = gcry_sexp_find_token(key, "private-key", 0);
        if (!priv_key) {
            printf("privatepart missing in key\n");
        }
	gcry_sexp_release(key);
	//gcry_sexp_dump(pub_key);
	//gcry_sexp_dump(priv_key);
	//gcry_sexp_dump(data) 
        
	// Create Signature
	rc = gcry_pk_hash_sign(&signature, template, priv_key, hd, NULL);
        if (rc) {
            printf("gcrypt error signing data: %s\n", gcry_strerror(rc));
        }
	gcry_sexp_release(priv_key);
	//gcry_sexp_dump(signature);
	gcry_md_final(hd);
	//printf("Hash: %s \n", gcry_md_read(hd, GCRY_MD_SHA256));
	rc = gcry_pk_hash_verify(signature, template, pub_key, hd, NULL);
        if (rc) {
            printf("gcrypt error verifying data: %i %s\n", rc-GPG_ERR_INTERNAL, gcry_strerror(rc));
        }
	gcry_sexp_release(signature);
	gcry_sexp_release(pub_key);
	gcry_md_close(hd);
}
#endif

#if WOLFCRYPT
void ecdsaWolfcryptTest(void){
	int ret, verified = 0;
	unsigned int sigSz;
	unsigned int msgSize = sizeof(ecdsaTestMessage)/sizeof(ecdsaTestMessage[0]);
	/*ret = wolfSSL_Init();
	if (ret != SSL_SUCCESS) {
	    puts("failed to initialize wolfSSL");
	}*/
	
	byte sig[512];
	//byte digest[256];
	sigSz = sizeof(sig);


	// RNG
	WC_RNG rng;
	wc_InitRng(&rng);

	// Key Gen
	ed25519_key key, pubKey;
	byte pub[32];
	word32 pubSz = sizeof(pub);
	wc_ed25519_init(&key);
	wc_ed25519_init(&pubKey);
	ret = wc_ed25519_make_key(&rng, 32, &key);
	if (ret != 0){
	    printf("wolfcrypt error %i while generating private key\n", ret);
	}
	ret = wc_ed25519_make_public(&key, pub, pubSz);
	if (ret != 0) {
	    printf("wolfcrypt error %i while generating publickey\n", ret);
	}
	ret = wc_ed25519_import_public(pub, pubSz, &pubKey);
	if (ret != 0) {
	    printf("wolfcrypt error %i while importing publickey\n", ret);
	}
	
	// Sign
	ret = wc_ed25519_sign_msg((byte*)ecdsaTestMessage, msgSize, sig, &sigSz, &key);
	if (ret != 0){
	    printf("wolfcrypt error %i while generating signature\n", ret);
	}
	
	// Verify
	ret = wc_ed25519_verify_msg(sig, sigSz, (byte*)ecdsaTestMessage, msgSize, &verified, &pubKey);
	if (ret < 0) {
	    printf("wolfcrypt error %i while verifying signature\n", ret);
	} else if (verified == 0){
	    puts("Signature is invalid");
	}
	wc_ed25519_free(&key);
	wc_ed25519_free(&pubKey);
}
#endif

int main(int argc, char const *argv[])
{
	(void)argc;
	(void)argv;
	xtimer_ticks32_t tick, tock, diff;
	float seconds;
        gnrc_netreg_entry_t dump = GNRC_NETREG_ENTRY_INIT_PID(GNRC_NETREG_DEMUX_CTX_ALL, gnrc_pktdump_pid);
        gnrc_netreg_register(GNRC_NETTYPE_UNDEF, &dump);
	xtimer_init();

        (void) puts("Welcome to ED25519!");

        //char line_buf[SHELL_DEFAULT_BUFSIZE];
        // shell_run(NULL, line_buf, SHELL_DEFAULT_BUFSIZE);


	srand(time(NULL));
	tick = xtimer_now();
	for(int i = 0; i < 5; i++){
	    #if SODIUM
	    ecdsaSodiumTest();
	    #endif	
	    #if GCRYPT
	    ecdsaGcryptTest();
	    #endif	
	    #if WOLFCRYPT
	    ecdsaWolfcryptTest();
	    #endif	
	}
	tock = xtimer_now();
	diff = xtimer_diff(tock, tick);	
	seconds= xtimer_usec_from_ticks(diff) / 1000000;
	printf("It took %i ticks to complete or %f seconds\n", diff, seconds);
	printf("%s\n", "All Tests successful.");
	return 0;
}

