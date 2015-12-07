#ifndef TTTP_INTERNAL_H
#define TTTP_INTERNAL_H

#include "tttp_common.h"
#include <lsx.h>
#include <gmp.h>

#define SRP_N_BYTES 384
#define SRP_N_BITS 3072
#define SRP_k_BYTES (SHA256_HASHBYTES)
#define SRP_k_BITS (SHA256_HASHBYTES*8)
#define SRP_g_BYTES 1
#define SRP_g_BITS 8

#if TTTP_SALT_LENGTH != SHA256_HASHBYTES
#error TTTP_SALT_LENGTH and SHA256_HASHBYTES do not match!
#endif

#if TTTP_VERIFIER_LENGTH != SRP_N_BYTES
#error TTTP_SALT_LENGTH and SHA256_HASHBYTES do not match!
#endif

#if SRP_N_BYTES < SHA256_HASHBYTES || SRP_N_BYTES%SHA256_HASHBYTES
#error No.
#endif

#define SRP_N tttp_SRP_N
#define SRP_g tttp_SRP_g
#define SRP_k tttp_SRP_k
#define SRP_param_hash tttp_SRP_param_hash
#define INITIAL_C2S_NONCE TTTP_INITIAL_C2S_NONCE
#define INITIAL_S2C_NONCE TTTP_INITIAL_S2C_NONCE
extern const uint8_t SRP_N[SRP_N_BYTES];
extern const int SRP_g;
extern const uint8_t SRP_k[SRP_k_BYTES];
extern const uint8_t SRP_param_hash[SHA256_HASHBYTES];
extern const uint8_t INITIAL_C2S_NONCE[TWOFISH_BLOCKBYTES];
extern const uint8_t INITIAL_S2C_NONCE[TWOFISH_BLOCKBYTES];

enum tttp_message_state {
  MS_TYPE_1,
  MS_TYPE_2,
  MS_TYPE_3,
  MS_TYPE_4,
  MS_LEN_1,
  MS_LEN_2,
  MS_LEN_3,
  MS_DATA
};

extern volatile int tttp_init_called;

void tttp_export_and_zero_fill_Nsize(uint8_t out[SRP_N_BYTES], mpz_t in);
void tttp_call_active_fatal(const char*)
#if __GNUC__
  __attribute__((noreturn))
#endif
  ;

#endif
