#define CHECK_FOR_BIG_NUMBERS 1

#include "tttp_internal.h"

#include <string.h>
#include <stdio.h>
#include <assert.h>

const uint8_t SRP_N[SRP_N_BYTES] = {
  0xff, 0x12, 0xd2, 0xf1, 0xd5, 0xa0, 0xa1, 0x1a,
  0x5f, 0xe3, 0x06, 0xd5, 0x14, 0xcc, 0x80, 0xe0,
  0xf4, 0xbf, 0x31, 0xd5, 0xea, 0x39, 0xcf, 0xd1,
  0x9c, 0x74, 0xa7, 0xa4, 0x4b, 0x5f, 0x97, 0x4e,
  0x64, 0x96, 0x32, 0x16, 0x08, 0x61, 0x84, 0xe3,
  0x07, 0x0b, 0x55, 0x41, 0x46, 0x61, 0xc5, 0x4a,
  0xc8, 0x25, 0xf3, 0xf4, 0xed, 0x10, 0x93, 0x88,
  0xad, 0x3a, 0x2f, 0x5e, 0x2d, 0xd5, 0x6a, 0x96,
  0x0c, 0x8c, 0xa0, 0xc4, 0x22, 0xd6, 0xf0, 0x20,
  0x41, 0xe8, 0x55, 0x5c, 0xc0, 0x2b, 0x53, 0x9a,
  0x19, 0xb3, 0x96, 0xa2, 0xad, 0xfc, 0xdc, 0x4a,
  0x9c, 0x28, 0x18, 0x78, 0x47, 0x49, 0x86, 0x4a,
  0x39, 0x3d, 0x6f, 0xb4, 0x57, 0xe7, 0xc4, 0x4d,
  0x66, 0x5d, 0x4a, 0x42, 0x09, 0xdb, 0x57, 0xcf,
  0xb8, 0x60, 0xb6, 0x28, 0x2a, 0x0c, 0xe4, 0xfe,
  0xe0, 0x9d, 0xe0, 0x48, 0x47, 0xdb, 0xff, 0x93,
  0x8f, 0x16, 0xab, 0x50, 0x7f, 0x92, 0x08, 0x72,
  0xbd, 0xbb, 0x9b, 0x3d, 0xde, 0x95, 0x16, 0x84,
  0x15, 0xcc, 0x38, 0xb4, 0xe3, 0xaa, 0x86, 0xe9,
  0x7d, 0xaf, 0xc2, 0x9a, 0x6d, 0x4a, 0x08, 0xeb,
  0xf0, 0x1c, 0xe2, 0xd5, 0x1a, 0xa1, 0x0a, 0x21,
  0xf9, 0x03, 0x46, 0x0f, 0x93, 0xa3, 0x3b, 0x36,
  0x58, 0xd8, 0xf1, 0x6c, 0xbc, 0x5a, 0x94, 0x2e,
  0x6c, 0x31, 0xd6, 0xb9, 0xe6, 0xfa, 0xa1, 0x24,
  0x2c, 0x02, 0x28, 0xb8, 0x7c, 0x44, 0xa4, 0x4f,
  0xbf, 0xce, 0x75, 0x0c, 0xfa, 0xb2, 0x04, 0x34,
  0x6e, 0x48, 0x1d, 0xd1, 0xa0, 0x3c, 0x1f, 0x70,
  0xb1, 0xc8, 0x2d, 0xd0, 0x18, 0x98, 0x64, 0x76,
  0x60, 0xec, 0x32, 0xac, 0x83, 0xc2, 0x9c, 0x95,
  0xcb, 0x5c, 0xbc, 0x93, 0x31, 0x60, 0xa3, 0x69,
  0x35, 0x89, 0xae, 0xaa, 0x29, 0xdb, 0x0d, 0x27,
  0x85, 0x1e, 0x96, 0xd8, 0xa6, 0x1b, 0x0a, 0x59,
  0x53, 0xb0, 0xfc, 0x10, 0x99, 0x98, 0x7d, 0x5f,
  0x33, 0xd2, 0xba, 0x14, 0x3d, 0x6f, 0x1a, 0x1d,
  0x8b, 0xc3, 0x6f, 0x6f, 0x36, 0x50, 0x8f, 0xd0,
  0x45, 0x31, 0xf9, 0x29, 0x72, 0x6d, 0x59, 0xb8,
  0xe1, 0x59, 0x9f, 0x91, 0x1b, 0x4b, 0x06, 0x98,
  0xc9, 0x1d, 0xa6, 0x91, 0xd0, 0x96, 0x09, 0xc3,
  0x2b, 0x16, 0xeb, 0x3d, 0x7d, 0x0a, 0x98, 0x3e,
  0xd7, 0x71, 0x09, 0xe7, 0x82, 0x06, 0x99, 0x1b,
  0x34, 0xe5, 0x72, 0x37, 0x40, 0x9d, 0x1b, 0x37,
  0x82, 0x3c, 0xa0, 0xcc, 0x91, 0xeb, 0x36, 0xc7,
  0x88, 0xf2, 0x25, 0x27, 0x82, 0x3c, 0xe3, 0x4a,
  0x43, 0x47, 0xe1, 0x89, 0xe7, 0x22, 0x42, 0xb0,
  0x8f, 0x32, 0x73, 0x7b, 0x59, 0x2e, 0x0b, 0x19,
  0x51, 0x58, 0xd7, 0x46, 0x26, 0xc5, 0x6b, 0x8d,
  0x3a, 0xaa, 0x5e, 0xcd, 0xc0, 0x9c, 0x6f, 0xf4,
  0xc7, 0xaa, 0xcd, 0x9e, 0xd3, 0xb8, 0x60, 0x23,
};
const int SRP_g = 5;
const uint8_t SRP_k[SRP_k_BYTES] = {
  0x99, 0x34, 0x06, 0xe3, 0x1c, 0x1e, 0x6f, 0xb6,
  0x6a, 0xc3, 0x68, 0x49, 0x48, 0x41, 0xa6, 0x7c,
  0x65, 0xcd, 0x48, 0xfd, 0x86, 0x76, 0x7e, 0x56,
  0x9e, 0x91, 0x8b, 0xa7, 0xb9, 0x00, 0xeb, 0xde,
};
const uint8_t SRP_param_hash[SHA256_HASHBYTES] = {
  0x44, 0xd3, 0x45, 0x73, 0x35, 0x3b, 0x7a, 0x26,
  0x02, 0xa9, 0x47, 0x69, 0x99, 0x73, 0x85, 0xc1,
  0xaa, 0x84, 0x40, 0x0c, 0xf5, 0x9a, 0x8d, 0x3b,
  0x94, 0x66, 0x61, 0x0f, 0x2d, 0x3a, 0xd1, 0x71,
};
const uint8_t INITIAL_C2S_NONCE[TWOFISH_BLOCKBYTES] = {
  0x24, 0x3f, 0x6a, 0x88, 0x85, 0xa3, 0x08, 0xd3,
  0x13, 0x19, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x44, 
};
const uint8_t INITIAL_S2C_NONCE[TWOFISH_BLOCKBYTES] = {
  0xdb, 0xc0, 0x95, 0x77, 0x7a, 0x5c, 0xf7, 0x2c,
  0xec, 0xe6, 0x75, 0xd1, 0xfc, 0x8f, 0x8c, 0xbb,
};

volatile int tttp_init_called = 0;

static void* secure_alloc(size_t amt) {
  void* ret = malloc(amt);
  if(ret == NULL)
    tttp_call_active_fatal("memory allocation failed inside GMP");
  return ret;
}

static void secure_free(void* p, size_t oldsize) {
  lsx_explicit_bzero(p, oldsize);
  free(p);
}

static void* secure_realloc(void* p, size_t oldsize, size_t newsize) {
  void* ret = malloc(newsize);
  if(ret == NULL && oldsize >= newsize) {
    /* we can survive */
    memset((uint8_t*)p+newsize, 0, oldsize-newsize);
    return p;
  }
  else if(ret == NULL)
    tttp_call_active_fatal("memory allocation failed inside GMP");
  memcpy(ret, p, oldsize > newsize ? newsize : oldsize);
  secure_free(p, oldsize);
  return ret;
}

void tttp_init() {
  if(tttp_init_called) {
    fprintf(stderr, "tttp_init() called more than once\n");
    abort();
  }
  mp_set_memory_functions(secure_alloc, secure_realloc, secure_free);
  lsx_get_random(NULL, 0);
  tttp_init_called = 1;
}

void tttp_export_and_zero_fill_Nsize(uint8_t out[SRP_N_BYTES], mpz_t in) {
#if CHECK_FOR_BIG_NUMBERS
  size_t count = SRP_N_BYTES+1;
  uint8_t tmpout[SRP_N_BYTES+1];
  if(mpz_sgn(in) < 0) {
    fprintf(stderr, "NEGATIVE NUMBER! NEGATIVE NUMBER!\n");
    abort();
  }
  mpz_export(tmpout, &count, 1, 1, 1, 0, in);
  if(count > SRP_N_BYTES) {
    fprintf(stderr, "BIG NUMBER! BIG NUMBER! DIE! DIE! (%u)\n",
            (unsigned int)mpz_sizeinbase(in,2));
    abort();
  }
  else if(count < SRP_N_BYTES) {
    memcpy(out + (SRP_N_BYTES-count), tmpout, count);
    memset(out, 0, SRP_N_BYTES-count);
  }
  else memcpy(out, tmpout, SRP_N_BYTES);
#else
  size_t count = SRP_N_BYTES;
  mpz_export(out, &count, 1, 1, 1, 0, in);
  if(count < SRP_N_BYTES) {
    memmove(out + (SRP_N_BYTES-count), out, count);
    memset(out, 0, SRP_N_BYTES-count);
  }
#endif
}

void tttp_set_active_fatal(void(*fp)(void*,const char*), void* d) {
  tttp_thread_local_block* tlb = tttp_get_thread_local_block();
  if(tlb == NULL) fp(d, "tttp_get_thread_local_block returned NULL");
  tlb->fp = fp; tlb->d = d;
}

#if __GNUC__
static void default_fatal(void* ignored, const char* what)
  __attribute__((noreturn));
#endif
static void default_fatal(void* ignored, const char* what) {
  (void)ignored;
  fprintf(stderr, "Fatal error with no active fatal callback:\n%s\n", what);
  abort();
}

void tttp_call_active_fatal(const char* what) {
  tttp_thread_local_block* tlb = tttp_get_thread_local_block();
  if(tlb->fp) {
    tlb->fp(tlb->d, what);
    fprintf(stderr, "fatal handler returned! aborting!\n");
    abort();
  }
  else default_fatal(NULL, what);
}

void tttp_password_to_verifier(void(*fatal_callback)(void*,const char*),
                               void* callback_data,
                               const uint8_t* password,
                               size_t passwordlen,
                               uint8_t salt[SHA256_HASHBYTES],
                               uint8_t verifier[SRP_N_BYTES]) {
  if(!tttp_init_called) {
    fprintf(stderr, "tttp_password_to_verifier called before tttp_init\n");
    abort();
  }
  tttp_set_active_fatal(fatal_callback, callback_data);
  lsx_get_random(salt, SHA256_HASHBYTES);
  uint8_t x_bytes[SHA256_HASHBYTES];
  {
    lsx_sha256_context sha256;
    lsx_setup_sha256(&sha256);
    lsx_input_sha256(&sha256, salt, SHA256_HASHBYTES);
    if(passwordlen > 0) lsx_input_sha256(&sha256, password, passwordlen);
    lsx_finish_sha256(&sha256, x_bytes);
    lsx_destroy_sha256(&sha256);
  }
  mpz_t g, x, N, result;
  mpz_init_set_ui(g, SRP_g);
  mpz_init2(x, SHA256_HASHBYTES*8);
  mpz_init2(N, SRP_N_BITS);
  mpz_init2(result, SRP_N_BITS);
  // N := (SRP parameter N defined in specification)
  mpz_import(N, SRP_N_BYTES, 1, 1, 1, 0, SRP_N);
  // x := x
  mpz_import(x, SHA256_HASHBYTES, 1, 1, 1, 0, x_bytes);
  // result := g^x
  mpz_powm_sec(result, g, x, N);
  tttp_export_and_zero_fill_Nsize(verifier, result);
  mpz_clears(g, x, N, result, NULL);
}

int tttp_generate_public_key(void(*fatal_callback)(void*,const char*),
                             void* callback_data,
                             const uint8_t private[TTTP_PRIVATE_KEY_LENGTH],
                             uint8_t public[TTTP_PUBLIC_KEY_LENGTH]) {
  if(!tttp_init_called) {
    fprintf(stderr, "tttp_generate_public_key called before tttp_init\n");
    abort();
  }
  tttp_set_active_fatal(fatal_callback, callback_data);
  mpz_t g, z, N, result;
  mpz_init_set_ui(g, SRP_g);
  mpz_init2(z, SRP_N_BITS);
  mpz_init2(N, SRP_N_BITS);
  mpz_init2(result, SRP_N_BITS);
  // N := (SRP parameter N defined in specification)
  mpz_import(N, SRP_N_BYTES, 1, 1, 1, 0, SRP_N);
  // z := z
  mpz_import(z, SRP_N_BYTES, 1, 1, 1, 0, private);
  int ret;
  if(mpz_sgn(z) == 0 || mpz_cmp(z, N) >= 0) ret = 0;
  else {
    // result := g^z
    mpz_powm_sec(result, g, z, N);
    tttp_export_and_zero_fill_Nsize(public, result);
    ret = 1;
  }
  mpz_clears(g, z, N, result, NULL);
  return ret;
}

void tttp_get_key_fingerprint(const uint8_t key[TTTP_PUBLIC_KEY_LENGTH],
                              char buf[TTTP_FINGERPRINT_BUFFER_SIZE]) {
#if SHA256_HASHBYTES != 32
#error Uhh
#endif
  uint8_t hash[SHA256_HASHBYTES];
  lsx_sha256_expert_context sha256;
  lsx_setup_sha256_expert(&sha256);
  lsx_input_sha256_expert(&sha256, key,
                          TTTP_PUBLIC_KEY_LENGTH/SHA256_BLOCKBYTES);
  lsx_finish_sha256_expert(&sha256, NULL, 0, hash);
  lsx_destroy_sha256_expert(&sha256);
  for(unsigned int n = 0; n < 16; ++n) hash[n] ^= hash[16+n];
  snprintf(buf, TTTP_FINGERPRINT_BUFFER_SIZE,
           "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x"
           ":%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
           hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6],
           hash[7], hash[8], hash[9], hash[10], hash[11], hash[12], hash[13],
           hash[14], hash[15]);
  lsx_explicit_bzero(hash, sizeof(hash));
}

static const char* base64_digits =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
void tttp_key_to_base64(const uint8_t key[TTTP_KEY_LENGTH],
                        char buf[TTTP_KEY_BASE64_BUFFER_SIZE]) {
#if TTTP_KEY_LENGTH % 3 != 0
#error Will need to be rewritten
#endif
  char* outp = buf;
  const uint8_t* inp = key;
  for(unsigned int n = 0; n < TTTP_KEY_BASE64_MIN_SIZE/4; ++n) {
    *outp++ = base64_digits[inp[0]>>2];
    *outp++ = base64_digits[((inp[0]<<4)&48)|(inp[1]>>4)];
    *outp++ = base64_digits[((inp[1]<<2)&60)|(inp[2]>>6)];
    *outp++ = base64_digits[inp[2]&63];
    inp += 3;
    if(n % 16 == 15) *outp++ = '\n';
  }
  outp[-1] = 0;
  assert(outp == buf + TTTP_KEY_BASE64_BUFFER_SIZE);
}

static int base64_value(char c) {
  if(c >= 'A' && c <= 'Z') return c - 'A';
  else if(c >= 'a' && c <= 'z') return c - 'a' + 26;
  else if(c >= '0' && c <= '9') return c - '0' + 52;
  else if(c == '+') return 62;
  else if(c == '/') return 63;
  else return -1;
}

int tttp_key_from_base64(const char* str,
                         uint8_t key[TTTP_KEY_LENGTH]) {
#if TTTP_KEY_LENGTH % 3 != 0
#error Will need to be rewritten
#endif
  int32_t base64_buf = 0;
  int base64_had = 0;
  uint8_t* outp = key;
  while(*str && outp != key + TTTP_KEY_LENGTH) {
    int v = base64_value(*str++);
    if(v >= 0) {
      base64_buf = (base64_buf << 6) | v;
      ++base64_had;
      if(base64_had == 4) {
        *outp++ = (uint8_t)(base64_buf>>16);
        *outp++ = (uint8_t)(base64_buf>>8);
        *outp++ = (uint8_t)base64_buf;
        base64_buf = base64_had = 0;
      }
    }
  }
  if(outp == key + TTTP_KEY_LENGTH)
    return memcmp(key, SRP_N, SRP_N_BYTES) < 0;
  else
    return 0;
}

int tttp_key_is_null_public_key(const uint8_t key[TTTP_PUBLIC_KEY_LENGTH]) {
  for(unsigned int n = 0; n < TTTP_PUBLIC_KEY_LENGTH - 1; ++n)
    if(key[n]) return 0;
  return key[TTTP_PUBLIC_KEY_LENGTH-1] == 1;
}

int tttp_key_is_null_private_key(const uint8_t key[TTTP_PUBLIC_KEY_LENGTH]) {
  for(unsigned int n = 0; n < TTTP_PUBLIC_KEY_LENGTH; ++n)
    if(key[n]) return 0;
  return 1;
}
