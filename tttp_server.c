#include "tttp_server.h"
#include "tttp_internal.h"

#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <zlib.h>
#include <gmp.h>
#include <lsx.h>

#define RECEIVE_BUFFER_SIZE 1024
#define SRP self->tail->srp

enum tttp_server_state {
  SS_DEAD,
  SS_INITIALIZED, SS_QUERIED, SS_FLAGGED,
  SS_NEED_AUTH,
  SS_AUTH, SS_AUTH_NEED_CONFIRM,
  SS_NO_AUTH,
  SS_COMPLETE, SS_RESETTING
};

struct tttp_server {
  enum tttp_server_state server_state;
  void* cbdata;
  void(*fatal_callback)(void* data, const char* what);
  void(*foul_callback)(void* data, const char* what);
  /* remainder of struct will be clobbered on error */
  enum tttp_message_state message_state;
  int(*receive_callback)(void* data, void* buf, size_t bufsz);
  int(*send_callback)(void* data, const void* buf, size_t bufsz);
  void(*flush_callback)(void* data);
  void(*ones_callback)(void* data);
  void(*queu_callback)(void* data, uint8_t queue_depth);
  void(*scrn_callback)(void* data,
                       uint16_t preferred_width, uint16_t preferred_height,
                       uint16_t maximum_width, uint16_t maximum_height);
  void(*mres_callback)(void* data, uint8_t w, uint8_t h);
  void(*key_callback)(void* data, int pressed, uint16_t scancode);
  void(*mous_callback)(void* data, int16_t x, int16_t y);
  void(*mbtn_callback)(void* data, int pressed, uint16_t button);
  void(*scrl_callback)(void* data, int8_t x, int8_t y);
  void(*text_callback)(void* data, const uint8_t* text, size_t len);
  void(*pbeg_callback)(void* data);
  void(*pend_callback)(void* data);
  void(*unknown_callback)(void* data, uint32_t msgid, const uint8_t* msgdata,
                          uint32_t datalen);
  uint8_t pasting_allowed:1, paste_in_progress:1;
  uint32_t negotiated_flags;
  uint32_t message_type, message_len;
  uint16_t last_width, last_height;
  uint8_t* framebuffer, *cbuffer;
  size_t data_buf_size, data_buf_pos;
  uint8_t* data_buf;
  uint8_t* message_data_ptr; // use message_data_ptr when actually reading data
  size_t recv_size, recv_buf_pos;
  z_stream zlib;
  uint8_t recv_buf[RECEIVE_BUFFER_SIZE];
  union tail {
    struct srp_tail {
      lsx_twofish_context twofish;
      mpz_t N, g, k; // constants
      mpz_t v; // the password verifier
      mpz_t h; // our public key
      mpz_t z; // our private key
      mpz_t b; // our secret quantity
      mpz_t A, B; // the shared quantities
      mpz_t u; // H(A, B)
      mpz_t S; // the shared secret
      mpz_t temp;
      // s is also used to store H(A, M, K)
      uint8_t K[SHA256_HASHBYTES], s[SHA256_HASHBYTES], M[SHA256_HASHBYTES],
        H_I[SHA256_HASHBYTES];
      lsx_sha256_expert_context sha256;
    } srp;
    struct crypto_tail {
      lsx_twofish_context twofish;
      uint8_t c2s_buf[TWOFISH_BLOCKBYTES], s2c_buf[TWOFISH_BLOCKBYTES];
      uint8_t c2s_pos, s2c_pos;
    } crypto;
  } *tail;
};
#define get_error_buffer_pointer(self) ((char*)&self->message_state)
#define ERROR_BUFFER_SIZE (sizeof(tttp_server) - offsetof(tttp_server, message_state))

static void kill_state(tttp_server* self) {
  if(self->server_state != SS_DEAD) {
    if(self->data_buf)
      free(self->data_buf);
    if(self->framebuffer)
      free(self->framebuffer);
    if(self->cbuffer)
      free(self->cbuffer);
    if(self->zlib.opaque) {
      deflateEnd(&self->zlib);
      self->zlib.opaque = NULL;
    }
    if(self->tail) {
      if(self->server_state >= SS_COMPLETE) {
        lsx_destroy_twofish256(&self->tail->crypto.twofish);
        lsx_explicit_bzero(self->tail, sizeof(self->tail->crypto));
      }
      else {
        lsx_destroy_twofish256(&SRP.twofish);
        mpz_clears(SRP.N, SRP.g, SRP.k, SRP.v, SRP.b, SRP.A, SRP.B,
                   SRP.u, SRP.S, SRP.temp, SRP.z, SRP.h, NULL);
        lsx_destroy_sha256_expert(&SRP.sha256);
        lsx_explicit_bzero(self->tail, sizeof(SRP));
      }
      free(self->tail);
    }
  }
  self->server_state = SS_DEAD;
}

#if __GNUC__
static void fatal(tttp_server* self, const char* what, ...)
  __attribute__((noreturn,format(printf,2,3)));
#endif
static void fatal(tttp_server* self, const char* what, ...) {
  kill_state(self);
  va_list arg;
  va_start(arg, what);
  vsnprintf(get_error_buffer_pointer(self), ERROR_BUFFER_SIZE,
            what, arg);
  va_end(arg);
  if(self->fatal_callback)
    self->fatal_callback(self->cbdata, get_error_buffer_pointer(self));
  fputs("Fatal error in libtttp\n", stderr);
  fputs(what, stderr);
  fputc('\n', stderr);
  abort();
}

#if __GNUC__
static void foul(tttp_server* self, const char* what, ...)
  __attribute__((format(printf,2,3)));
#endif
static void foul(tttp_server* self, const char* what, ...) {
  if(self->server_state == SS_DEAD)
    fatal(self, "foul called on a dead server (libtttp bug)");
  kill_state(self);
  va_list arg;
  va_start(arg, what);
  vsnprintf(get_error_buffer_pointer(self), ERROR_BUFFER_SIZE,
            what, arg);
  va_end(arg);
  if(self->foul_callback)
    self->foul_callback(self->cbdata, get_error_buffer_pointer(self));
  else {
    fputs("Foul in libtttp\n", stderr);
    fputs(what, stderr);
    fputc('\n', stderr);
  }
}

#define FATAL_DEAD_STATE(self) fatal(self, "%s called on dead tttp_server", __FUNCTION__)
#define FATAL_WRONG_STATE(self) fatal(self, "%s called on tttp_server in inappropriate state", __FUNCTION__)
#define FATAL_MISSING_CALLBACK(self, what) fatal(self, "%s called with null %s callback", __FUNCTION__, what)

static uint8_t slow_hash_check(uint8_t a[SHA256_HASHBYTES],
                               uint8_t b[SHA256_HASHBYTES]) {
  uint8_t ret = 0;
  for(int n = 0; n < SHA256_HASHBYTES; ++n) { ret |= a[n]^b[n]; }
  return ret;
}

static void advance_keystream(tttp_server* self, uint8_t buf[16]) {
  lsx_encrypt_twofish(&self->tail->crypto.twofish, buf, buf);
}

static void decrypt(tttp_server* self, uint8_t* p, size_t rem) {
  uint8_t pos = self->tail->crypto.c2s_pos;
  while(rem > 0) {
    if(pos == 16) {
      advance_keystream(self, self->tail->crypto.c2s_buf);
      pos = 0;
    }
    do {
      uint8_t cipherbyte = *p;
      uint8_t keybyte = self->tail->crypto.c2s_buf[pos];
      uint8_t clearbyte = cipherbyte ^ keybyte;
      self->tail->crypto.c2s_buf[pos++] = cipherbyte;
      *p++ = clearbyte;
    } while(--rem > 0 && pos < 16);
  }
  self->tail->crypto.c2s_pos = pos;
}

static void encrypt(tttp_server* self, uint8_t* p, size_t rem) {
    uint8_t pos = self->tail->crypto.s2c_pos;
  while(rem > 0) {
    if(pos == 16) {
      advance_keystream(self, self->tail->crypto.s2c_buf);
      pos = 0;
    }
    do {
      uint8_t clearbyte = *p;
      uint8_t keybyte = self->tail->crypto.s2c_buf[pos];
      uint8_t cipherbyte = clearbyte ^ keybyte;
      self->tail->crypto.s2c_buf[pos++] = cipherbyte;
      *p++ = cipherbyte;
    } while(--rem > 0 && pos < 16);
  }
  self->tail->crypto.s2c_pos = pos;
}

static int send_data(tttp_server* self, uint8_t* send_buf, size_t len) {
  if(self->server_state < SS_COMPLETE
     || !(self->negotiated_flags & TTTP_FLAG_ENCRYPTION))
    return self->send_callback(self->cbdata, send_buf, len);
  encrypt(self, send_buf, len);
  return self->send_callback(self->cbdata, send_buf, len);
}

static int receive_data(tttp_server* self, uint8_t* recv_buf, size_t len) {
  if(self->server_state < SS_COMPLETE
     || !(self->negotiated_flags & TTTP_FLAG_ENCRYPTION))
    return self->receive_callback(self->cbdata, recv_buf, len);
  int red = self->receive_callback(self->cbdata, recv_buf, len);
  if(red <= 0) return red;
  decrypt(self, recv_buf, red);
  return red;
}

static void maybe_flush(tttp_server* self) {
  if(self->flush_callback) self->flush_callback(self->cbdata);
}

static int get_byte(tttp_server* self) {
  if(self->recv_buf_pos < self->recv_size)
    return self->recv_buf[self->recv_buf_pos++];
  else {
    int red = receive_data(self, self->recv_buf, sizeof(self->recv_buf));
    if(red == 0) return -1;
    else if(red < 0) return -2;
    self->recv_size = red;
    self->recv_buf_pos = 1;
    return self->recv_buf[0];
  }
}

static char safe_char(char c) {
  if(c < 0x20 || c > 0x7E) return '?'; else return c;
}

/*
  -1: error
  0: no message
  1: yes message
 */
static int get_message(tttp_server* self) {
  int c;
  switch(self->message_state) {
  case MS_TYPE_1:
    c = get_byte(self);
    if(c < 0) { self->message_state = MS_TYPE_1; goto err; }
    self->message_type = (uint32_t)c << 24;
  case MS_TYPE_2:
    c = get_byte(self);
    if(c < 0) { self->message_state = MS_TYPE_2; goto err; }
    self->message_type |= (uint32_t)c << 16;
  case MS_TYPE_3:
    c = get_byte(self);
    if(c < 0) { self->message_state = MS_TYPE_3; goto err; }
    self->message_type |= (uint32_t)c << 8;
  case MS_TYPE_4:
    c = get_byte(self);
    if(c < 0) { self->message_state = MS_TYPE_4; goto err; }
    self->message_type |= (uint32_t)c;
    if((self->message_type & 0x20200000) == 0) {
      switch(self->message_type & 0x7F7FFFFF) {
      case 'FLAG': case 'AUTH': case 'NAUT': case 'ONES': case 'QUER':
      case 'MRES':
        break;
      default:
        foul(self, "Unknown standard critical message received (%c%c%c%c)",
             safe_char((self->message_type >> 24) & 0x7F),
             safe_char((self->message_type >> 16) & 0x7F),
             safe_char((self->message_type >> 8) & 0x7F),
             safe_char((self->message_type >> 0) & 0x7F));
        return -1;
      }
    }
    if((self->message_type & 0x80000000) == 0) {
      // no data
      self->message_len = 0;
      break;
    }
  case MS_LEN_1:
    c = get_byte(self);
    if(c < 0) { self->message_state = MS_LEN_1; goto err; }
    else if(c == 0) {
      foul(self, "Explicit zero data length received");
      return -1;
    }
    else if(c == 0x80) {
      foul(self, "Data length with excessive digits received");
      return -1;
    }
    self->message_len = c & 0x7F;
    if(c < 0x80) goto data_in;
  case MS_LEN_2:
    c = get_byte(self);
    if(c < 0) { self->message_state = MS_LEN_2; goto err; }
    self->message_len = (self->message_len << 7) | (c & 0x7F);
    if(c < 0x80) goto data_in;
  case MS_LEN_3:
    c = get_byte(self);
    if(c < 0) { self->message_state = MS_LEN_3; goto err; }
    self->message_len = (self->message_len << 7) | (c & 0x7F);
    if(c < 0x80) goto data_in;
    kill_state(self);
    foul(self, "Excessively large message received");
    return -1;
  data_in:
    if(self->recv_size - self->recv_buf_pos >= self->message_len) {
      self->message_data_ptr = self->recv_buf + self->recv_buf_pos;
      self->recv_buf_pos += self->message_len;
      break;
    }
    if(self->data_buf_size < self->message_len) {
      free(self->data_buf);
      self->data_buf = NULL;
      void* new_buf = malloc(self->message_len);
      if(!new_buf) foul(self, "Memory allocation failed");
      self->data_buf = new_buf;
      self->data_buf_size = self->message_len;
    }
    self->message_data_ptr = self->data_buf;
    /* if we reach this point, we know that more data than is in recv_buf is
       required */
    {
      size_t rem_recv_bytes = self->recv_size - self->recv_buf_pos;
      memcpy(self->data_buf, self->recv_buf + self->recv_buf_pos,
             rem_recv_bytes);
      self->data_buf_pos = rem_recv_bytes;
      self->recv_size = 0;
      self->recv_buf_pos = 0;
    }
  case MS_DATA: {
    int red = receive_data(self,
                           self->data_buf + self->data_buf_pos,
                           self->message_len - self->data_buf_pos);
    if(red == -1) { self->message_state = MS_DATA; return -1; }
    else {
      self->data_buf_pos += red;
      if(self->data_buf_pos >= self->message_len) break;
      self->message_state = MS_DATA;
      return 0;
    }
  }
  }
  /* reached only if we got a complete message */
  self->message_type &= 0x7F7FFFFF;
  self->message_state = MS_TYPE_1;
  return 1;
 err:
  if(c == -2) return -1; else return 0;
}

tttp_server* tttp_server_init(void* data,
                              int(*receive)(void* data,
                                            void* buf, size_t bufsz),
                              int(*send)(void* data,
                                         const void* buf, size_t bufsz),
                              void(*flush)(void* data),
                              void(*fatal_cb)(void* data,
                                           const char* why),
                              void(*foul)(void* data,
                                          const char* why)) {
  tttp_server* ret = malloc(sizeof(tttp_server));
  if(ret == NULL) return NULL;
  ret->server_state = SS_INITIALIZED;
  ret->cbdata = data;
  ret->fatal_callback = fatal_cb;
  ret->zlib.opaque = NULL;
  ret->message_state = MS_TYPE_1;
  ret->receive_callback = receive;
  ret->send_callback = send;
  ret->flush_callback = flush;
  ret->foul_callback = foul;
  ret->ones_callback = NULL;
  ret->queu_callback = NULL;
  ret->scrn_callback = NULL;
  ret->mres_callback = NULL;
  ret->key_callback = NULL;
  ret->mous_callback = NULL;
  ret->mbtn_callback = NULL;
  ret->scrl_callback = NULL;
  ret->text_callback = NULL;
  ret->pbeg_callback = NULL;
  ret->pend_callback = NULL;
  ret->unknown_callback = NULL;
  ret->pasting_allowed = 0;
  ret->paste_in_progress = 0;
  ret->negotiated_flags = 0;
  ret->last_width = 0;
  ret->last_height = 0;
  ret->framebuffer = NULL;
  ret->cbuffer = NULL;
  ret->data_buf = NULL;
  ret->data_buf_size = 0;
  // ret->data_buf_pos = 0;
  ret->recv_size = 0;
  ret->recv_buf_pos = 0;
  ret->tail = NULL;
  ret->zlib.zalloc = NULL;
  ret->zlib.zfree = NULL;
  ret->zlib.next_in = NULL;
  ret->zlib.avail_in = 0;
  if(!tttp_init_called) {
    fatal(ret, "tttp_server_init called before tttp_init!");
    return NULL;
  }
  if(!receive) FATAL_MISSING_CALLBACK(ret, "receive");
  if(!send) FATAL_MISSING_CALLBACK(ret, "send");
  if(deflateInit2(&ret->zlib, Z_BEST_COMPRESSION, Z_DEFLATED, 15, 9,
                  Z_FILTERED) != Z_OK) {
    foul(ret, "zlib error");
    tttp_server_fini(ret);
    return NULL;
  }
  ret->zlib.opaque = (void*)-1;
  return ret;
}

void tttp_server_fini(tttp_server* self) {
  kill_state(self);
  free(self);
}

void tttp_server_change_data_pointer(tttp_server* self, void* data) {
  if(self->server_state == SS_DEAD) FATAL_DEAD_STATE(self);
  self->cbdata = data;
}

tttp_handshake_result tttp_server_pump_beginning(tttp_server* self,
                                               uint32_t(*flagfilter)(uint32_t),
                            const uint8_t private_key[TTTP_PRIVATE_KEY_LENGTH],
                            const uint8_t public_key[TTTP_PUBLIC_KEY_LENGTH],
                                                 const uint8_t* servername,
                                                 size_t servernamelen,
                                                 uint8_t** username,
                                                 size_t* usernamelen) {
  if(self->server_state == SS_DEAD) FATAL_DEAD_STATE(self);
  else if(self->server_state != SS_INITIALIZED
          && self->server_state != SS_QUERIED
          && self->server_state != SS_FLAGGED) FATAL_WRONG_STATE(self);
  if(!flagfilter) FATAL_MISSING_CALLBACK(self, "flagfilter");
  while(1) {
    switch(get_message(self)) {
    case -1: return TTTP_HANDSHAKE_ERROR;
    case 0: return TTTP_HANDSHAKE_CONTINUE;
    case 1:
      switch(self->message_type) {
      case 'QUER':
        if(self->server_state != SS_INITIALIZED) {
          foul(self, "Received an inappropriate QUER message.");
          return TTTP_HANDSHAKE_ERROR;
        }
        self->server_state = SS_QUERIED;
        if(servername == NULL) {
          uint8_t buf[4] = {'Q','U','E','R'};
          send_data(self, buf, sizeof(buf));
          maybe_flush(self);
        }
        else {
          if(servernamelen > 255)
            fatal(self, "%s: server name too long", __FUNCTION__);
          uint8_t servernamelenbyte = servernamelen;
          uint32_t total_len = servernamelen + TTTP_PUBLIC_KEY_LENGTH + 1;
          uint8_t buf[6] = {
            'Q'|0x80, 'U', 'E', 'R', (total_len>>7)|0x80, total_len&0x7f
          };
          send_data(self, buf, sizeof(buf));
          // we know that at this point send_data will not clobber the buffer,
          // so we can do this
          send_data(self, (uint8_t*)public_key, TTTP_PUBLIC_KEY_LENGTH);
          send_data(self, &servernamelenbyte, 1);
          if(servernamelen > 0)
            send_data(self, (uint8_t*)servername, servernamelen);
          maybe_flush(self);
        }
        break;
      case 'FLAG':
        if(self->message_len < 4) {
          foul(self, "FLAG message too short");
          return TTTP_HANDSHAKE_ERROR;
        }
        uint32_t requested_flags = ((uint32_t)self->message_data_ptr[0] << 24)|
          ((uint32_t)self->message_data_ptr[1] << 16) |
          ((uint32_t)self->message_data_ptr[2] << 8) |
          ((uint32_t)self->message_data_ptr[3]);
        uint32_t filtered_flags = flagfilter(requested_flags);
        uint8_t buf[9] = {'F'|0x80,'L','A','G',4,
                          filtered_flags>>24, filtered_flags>>16,
                          filtered_flags>>8, filtered_flags};
        send_data(self, buf, sizeof(buf));
        maybe_flush(self);
        self->negotiated_flags = filtered_flags;
        self->server_state = SS_FLAGGED;
        break;
      case 'NAUT':
        if(self->server_state != SS_FLAGGED) {
          foul(self, "NAUT received before FLAG");
          return TTTP_HANDSHAKE_ERROR;
        }
        *username = NULL;
        *usernamelen = 0;
        self->server_state = SS_NO_AUTH;
        return TTTP_HANDSHAKE_ADVANCE;
      case 'AUTH':
        if(self->server_state != SS_FLAGGED) {
          foul(self, "AUTH received before FLAG");
          return TTTP_HANDSHAKE_ERROR;
        }
        if(self->message_len < SRP_N_BYTES+1
           || self->message_len < ((unsigned)SRP_N_BYTES+1U)
           + self->message_data_ptr[SRP_N_BYTES]) {
          foul(self, "AUTH message too short");
          return TTTP_HANDSHAKE_ERROR;
        }
        if(memchr(self->message_data_ptr + SRP_N_BYTES + 1, 0,
                  self->message_data_ptr[SRP_N_BYTES])) {
          foul(self, "Username contained NULs");
          return TTTP_HANDSHAKE_ERROR;
        }
        self->tail = malloc(sizeof(struct srp_tail));
        if(!self->tail) {
          foul(self, "Memory allocation failed");
          return TTTP_HANDSHAKE_ERROR;
        }
        tttp_set_active_fatal(self->fatal_callback, self->cbdata);
        mpz_init2(SRP.N, SRP_N_BITS);
        mpz_init_set_ui(SRP.g, SRP_g);
        mpz_init2(SRP.k, SRP_N_BITS);
        mpz_init2(SRP.v, SRP_N_BITS);
        mpz_init2(SRP.z, SRP_N_BITS);
        mpz_init2(SRP.h, SRP_N_BITS);
        mpz_init2(SRP.b, SRP_N_BITS);
        mpz_init2(SRP.A, SRP_N_BITS);
        mpz_init2(SRP.B, SRP_N_BITS);
        mpz_init2(SRP.u, SHA256_HASHBYTES*8);
        mpz_init2(SRP.S, SRP_N_BITS);
        mpz_init2(SRP.temp, SRP_N_BITS*2+1);
        // N := (SRP parameter N defined in specification)
        mpz_import(SRP.N, SRP_N_BYTES, 1, 1, 1, 0, SRP_N);
        // k := (SRP parameter k defined in specification)
        mpz_import(SRP.k, SRP_k_BYTES, 1, 1, 1, 0, SRP_k);
        // A := A from packet
        mpz_import(SRP.A, SRP_N_BYTES, 1, 1, 1, 0, self->message_data_ptr);
        if(mpz_cmp_si(SRP.A, 0) == 0 ||
           mpz_cmp(SRP.A, SRP.N) >= 0) {
          foul(self, "Client sent blatantly incorrect crypto parameters. The client is probably trying something!");
          return TTTP_HANDSHAKE_ERROR;
        }
        // z := private key
        mpz_import(SRP.z, SRP_N_BYTES, 1, 1, 1, 0, private_key);
        if(mpz_cmp(SRP.z, SRP.N) >= 0)
          fatal(self, "%s: caller gave us an invalid private key!",
                __FUNCTION__);
        // h := public key
        mpz_import(SRP.h, SRP_N_BYTES, 1, 1, 1, 0, public_key);
        if(mpz_cmp(SRP.h, SRP.N) >= 0)
          fatal(self, "%s: caller gave us an invalid public key!",
                __FUNCTION__);
        uint8_t* up = *username = self->message_data_ptr + SRP_N_BYTES + 1;
        size_t rem = *usernamelen = self->message_data_ptr[SRP_N_BYTES];
        lsx_setup_sha256_expert(&SRP.sha256);
        if(rem >= SHA256_BLOCKBYTES) {
          lsx_input_sha256_expert(&SRP.sha256,
                                  up, rem / SHA256_BLOCKBYTES);
          up += rem / SHA256_BLOCKBYTES * SHA256_BLOCKBYTES;
        }
        lsx_finish_sha256_expert(&SRP.sha256,
                                 up, rem, SRP.H_I);
        lsx_destroy_sha256_expert(&SRP.sha256);
        self->server_state = SS_NEED_AUTH;
        return TTTP_HANDSHAKE_ADVANCE;
      default:
        if(self->unknown_callback) {
          self->unknown_callback(self->cbdata, self->message_type,
                                 self->message_data_ptr, self->message_len);
          /* they must make an error if we don't */
        }
        else if(self->message_type & 0x00200000) {
          foul(self, "Received an unknown critical message during flag negotiation");
          return TTTP_HANDSHAKE_ERROR;
        }
        break;
      }
    }
  }
}

uint32_t tttp_server_get_flags(tttp_server* self) {
  if(self->server_state == SS_DEAD) FATAL_DEAD_STATE(self);
  else if(self->server_state == SS_INITIALIZED) FATAL_WRONG_STATE(self);
  return self->negotiated_flags;
}

void tttp_server_accept_no_auth(tttp_server* self) {
  if(self->server_state == SS_DEAD) FATAL_DEAD_STATE(self);
  else if(self->server_state != SS_NO_AUTH) FATAL_WRONG_STATE(self);
  self->negotiated_flags &= ~(uint32_t)TTTP_FLAG_ENCRYPTION;
  uint8_t buf[4] = {'A','U','T','H'};
  send_data(self, buf, sizeof(buf));
  maybe_flush(self);
  self->server_state = SS_COMPLETE;
}

void tttp_server_reject_auth(tttp_server* self) {
  if(self->server_state == SS_DEAD) FATAL_DEAD_STATE(self);
  else if(self->server_state != SS_AUTH_NEED_CONFIRM
          && self->server_state != SS_NO_AUTH) FATAL_WRONG_STATE(self);
  uint8_t buf[4] = {'N','A','U','T'};
  send_data(self, buf, sizeof(buf));
  maybe_flush(self);
  kill_state(self);
}

void tttp_server_begin_auth(tttp_server* self,
                            const uint8_t salt[SHA256_HASHBYTES],
                            const uint8_t verifier[SRP_N_BYTES]) {
  if(self->server_state == SS_DEAD) FATAL_DEAD_STATE(self);
  else if(self->server_state != SS_NEED_AUTH) FATAL_WRONG_STATE(self);
  tttp_set_active_fatal(self->fatal_callback, self->cbdata);
  // v := verifier
  mpz_import(SRP.v, SRP_N_BYTES, 1, 1, 1, 0, verifier);
  if(mpz_cmp(SRP.v, SRP.N) >= 0)
    fatal(self, "%s: invalid verifier given", __FUNCTION__);
  // s := salt
  memcpy(SRP.s, salt, SHA256_HASHBYTES);
  uint8_t bytes[SRP_N_BYTES+SHA256_HASHBYTES*2];
  do {
    // b := random bytes
    lsx_get_random(bytes, SRP_N_BYTES);
    mpz_import(SRP.b, SRP_N_BYTES, 1, 1, 1, 0, bytes);
    if(mpz_cmp(SRP.b, SRP.N) >= 0) continue;
    // B := g^b
    mpz_powm_sec(SRP.B, SRP.g, SRP.b, SRP.N);
    // temp := kv
    mpz_mul(SRP.temp, SRP.k, SRP.v);
    // temp := kv + g^b
    mpz_add(SRP.temp, SRP.temp, SRP.B);
    // (modularize)
    mpz_fdiv_r(SRP.B, SRP.temp, SRP.N);
    // B will never be >= N; if B is 0, we were really unlucky, get another
    // set of random bytes
    if(mpz_cmp_si(SRP.B, 0) == 0) continue;
    lsx_setup_sha256_expert(&SRP.sha256);
    tttp_export_and_zero_fill_Nsize(bytes, SRP.A);
    lsx_input_sha256_expert(&SRP.sha256,
                            bytes, SRP_N_BYTES / SHA256_BLOCKBYTES);
    tttp_export_and_zero_fill_Nsize(bytes+SHA256_HASHBYTES+6,
                                    SRP.B);
    lsx_input_sha256_expert(&SRP.sha256,
                            bytes+SHA256_HASHBYTES+6,
                            SRP_N_BYTES / SHA256_BLOCKBYTES);
    lsx_finish_sha256_expert(&SRP.sha256,
                             NULL, 0, bytes);
    mpz_import(SRP.u, SHA256_HASHBYTES, 1, 1, 1, 0, bytes);
  } while(mpz_cmp_si(SRP.u, 0) == 0);
  bytes[0] = 'A'|0x80; bytes[1] = 'U'; bytes[2] = 'T'; bytes[3] = 'H';
  bytes[4] = ((SRP_N_BYTES+SHA256_HASHBYTES)>>7)|0x80;
  bytes[5] = ((SRP_N_BYTES+SHA256_HASHBYTES)&0x7F);
  memcpy(bytes+6, salt, SHA256_HASHBYTES);
  // (bytes+SHA256_HASHBYTES+6 still contains B)
  send_data(self, bytes, SRP_N_BYTES+SHA256_HASHBYTES+6);
  maybe_flush(self);
  // crunch time!
  // S := v^u
  mpz_powm_sec(SRP.S, SRP.v, SRP.u, SRP.N);
  // temp := kh
  mpz_mul(SRP.temp, SRP.k, SRP.h);
  // temp := A-kh
  mpz_sub(SRP.temp, SRP.A, SRP.temp);
  // (modularize)
  mpz_fdiv_r(SRP.temp, SRP.temp, SRP.N);
  // temp := (A-kh)(v^u)
  mpz_mul(SRP.temp, SRP.temp, SRP.S);
  // (modularize into S)
  mpz_fdiv_r(SRP.S, SRP.temp, SRP.N);
  // temp := uz
  mpz_mul(SRP.temp, SRP.u, SRP.z);
  // temp := b + uz
  mpz_add(SRP.temp, SRP.b, SRP.temp);
  // S := ((A-kh)(v^u))^(b+uz)
  mpz_powm_sec(SRP.S, SRP.S, SRP.temp, SRP.N);
  // K := H(S)
  tttp_export_and_zero_fill_Nsize(bytes, SRP.S);
  lsx_setup_sha256_expert(&SRP.sha256);
  lsx_input_sha256_expert(&SRP.sha256,
                          bytes, SRP_N_BYTES / SHA256_BLOCKBYTES);
  lsx_finish_sha256_expert(&SRP.sha256,
                           NULL, 0, SRP.K);
  // setup twofish context
  lsx_setup_twofish256(&SRP.twofish, SRP.K);
  // now make M, holy cow
#if SHA256_HASHBYTES*2 != SHA256_BLOCKBYTES
#error this section will need to be rewritten
#endif
  lsx_setup_sha256_expert(&SRP.sha256);
  // block 1 = H(N) xor H(g), H(I)
  memcpy(bytes, SRP_param_hash, SHA256_HASHBYTES);
  memcpy(bytes+SHA256_HASHBYTES, SRP.H_I, SHA256_HASHBYTES);
  lsx_input_sha256_expert(&SRP.sha256, bytes, 1);
  // block 2..a-1 = s, A
  memcpy(bytes, SRP.s, SHA256_HASHBYTES);
  tttp_export_and_zero_fill_Nsize(bytes+SHA256_HASHBYTES, SRP.A);
  lsx_input_sha256_expert(&SRP.sha256,
                          bytes, SRP_N_BYTES / SHA256_BLOCKBYTES);
  // block a..b-1 = A (tail), B
  memcpy(bytes, bytes+SRP_N_BYTES, SHA256_HASHBYTES);
  tttp_export_and_zero_fill_Nsize(bytes+SHA256_HASHBYTES, SRP.B);
  lsx_input_sha256_expert(&SRP.sha256, bytes,
                          SRP_N_BYTES / SHA256_BLOCKBYTES);
  // block b = B (tail), K
  memcpy(bytes, bytes+SRP_N_BYTES, SHA256_HASHBYTES);
  memcpy(bytes+SHA256_HASHBYTES, SRP.K, SHA256_HASHBYTES);
  lsx_input_sha256_expert(&SRP.sha256, bytes, 1);
  lsx_finish_sha256_expert(&SRP.sha256,
                           NULL, 0, SRP.M);
  // and now we calculate H(A, M, K)
  tttp_export_and_zero_fill_Nsize(bytes, SRP.A);
  memcpy(bytes+SRP_N_BYTES, SRP.M, SHA256_HASHBYTES);
  memcpy(bytes+SRP_N_BYTES+SHA256_HASHBYTES, SRP.K,
         SHA256_HASHBYTES);
  lsx_setup_sha256_expert(&SRP.sha256);
  lsx_input_sha256_expert(&SRP.sha256, bytes,
                          (SRP_N_BYTES / SHA256_BLOCKBYTES) + 1);
  lsx_finish_sha256_expert(&SRP.sha256,
                           NULL, 0, SRP.s);
  lsx_destroy_sha256_expert(&SRP.sha256);
  self->server_state = SS_AUTH;
}

tttp_handshake_result tttp_server_pump_auth(tttp_server* self) {
  if(self->server_state == SS_DEAD) FATAL_DEAD_STATE(self);
  else if(self->server_state != SS_AUTH) FATAL_WRONG_STATE(self);
  while(1) {
    switch(get_message(self)) {
    case -1: return TTTP_HANDSHAKE_ERROR;
    case 0: return TTTP_HANDSHAKE_CONTINUE;
    case 1:
      switch(self->message_type) {
      case 'AUTH':
        if(self->message_len < SHA256_HASHBYTES) {
          foul(self, "AUTH message too short");
          return TTTP_HANDSHAKE_ERROR;
        }
        self->server_state = SS_AUTH_NEED_CONFIRM;
        if(slow_hash_check(self->message_data_ptr, SRP.M))
          return TTTP_HANDSHAKE_REJECTED;
        else
          return TTTP_HANDSHAKE_ADVANCE;
      default:
        if(self->unknown_callback) {
          self->unknown_callback(self->cbdata, self->message_type,
                                 self->message_data_ptr, self->message_len);
          /* they must make an error if we don't */
        }
        else if(self->message_type & 0x00200000) {
          foul(self, "Received an unknown critical message during flag negotiation");
          return TTTP_HANDSHAKE_ERROR;
        }
        break;
      }
    }
  }
}

void tttp_server_accept_auth(tttp_server* self) {
  if(self->server_state == SS_DEAD) FATAL_DEAD_STATE(self);
  else if(self->server_state != SS_AUTH_NEED_CONFIRM) FATAL_WRONG_STATE(self);
  uint8_t buf[SHA256_HASHBYTES+5];
  buf[0] = 'A'|0x80; buf[1] = 'U'; buf[2] = 'T'; buf[3] = 'H';
  buf[4] = SHA256_HASHBYTES;
  memcpy(buf+5, SRP.s, SHA256_HASHBYTES);
  send_data(self, buf, sizeof(buf));
  maybe_flush(self);
  if(self->negotiated_flags & TTTP_FLAG_ENCRYPTION) {
    uint8_t k_x = 0;
    for(unsigned int n = 0; n < sizeof(SRP.K); ++n)
      k_x ^= SRP.K[n];
    /* We can't use realloc as it might leave some old remnants of
       sensitive data around */
    union tail* new_tail = malloc(sizeof(struct crypto_tail));
    if(new_tail == NULL) {
      foul(self, "Memory allocation failed");
      return;
    }
    memcpy(&new_tail->crypto.twofish, &SRP.twofish,
           sizeof(lsx_twofish_context));
    mpz_clears(SRP.N, SRP.g, SRP.k, SRP.v, SRP.b, SRP.A,
               SRP.B, SRP.u, SRP.S, SRP.temp, SRP.z, SRP.h, NULL);
    lsx_explicit_bzero(&SRP, sizeof(SRP));
    free(self->tail);
    self->tail = new_tail;
    lsx_encrypt_twofish(&self->tail->crypto.twofish,
                        INITIAL_C2S_NONCE, self->tail->crypto.c2s_buf);
    lsx_encrypt_twofish(&self->tail->crypto.twofish,
                        INITIAL_S2C_NONCE, self->tail->crypto.s2c_buf);
    self->tail->crypto.c2s_pos = k_x&15;
    for(int n = 0; n < self->tail->crypto.c2s_pos; ++n)
      self->tail->crypto.c2s_buf[n] ^= 0xCC;
    self->tail->crypto.s2c_pos = k_x>>4;
    for(int n = 0; n < self->tail->crypto.s2c_pos; ++n)
      self->tail->crypto.s2c_buf[n] ^= 0xCC;
    if(self->recv_size > self->recv_buf_pos)
      decrypt(self, self->recv_buf + self->recv_buf_pos,
              self->recv_size - self->recv_buf_pos);
  }
  else {
    mpz_clears(SRP.N, SRP.g, SRP.k, SRP.v, SRP.b, SRP.A,
               SRP.B, SRP.u, SRP.S, SRP.temp, SRP.z, SRP.h, NULL);
    lsx_explicit_bzero(&SRP, sizeof(SRP));
    free(self->tail);
  }
  self->server_state = SS_COMPLETE;
}

void tttp_server_set_ones_callback(tttp_server* self,
                                   void(*ones)(void* data)) {
  if(self->server_state == SS_DEAD) FATAL_DEAD_STATE(self);
  self->ones_callback = ones;
}

void tttp_server_set_queue_depth_callback(tttp_server* self,
                                          void(*queue_depth)(void* data,
                                                             uint8_t depth)) {
  if(self->server_state == SS_DEAD) FATAL_DEAD_STATE(self);
  self->queu_callback = queue_depth;
}

void tttp_server_set_screen_params_callback
(tttp_server* self, void(*screen_params)(void* data,
                                         uint16_t preferred_width,
                                         uint16_t preferred_height,
                                         uint16_t maximum_width,
                                         uint16_t maximum_height)) {
  if(self->server_state == SS_DEAD) FATAL_DEAD_STATE(self);
  self->scrn_callback = screen_params;
}

void tttp_server_set_mouse_res_callback(tttp_server* self,
                                        void(*mres)(void* data,
                                                    uint8_t w, uint8_t h)) {
  if(self->server_state == SS_DEAD) FATAL_DEAD_STATE(self);
  self->mres_callback = mres;
}

void tttp_server_set_key_callback(tttp_server* self,
                                  void(*key)(void* data,
                                             int pressed,
                                             uint16_t scancode)) {
  if(self->server_state == SS_DEAD) FATAL_DEAD_STATE(self);
  self->key_callback = key;
}

void tttp_server_set_text_callback(tttp_server* self,
                                   void(*text)(void* data,
                                               const uint8_t* text,
                                               size_t len)) {
  if(self->server_state == SS_DEAD) FATAL_DEAD_STATE(self);
  self->text_callback = text;
}

void tttp_server_set_mouse_motion_callback(tttp_server* self,
                                           void(*mous)(void* data,
                                                       int16_t x, int16_t y)) {
  if(self->server_state == SS_DEAD) FATAL_DEAD_STATE(self);
  self->mous_callback = mous;
}

void tttp_server_set_mouse_button_callback(tttp_server* self,
                                           void(*mbtn)(void* data,
                                                       int pressed,
                                                       uint16_t button)) {
  if(self->server_state == SS_DEAD) FATAL_DEAD_STATE(self);
  self->mbtn_callback = mbtn;
}

void tttp_server_set_scroll_callback(tttp_server* self,
                                     void(*scrl)(void* data,
                                                 int8_t x, int8_t y)) {
  if(self->server_state == SS_DEAD) FATAL_DEAD_STATE(self);
  self->scrl_callback = scrl;
}

void tttp_server_set_paste_callbacks(tttp_server* self,
                                     void(*pbeg)(void* data),
                                     void(*pend)(void* data)) {
  if(self->server_state == SS_DEAD) FATAL_DEAD_STATE(self);
  self->pbeg_callback = pbeg;
  self->pend_callback = pend;
}

void tttp_server_set_unknown_callback(tttp_server* self,
                                      void(*unknown)(void* data,
                                                     uint32_t msgid,
                                                     const uint8_t* msgdata,
                                                     uint32_t datalen)) {
  if(self->server_state == SS_DEAD) FATAL_DEAD_STATE(self);
  self->unknown_callback = unknown;
}

void tttp_server_allow_paste(tttp_server* self) {
  if(self->server_state == SS_DEAD) FATAL_DEAD_STATE(self);
  else if(self->server_state != SS_COMPLETE) FATAL_WRONG_STATE(self);
  if(!self->pasting_allowed) {
    uint8_t buf[4] = {'P', 'o', 'n', 0};
    send_data(self, buf, sizeof(buf));
    self->pasting_allowed = 1;
  }
}

void tttp_server_forbid_paste(tttp_server* self) {
  if(self->server_state == SS_DEAD) FATAL_DEAD_STATE(self);
  else if(self->server_state != SS_COMPLETE) FATAL_WRONG_STATE(self);
  if(self->pasting_allowed) {
    uint8_t buf[4] = {'P', 'o', 'f', 'f'};
    send_data(self, buf, sizeof(buf));
    self->pasting_allowed = 0;
  }
}

void tttp_server_send_palette(tttp_server* self,
                              const uint8_t* colors, uint8_t colorcount) {
  if(self->server_state == SS_DEAD) FATAL_DEAD_STATE(self);
  else if(self->server_state != SS_COMPLETE) FATAL_WRONG_STATE(self);
  if(colorcount == 0) {
    uint8_t buf[4] = {'P','L','T','T'};
    send_data(self, buf, sizeof(buf));
  }
  else if(colorcount < 2 || colorcount > 16)
    fatal(self, "%s: colorcount must be 0, or 2--16 inclusive", __FUNCTION__);
  else {
    uint8_t buf[colorcount*3+5];
    buf[0] = 'P'|0x80; buf[1] = 'L'; buf[2] = 'T'; buf[3] = 'T';
    buf[4] = colorcount*3;
    memcpy(buf+5, colors, colorcount*3);
    send_data(self, buf, sizeof(buf));
  }
}

void tttp_server_send_frame(tttp_server* self,
                            uint16_t width, uint16_t height,
                            const uint8_t* framedata) {
  if(self->server_state == SS_DEAD) FATAL_DEAD_STATE(self);
  else if(self->server_state != SS_COMPLETE) FATAL_WRONG_STATE(self);
  if(width == 0 || height == 0)
    fatal(self, "%s: zero-byte framebuffer provided", __FUNCTION__);
  uint32_t total_bytes = ((uint32_t)width)*height*2;
  uint32_t needed_buffers = 2;
  if(self->negotiated_flags & TTTP_FLAG_UNICODE) total_bytes *= 2;
  uint32_t max_cbytes = compressBound(total_bytes)+4+3+4;
  if(width != self->last_width || height != self->last_height
     || !self->framebuffer) {
    if(self->framebuffer) free(self->framebuffer);
    if(self->cbuffer) { free(self->cbuffer); self->cbuffer = NULL; }
    self->framebuffer = calloc(total_bytes, needed_buffers);
    if(!self->framebuffer) {
      foul(self, "Memory allocation failed");
      return;
    }
    self->cbuffer = malloc(max_cbytes);
    if(!self->cbuffer) {
      foul(self, "Memory allocation failed");
      return;
    }
    self->last_width = width;
    self->last_height = height;
  }
  // delta-encode frame and store new data for next time
  const uint8_t* srcp = framedata;
  uint8_t* xop = self->framebuffer;
  uint8_t* pop = self->framebuffer + total_bytes;
  uint32_t rem = total_bytes;
  while(rem-- > 0) {
    uint8_t src = *srcp++;
    uint8_t pi = *pop;
    uint8_t x = src == pi ? 0 : src == 0 ? pi : src;
    *xop++ = x;
    *pop++ = src;
  }
  // Compress new frame
  self->zlib.avail_out = max_cbytes-4-3-4;
  self->zlib.next_out = self->cbuffer+4+3+4;
  self->zlib.avail_in = total_bytes;
  self->zlib.next_in = self->framebuffer;
  if(deflate(&self->zlib, Z_PARTIAL_FLUSH) != Z_OK) {
    foul(self, "zlib error");
    return;
  }
  else if(self->zlib.avail_in != 0) {
    foul(self, "bug in libtttp, max_cbytes was calculated wrong");
    return;
  }
  uint32_t len = self->zlib.next_out - self->cbuffer - 4 - 3;
  uint8_t* rp = self->cbuffer+4+3+4;
  *--rp = height;
  *--rp = height>>8;
  *--rp = width;
  *--rp = width>>8;
  if(len >= 2097152)
    fatal(self, "Frame way too big");
  else if(len >= 16384) {
    *--rp = len&0x7F;
    *--rp = (len>>7)|0x80;
    *--rp = (len>>14)|0x80;
  }
  else if(len >= 128) {
    *--rp = len&0x7F;
    *--rp = (len>>7)|0x80;
  }
  else *--rp = len;
  *--rp = 'M'; *--rp = 'A'; *--rp = 'R'; *--rp = 'F'|0x80;
  send_data(self, rp, self->zlib.next_out-rp);
  maybe_flush(self);
}

void tttp_server_destroy_previous_frame(tttp_server* self) {
  if(self->server_state == SS_DEAD) FATAL_DEAD_STATE(self);
  else if(self->server_state != SS_COMPLETE) FATAL_WRONG_STATE(self);
  self->last_height = self->last_width = 0;
  uint8_t buf[4] = {'D','F','R','M'};
  send_data(self, buf, sizeof(buf));
}

void tttp_server_reset(tttp_server* self) {
  if(self->server_state == SS_DEAD) FATAL_DEAD_STATE(self);
  else if(self->server_state != SS_COMPLETE) FATAL_WRONG_STATE(self);
  self->last_height = self->last_width = 0;
  uint8_t buf[4] = {'R','S','E','T'};
  send_data(self, buf, sizeof(buf));
  maybe_flush(self);
  deflateReset(&self->zlib);
}

tttp_handshake_result tttp_server_pump_reset(tttp_server* self) {
  if(self->server_state == SS_DEAD) FATAL_DEAD_STATE(self);
  else if(self->server_state != SS_RESETTING) FATAL_WRONG_STATE(self);
  while(1) {
    switch(get_message(self)) {
    case -1: return TTTP_HANDSHAKE_ERROR;
    case 0: return TTTP_HANDSHAKE_CONTINUE;
    case 1:
      switch(self->message_type) {
      case 'Rack':
        self->server_state = SS_COMPLETE;
        return TTTP_HANDSHAKE_ADVANCE;
      default: break;
      }
    }
  }
}

void tttp_server_kick(tttp_server* self, uint8_t* msg, size_t msglen) {
  if(self->server_state == SS_DEAD) FATAL_DEAD_STATE(self);
  else if(self->server_state != SS_COMPLETE) FATAL_WRONG_STATE(self);
  if(msglen >= 2097152) fatal(self, "Kick message too long");
  tttp_server_send_custom_message(self, 'KICK', msg, msglen);
  kill_state(self);
}

void tttp_server_request_key_repeat(tttp_server* self,
                                    uint32_t delay, uint32_t interval) {
  if(self->server_state == SS_DEAD) FATAL_DEAD_STATE(self);
  else if(self->server_state != SS_COMPLETE) FATAL_WRONG_STATE(self);
  uint8_t buf[13] = {'K'|0x80, 'y', 'r', 'p', 8,
                     delay>>24, delay>>16, delay>>8, delay,
                     interval>>24, interval>>16, interval>>8, interval};
  send_data(self, buf, 13);
}

void tttp_server_send_text(tttp_server* self, uint8_t* text, size_t textlen) {
  if(self->server_state == SS_DEAD) FATAL_DEAD_STATE(self);
  else if(self->server_state != SS_COMPLETE) FATAL_WRONG_STATE(self);
  if(textlen >= 2097152) fatal(self, "text message too long");
  else if(textlen <= 0) fatal(self, "cannot send a blank text message");
  tttp_server_send_custom_message(self, 'Text', text, textlen);
}

void tttp_server_send_cdpt(tttp_server* self, const uint32_t encoding[256]) {
  if(self->server_state == SS_DEAD) FATAL_DEAD_STATE(self);
  else if(self->server_state != SS_COMPLETE) FATAL_WRONG_STATE(self);
  uint8_t buf[6+256*4];
  buf[0] = 'C'|0x80; buf[1] = 'D'; buf[2] = 'P'; buf[3] = 'T';
  buf[4] = ((256*4)>>7)|0x80; buf[5] = (256*4)&0x7F;
  uint8_t* outp = buf + 6;
  const uint32_t* inp = encoding;
  for(int n = 0; n < 256; ++n) {
    uint32_t in = *inp++;
    *outp++ = in >> 24;
    *outp++ = in >> 16;
    *outp++ = in >> 8;
    *outp++ = in;
  }
  send_data(self, buf, sizeof(buf));
}

void tttp_server_send_custom_message(tttp_server* self, uint32_t msgid,
                                     void* msgdata, size_t msglen) {
  if(self->server_state == SS_DEAD) FATAL_DEAD_STATE(self);
  if(msglen > TTTP_MAX_DATA_SIZE)
    fatal(self,"%s: Too much data provided",__func__);
  uint8_t buf[7] = {msgid>>24, msgid>>16, msgid>>8, msgid, 0, 0, 0};
  int len;
  if(msglen == 0) {
    buf[0] &= 0x7F;
    len = 4;
  }
  else {
    buf[0] |= 0x80;
    if(msglen >= 16384) {
      buf[4] = (msglen >> 7) | 0x80;
      buf[5] = (msglen >> 14) | 0x80;
      buf[6] = (msglen >> 21) & 0x7F;
      len = 7;
    }
    else if(msglen >= 128) {
      buf[4] = (msglen >> 7) | 0x80;
      buf[5] = (msglen >> 14) & 0x7F;
      len = 6;
    }
    else {
      buf[4] = msglen;
      len = 5;
    }
  }
  send_data(self, buf, len);
  send_data(self, msgdata, msglen);
}

int tttp_server_pump(tttp_server* self) {
  if(self->server_state == SS_DEAD) FATAL_DEAD_STATE(self);
  else if(self->server_state != SS_COMPLETE) FATAL_WRONG_STATE(self);
  if(!self->ones_callback) FATAL_MISSING_CALLBACK(self, "ONES");
  while(self->server_state == SS_COMPLETE) {
    switch(get_message(self)) {
    case -1: return 0;
    case 0: return 1;
    case 1:
      if(self->paste_in_progress) {
        if(self->message_type != 'Pend' && self->message_type != 'Text'
           && self->message_type != 'Kp\0\n' && self->message_type != 'Kr\0\n'
           && self->message_type != 'Kp\0\t' && self->message_type !='Kr\0\t'){
          foul(self, "Received inappropriate message during paste");
          return 0;
        }
        else if(!self->pasting_allowed && self->message_type != 'Pend')
          break; // ignore
      }
      switch(self->message_type) {
      case 'Scrn':
        if(self->message_len < 8) {
          foul(self, "Scrn message too short");
          return 0;
        }
        if(self->scrn_callback) {
          uint16_t preferred_width = ((uint16_t)self->message_data_ptr[0]<<8)
            |(self->message_data_ptr[1]);
          uint16_t preferred_height = ((uint16_t)self->message_data_ptr[2]<<8)
            |(self->message_data_ptr[3]);
          uint16_t maximum_width = ((uint16_t)self->message_data_ptr[4]<<8)
            |(self->message_data_ptr[5]);
          uint16_t maximum_height = ((uint16_t)self->message_data_ptr[7]<<8)
            |(self->message_data_ptr[7]);
          self->scrn_callback(self->cbdata, preferred_width, preferred_height,
                              maximum_width, maximum_height);
        }
        break;
      case 'Queu':
        if(self->message_len < 1) {
          foul(self, "Queu message too short");
          return 0;
        }
        if(self->queu_callback)
          self->queu_callback(self->cbdata, self->message_data_ptr[0]);
        break;
      case 'MRES':
        if(!(self->negotiated_flags & TTTP_FLAG_PRECISE_MOUSE)) {
          foul(self, "MRES received outside precise mouse mode");
          return 0;
        }
        if(self->message_len < 2) {
          foul(self, "MRES message too short");
          return 0;
        }
        if(!self->mres_callback) FATAL_MISSING_CALLBACK(self,
                                                        "mouse resolution");
        self->mres_callback(self->cbdata, self->message_data_ptr[0],
                            self->message_data_ptr[1]);
        break;
      case 'ONES':
        self->ones_callback(self->cbdata);
        break;
      case 'Text':
        if(self->message_len <= 0) {
          foul(self, "empty text input received");
          return 0;
        }
        else if(memchr(self->message_data_ptr, 0, self->message_len)) {
          foul(self, "text input containing a NUL received");
          return 0;
        }
        if(self->text_callback)
          self->text_callback(self->cbdata,
                              self->message_data_ptr, self->message_len);
        break;
      case 'Mous':
        if(self->message_len < 4) {
          foul(self, "Mous message too short");
          return 0;
        }
        if(self->mous_callback) {
          /* yes, we mean uint16_t *and* int16_t where we have them */
          int16_t x = ((uint16_t)self->message_data_ptr[0]<<8)
            |(self->message_data_ptr[1]);
          int16_t y = ((uint16_t)self->message_data_ptr[2]<<8)
            |(self->message_data_ptr[3]);
          self->mous_callback(self->cbdata, x, y);
        }
        break;
      case 'Pbeg':
        if(self->pbeg_callback) self->pbeg_callback(self->cbdata);
        if(self->paste_in_progress)
          foul(self, "nested Pbeg");
        else
          self->paste_in_progress = 1;
        break;
      case 'Pend':
        if(self->pend_callback) self->pend_callback(self->cbdata);
        if(!self->paste_in_progress)
          foul(self, "spurious Pend");
        else
          self->paste_in_progress = 0;
        break;
      default:
        if((self->message_type & 0x7F7F0000) == 'Kp\0\0'
           || (self->message_type & 0x7F7F0000) == 'Kr\0\0') {
          if(self->key_callback)
            self->key_callback(self->cbdata,
                               (self->message_type & 0x7F7F0000) == 'Kp\0\0',
                               self->message_type & 0xFFFF);
          break;
        }
        else if((self->message_type & 0x7F7F0000) == 'Mp\0\0'
           || (self->message_type & 0x7F7F0000) == 'Mr\0\0') {
          if(self->mbtn_callback)
            self->mbtn_callback(self->cbdata,
                                (self->message_type & 0x7F7F0000) == 'Mp\0\0',
                                self->message_type & 0xFFFF);
          break;
        }
        else if((self->message_type & 0x7F7F0000) == 'Sc\0\0') {
          if(self->scrl_callback)
            self->scrl_callback(self->cbdata,
                                (uint8_t)(self->message_type >> 8),
                                (uint8_t)(self->message_type));
          break;
        }
        else if(self->unknown_callback) {
          self->unknown_callback(self->cbdata, self->message_type,
                                 self->message_data_ptr, self->message_len);
          /* they must do the critical chunk check themselves */
        }
        else if(self->message_type & 0x00200000) {
          foul(self, "Received an unknown critical message during handshake");
          return 0;
        }
        break;
      }
    }
  }
  return 0;
}
