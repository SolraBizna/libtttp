#include "tttp_client.h"
#include "tttp_internal.h"

#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <zlib.h>
#include <lsx.h>

#define RECEIVE_BUFFER_SIZE 1024

#define SRP self->tail->srp

static const uint8_t default_palette[48] = {
  0x00, 0x00, 0x00,  0xaa, 0x00, 0x00,  0x00, 0xaa, 0x00,  0xaa, 0x55, 0x00,
  0x00, 0x00, 0xaa,  0xaa, 0x00, 0xaa,  0x00, 0xaa, 0xaa,  0xaa, 0xaa, 0xaa,
  0x55, 0x55, 0x55,  0xff, 0x55, 0x55,  0x55, 0xff, 0x55,  0xff, 0xff, 0x55,
  0x55, 0x55, 0xff,  0xff, 0x55, 0xff,  0x55, 0xff, 0xff,  0xff, 0xff, 0xff,
};

static const uint32_t default_codepoint_table[256] = {
  0x00000000, 0x0100263a, 0x0200263b, 0x03002665,
  0x04002666, 0x05002663, 0x06002660, 0x07002022,
  0x080025d8, 0x090025cb, 0x0a0025d9, 0x0b002642,
  0x0c002640, 0x0d00266a, 0x0e00266b, 0x0f00263c,
  0x100025ba, 0x110025c4, 0x12002195, 0x1300203c,
  0x140000b6, 0x150000a7, 0x160025ac, 0x170021a8,
  0x18002191, 0x19002193, 0x1a002192, 0x1b002190,
  0x1c00221f, 0x1d002194, 0x1e0025b2, 0x1f0025bc,
  0x20000020, 0x21000021, 0x22000022, 0x23000023,
  0x24000024, 0x25000025, 0x26000026, 0x27000027,
  0x28000028, 0x29000029, 0x2a00002a, 0x2b00002b,
  0x2c00002c, 0x2d00002d, 0x2e00002e, 0x2f00002f,
  0x30000030, 0x31000031, 0x32000032, 0x33000033,
  0x34000034, 0x35000035, 0x36000036, 0x37000037,
  0x38000038, 0x39000039, 0x3a00003a, 0x3b00003b,
  0x3c00003c, 0x3d00003d, 0x3e00003e, 0x3f00003f,
  0x40000040, 0x41000041, 0x42000042, 0x43000043,
  0x44000044, 0x45000045, 0x46000046, 0x47000047,
  0x48000048, 0x49000049, 0x4a00004a, 0x4b00004b,
  0x4c00004c, 0x4d00004d, 0x4e00004e, 0x4f00004f,
  0x50000050, 0x51000051, 0x52000052, 0x53000053,
  0x54000054, 0x55000055, 0x56000056, 0x57000057,
  0x58000058, 0x59000059, 0x5a00005a, 0x5b00005b,
  0x5c00005c, 0x5d00005d, 0x5e00005e, 0x5f00005f,
  0x60000060, 0x61000061, 0x62000062, 0x63000063,
  0x64000064, 0x65000065, 0x66000066, 0x67000067,
  0x68000068, 0x69000069, 0x6a00006a, 0x6b00006b,
  0x6c00006c, 0x6d00006d, 0x6e00006e, 0x6f00006f,
  0x70000070, 0x71000071, 0x72000072, 0x73000073,
  0x74000074, 0x75000075, 0x76000076, 0x77000077,
  0x78000078, 0x79000079, 0x7a00007a, 0x7b00007b,
  0x7c00007c, 0x7d00007d, 0x7e00007e, 0x7f00007f,
  0x800000c7, 0x810000fc, 0x820000e9, 0x830000e2,
  0x840000e4, 0x850000e0, 0x860000e5, 0x870000e7,
  0x880000ea, 0x890000eb, 0x8a0000e8, 0x8b0000ef,
  0x8c0000ee, 0x8d0000ec, 0x8e0000c4, 0x8f0000c5,
  0x900000c9, 0x910000e6, 0x920000c6, 0x930000f4,
  0x940000f6, 0x950000f2, 0x960000fb, 0x970000f9,
  0x980000ff, 0x990000d6, 0x9a0000dc, 0x9b0000a2,
  0x9c0000a3, 0x9d0000a5, 0x9e0020a7, 0x9f000192,
  0xa00000e1, 0xa10000ed, 0xa20000f3, 0xa30000fa,
  0xa40000f1, 0xa50000d1, 0xa60000aa, 0xa70000ba,
  0xa80000bf, 0xa9002310, 0xaa0000ac, 0xab0000bd,
  0xac0000bc, 0xad0000a1, 0xae0000ab, 0xaf0000bb,
  0xb0002591, 0xb1002592, 0xb2002593, 0xb3002502,
  0xb4002524, 0xb5002561, 0xb6002562, 0xb7002556,
  0xb8002555, 0xb9002563, 0xba002551, 0xbb002557,
  0xbc00255d, 0xbd00255c, 0xbe00255b, 0xbf002510,
  0xc0002514, 0xc1002534, 0xc200252c, 0xc300251c,
  0xc4002500, 0xc500253c, 0xc600255e, 0xc700255f,
  0xc800255a, 0xc9002554, 0xca002569, 0xcb002566,
  0xcc002560, 0xcd002550, 0xce00256c, 0xcf002567,
  0xd0002568, 0xd1002564, 0xd2002565, 0xd3002559,
  0xd4002558, 0xd5002552, 0xd6002553, 0xd700256b,
  0xd800256a, 0xd9002518, 0xda00250c, 0xdb002588,
  0xdc002584, 0xdd00258c, 0xde002590, 0xdf002580,
  0xe00003b1, 0xe10000df, 0xe2000393, 0xe30003c0,
  0xe40003a3, 0xe50003c3, 0xe60000b5, 0xe70003c4,
  0xe80003a6, 0xe9000398, 0xea0003a9, 0xeb0003b4,
  0xec00221e, 0xed0003c6, 0xee0003b5, 0xef002229,
  0xf0002261, 0xf10000b1, 0xf2002265, 0xf3002264,
  0xf4002320, 0xf5002321, 0xf60000f7, 0xf7002248,
  0xf80000b0, 0xf9002219, 0xfa0000b7, 0xfb00221a,
  0xfc00207f, 0xfd0000b2, 0xfe0025a0, 0xff0000a0,
};

enum tttp_client_state {
  CS_DEAD=0,
  CS_INITIALIZED,
  CS_QUERYING, CS_QUERIED,
  CS_FLAG, CS_FLAGGED,
  CS_AUTH, CS_AUTH_NEED_PASSWORD,
  CS_VERIFY,
  CS_NO_AUTH,
  CS_COMPLETE,
  CS_PASTING
};

struct tttp_client {
  enum tttp_client_state client_state;
  void* cbdata;
  void(*fatal_callback)(void* data, const char* what);
  void(*foul_callback)(void* data, const char* what);
  /* remainder of struct will be clobbered on error */
  enum tttp_message_state message_state;
  int(*receive_callback)(void* data, void* buf, size_t bufsz);
  int(*send_callback)(void* data, const void* buf, size_t bufsz);
  void(*flush_callback)(void* data);
  void(*pltt_callback)(void* data, const uint8_t* colors);
  void(*fram_callback)(void* data, uint32_t width, uint32_t height,
                       uint32_t dirty_left, uint32_t dirty_top,
                       uint32_t dirty_width, uint32_t dirty_height,
                       void* framedata);
  void(*kick_callback)(void* data, const uint8_t* text, size_t len);
  void(*text_callback)(void* data, const uint8_t* text, size_t len);
  void(*kyrp_callback)(void* data, uint32_t delay, uint32_t interval);
  void(*cdpt_callback)(void* data, const uint32_t encoding[256]);
  void(*pmode_callback)(void* data, int enabled);
  void(*unknown_callback)(void* data, uint32_t msgid, const uint8_t* msgdata,
                          uint32_t datalen);
  uint8_t* cp437_map, *from_cp437_map;
  uint8_t queue_depth, have_valid_palette:1, paste_mode_enabled:1;
  uint16_t preferred_width, preferred_height, maximum_width, maximum_height;
  uint32_t negotiated_flags;
  uint32_t message_type, message_len;
  uint16_t last_width, last_height;
  uint8_t* framebuffer;
  size_t data_buf_size, data_buf_pos;
  uint8_t* data_buf;
  uint8_t* message_data_ptr; // use message_data_ptr when actually reading data
  size_t recv_size, recv_buf_pos;
  uint8_t recv_buf[RECEIVE_BUFFER_SIZE];
  z_stream zlib;
  union tail {
    struct srp_tail {
      lsx_twofish_context twofish;
      mpz_t N, g, a, A, B, u, x, S, k, h, temp;
      // H_I also stores the H value we expect to get from the server if they
      // do, indeed, have our password verifier on file and do, indeed, have
      // the private key that corresponds to our public key
      uint8_t K[SHA256_HASHBYTES], H_I[SHA256_HASHBYTES], s[SHA256_HASHBYTES];
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
#define ERROR_BUFFER_SIZE (sizeof(tttp_client) - offsetof(tttp_client, message_state))

#define CP437_MAP_DEFAULT ((uint8_t*)-1)

static void kill_state(tttp_client* self) {
  if(self->client_state != CS_DEAD) {
    if(self->data_buf)
      free(self->data_buf);
    if(self->framebuffer)
      free(self->framebuffer);
    if(self->cp437_map && self->cp437_map != CP437_MAP_DEFAULT)
      free(self->cp437_map);
    if(self->from_cp437_map)
      free(self->from_cp437_map);
    if(self->zlib.opaque) {
      inflateEnd(&self->zlib);
      self->zlib.opaque = NULL;
    }
    if(self->tail) {
      if(self->client_state >= CS_COMPLETE) {
        lsx_destroy_twofish256(&self->tail->crypto.twofish);
        lsx_explicit_bzero(self->tail, sizeof(self->tail->crypto));
      }
      else {
        lsx_destroy_twofish256(&SRP.twofish);
        mpz_clears(SRP.N, SRP.g, SRP.a, SRP.A, SRP.B, SRP.u, SRP.x, SRP.S,
                   SRP.k, SRP.h, SRP.temp, NULL);
        lsx_destroy_sha256_expert(&SRP.sha256);
        lsx_explicit_bzero(self->tail, sizeof(SRP));
      }
      free(self->tail);
    }
  }
  self->client_state = CS_DEAD;
}

#if __GNUC__
static void fatal(tttp_client* self, const char* what, ...)
  __attribute__((noreturn,format(printf,2,3)));
#endif
static void fatal(tttp_client* self, const char* what, ...) {
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
static void foul(tttp_client* self, const char* what, ...)
  __attribute__((noreturn,format(printf,2,3)));
#endif
static void foul(tttp_client* self, const char* what, ...) {
  if(self->client_state == CS_DEAD)
    fatal(self, "foul called on a dead client (libtttp bug)");
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

#define FATAL_DEAD_STATE(self) fatal(self, "%s called on dead tttp_client", __FUNCTION__)
#define FATAL_WRONG_STATE(self) fatal(self, "%s called on tttp_client in inappropriate state", __FUNCTION__)
#define FATAL_MISSING_CALLBACK(self, what) fatal(self, "%s called with null %s callback", __FUNCTION__, what)

static uint8_t slow_hash_check(uint8_t a[SHA256_HASHBYTES],
                               uint8_t b[SHA256_HASHBYTES]) {
  uint8_t ret = 0;
  for(int n = 0; n < SHA256_HASHBYTES; ++n) { ret |= a[n]^b[n]; }
  return ret;
}

static void advance_keystream(tttp_client* self, uint8_t buf[16]) {
  lsx_encrypt_twofish(&self->tail->crypto.twofish, buf, buf);
}

static void decrypt(tttp_client* self, uint8_t* p, size_t rem) {
  uint8_t pos = self->tail->crypto.s2c_pos;
  while(rem > 0) {
    if(pos == 16) {
      advance_keystream(self, self->tail->crypto.s2c_buf);
      pos = 0;
    }
    do {
      uint8_t cipherbyte = *p;
      uint8_t keybyte = self->tail->crypto.s2c_buf[pos];
      uint8_t clearbyte = cipherbyte ^ keybyte;
      self->tail->crypto.s2c_buf[pos++] = cipherbyte;
      *p++ = clearbyte;
    } while(--rem > 0 && pos < 16);
  }
  self->tail->crypto.s2c_pos = pos;
}

static void encrypt(tttp_client* self, uint8_t* p, size_t rem) {
    uint8_t pos = self->tail->crypto.c2s_pos;
  while(rem > 0) {
    if(pos == 16) {
      advance_keystream(self, self->tail->crypto.c2s_buf);
      pos = 0;
    }
    do {
      uint8_t clearbyte = *p;
      uint8_t keybyte = self->tail->crypto.c2s_buf[pos];
      uint8_t cipherbyte = clearbyte ^ keybyte;
      self->tail->crypto.c2s_buf[pos++] = cipherbyte;
      *p++ = cipherbyte;
    } while(--rem > 0 && pos < 16);
  }
  self->tail->crypto.c2s_pos = pos;
}

static int send_data(tttp_client* self, uint8_t* send_buf, size_t len) {
  if(self->client_state < CS_COMPLETE
     || !(self->negotiated_flags & TTTP_FLAG_ENCRYPTION))
    return self->send_callback(self->cbdata, send_buf, len);
  encrypt(self, send_buf, len);
  return self->send_callback(self->cbdata, send_buf, len);
}

static int receive_data(tttp_client* self, uint8_t* recv_buf, size_t len) {
  if(self->client_state < CS_COMPLETE
     || !(self->negotiated_flags & TTTP_FLAG_ENCRYPTION))
    return self->receive_callback(self->cbdata, recv_buf, len);
  int red = self->receive_callback(self->cbdata, recv_buf, len);
  if(red <= 0) return red;
  decrypt(self, recv_buf, red);
  return red;
}

static void maybe_flush(tttp_client* self) {
  if(self->flush_callback) self->flush_callback(self->cbdata);
}

static int get_byte(tttp_client* self) {
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
static int get_message(tttp_client* self) {
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
      case 'FLAG': case 'AUTH': case 'NAUT': case 'PLTT': case 'FRAM':
      case 'DFRM': case 'RSET': case 'KICK': case 'CDPT': case 'QUER':
        break;
      default:
        foul(self, "Unknown standard critical message received (%c%c%c%c)",
             safe_char((self->message_type >> 24) & 0x7F),
             safe_char((self->message_type >> 16) & 0x7F),
             safe_char((self->message_type >> 8) & 0x7F),
             safe_char((self->message_type >> 0) & 0x7F));
        return -1;
      }
      if((self->message_type & 0x80000000) == 0) {
        // no data
        self->message_len = 0;
        break;
      }
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
      if(!new_buf) { foul(self, "Memory allocation failed"); return -1; }
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

tttp_client* tttp_client_init(void* data,
                              int(*receive)(void* data,
                                            void* buf, size_t bufsz),
                              int(*send)(void* data,
                                         const void* buf, size_t bufsz),
                              void(*flush)(void* data),
                              void(*fatal_cb)(void* data,
                                           const char* why),
                              void(*foul)(void* data,
                                          const char* why)) {
  tttp_client* ret = malloc(sizeof(tttp_client));
  if(ret == NULL) return NULL;
  ret->client_state = CS_INITIALIZED;
  ret->cbdata = data;
  ret->fatal_callback = fatal_cb;
  ret->zlib.opaque = NULL;
  ret->message_state = MS_TYPE_1;
  ret->receive_callback = receive;
  ret->send_callback = send;
  ret->flush_callback = flush;
  ret->foul_callback = foul;
  ret->pltt_callback = NULL;
  ret->fram_callback = NULL;
  ret->kick_callback = NULL;
  ret->text_callback = NULL;
  ret->kyrp_callback = NULL;
  ret->cdpt_callback = NULL;
  ret->pmode_callback = NULL;
  ret->unknown_callback = NULL;
  ret->cp437_map = CP437_MAP_DEFAULT;
  ret->from_cp437_map = NULL;
  ret->queue_depth = 0;
  ret->have_valid_palette = 0;
  ret->paste_mode_enabled = 0;
  ret->preferred_width = 0;
  ret->preferred_height = 0;
  ret->maximum_width = 0;
  ret->maximum_height = 0;
  ret->negotiated_flags = 0;
  ret->last_width = 0;
  ret->last_height = 0;
  ret->framebuffer = NULL;
  ret->data_buf = NULL;
  ret->data_buf_size = 0;
  // ret->data_buf_pos = 0;
  ret->recv_size = 0;
  ret->recv_buf_pos = 0;
  ret->tail = NULL;
  if(!tttp_init_called) {
    fatal(ret, "tttp_client_init called before tttp_init!");
    return NULL;
  }
  if(!receive) FATAL_MISSING_CALLBACK(ret, "receive");
  if(!send) FATAL_MISSING_CALLBACK(ret, "send");
  return ret;
}

void tttp_client_fini(tttp_client* self) {
  kill_state(self);
  free(self);
}

void tttp_client_change_data_pointer(tttp_client* self, void* data) {
  if(self->client_state == CS_DEAD) FATAL_DEAD_STATE(self);
  self->cbdata = data;
}

void tttp_client_set_queue_depth(tttp_client* self, uint8_t depth) {
  switch(self->client_state) {
  case CS_DEAD: FATAL_DEAD_STATE(self);
  case CS_PASTING: FATAL_WRONG_STATE(self);
  case CS_COMPLETE:
    if(self->queue_depth != depth) {
      uint8_t buf[6] = {'Q' | 0x80, 'u', 'e', 'u', 1, depth};
      send_data(self, buf, sizeof(buf));
    }
  default:
    self->queue_depth = depth;
  }
}

void tttp_client_set_screen_params(tttp_client* self,
                                   uint16_t preferred_width,
                                   uint16_t preferred_height,
                                   uint16_t maximum_width,
                                   uint16_t maximum_height) {
  if(self->client_state == CS_DEAD) FATAL_DEAD_STATE(self);
  if(!preferred_width || !preferred_height)
    preferred_height = preferred_width = 0;
  if(!maximum_width || !maximum_height)
    maximum_height = maximum_width = 0;
  switch(self->client_state) {
  case CS_PASTING: FATAL_WRONG_STATE(self);
  case CS_COMPLETE:
    if(self->preferred_width != preferred_width
       || self->preferred_height != preferred_height
       || self->maximum_width != maximum_width
       || self->maximum_height != maximum_height) {
      uint8_t buf[13] = {'S' | 0x80, 'c', 'r', 'n', 8,
                         preferred_width >> 8, preferred_width,
                         preferred_height >> 8, preferred_height,
                         maximum_width >> 8, maximum_width,
                         maximum_height >> 8, maximum_height};
      send_data(self, buf, sizeof(buf));
    }
  default:
    self->preferred_width = preferred_width;
    self->preferred_height = preferred_height;
    self->preferred_width = preferred_width;
    self->preferred_height = preferred_height;
    self->maximum_width = maximum_width;
    self->maximum_height = maximum_height;
    self->maximum_width = maximum_width;
    self->maximum_height = maximum_height;
  }
}

tttp_handshake_result tttp_client_query_server(tttp_client* self,
                                    uint8_t public_key[TTTP_PUBLIC_KEY_LENGTH],
                                               const uint8_t** servername,
                                               size_t* servernamelen) {
  if(self->client_state == CS_DEAD) FATAL_DEAD_STATE(self);
  else if(self->client_state != CS_QUERYING
          && self->client_state != CS_INITIALIZED) FATAL_WRONG_STATE(self);
  if(self->client_state == CS_INITIALIZED) {
    uint8_t buf[4] = {'Q','U','E','R'};
    send_data(self, buf, sizeof(buf));
    self->client_state = CS_QUERYING;
  }
  while(1) {
    switch(get_message(self)) {
    case -1: return TTTP_HANDSHAKE_ERROR;
    case 0: return TTTP_HANDSHAKE_CONTINUE;
    case 1:
      switch(self->message_type) {
      case 'QUER':
        if(self->message_len == 0) {
          self->client_state = CS_QUERIED;
          return TTTP_HANDSHAKE_REJECTED;
        }
        else if(self->message_len < TTTP_PUBLIC_KEY_LENGTH+1
                || self->message_len < (size_t)(TTTP_PUBLIC_KEY_LENGTH+1+self->message_data_ptr[TTTP_PUBLIC_KEY_LENGTH])) {
          foul(self, "QUER message too short");
          return TTTP_HANDSHAKE_ERROR;
        }
        memcpy(public_key, self->message_data_ptr, TTTP_PUBLIC_KEY_LENGTH);
        if(memcmp(public_key, SRP_N, SRP_N_BYTES) >= 0) {
          foul(self, "Server sent invalid public key");
          return TTTP_HANDSHAKE_ERROR;
        }
        if(servername && servernamelen) {
          *servername = self->message_data_ptr + TTTP_PUBLIC_KEY_LENGTH+1;
          *servernamelen = self->message_data_ptr[TTTP_PUBLIC_KEY_LENGTH];
        }
        self->client_state = CS_QUERIED;
        return TTTP_HANDSHAKE_ADVANCE;
      default:
        if(self->unknown_callback) {
          self->unknown_callback(self->cbdata, self->message_type,
                                 self->message_data_ptr, self->message_len);
          /* they must make an error if we don't */
        }
        else if(self->message_type & 0x00200000) {
          foul(self, "Received an unknown critical message during query attempt");
          return TTTP_HANDSHAKE_ERROR;
        }
        break;
      }
    }
  }
}

void tttp_client_request_flags(tttp_client* self, uint32_t flags) {
  if(self->client_state == CS_DEAD) FATAL_DEAD_STATE(self);
  else if(self->client_state != CS_FLAGGED
          && self->client_state != CS_QUERIED
          && self->client_state != CS_INITIALIZED) FATAL_WRONG_STATE(self);
  if(flags & ~TTTP_KNOWN_FLAGS)
    fatal(self, "%s: unknown flags", __FUNCTION__);
  uint8_t buf[9] = {'F'|0x80,'L','A','G',4,
                    flags>>24, flags>>16, flags>>8, flags};
  send_data(self, buf, sizeof(buf));
  maybe_flush(self);
  self->client_state = CS_FLAG;
}

tttp_handshake_result tttp_client_pump_flags(tttp_client* self) {
  if(self->client_state == CS_DEAD) FATAL_DEAD_STATE(self);
  else if(self->client_state != CS_FLAG)
    FATAL_WRONG_STATE(self);
  while(1) {
    switch(get_message(self)) {
    case -1: return TTTP_HANDSHAKE_ERROR;
    case 0: return TTTP_HANDSHAKE_CONTINUE;
    case 1:
      switch(self->message_type) {
      case 'FLAG':
        if(self->message_len < 4) {
          foul(self, "FLAG message too short");
          return TTTP_HANDSHAKE_ERROR;
        }
        self->negotiated_flags = ((uint32_t)self->message_data_ptr[0] << 24) |
          ((uint32_t)self->message_data_ptr[1] << 16) |
          ((uint32_t)self->message_data_ptr[2] << 8) |
          ((uint32_t)self->message_data_ptr[3]);
        self->client_state = CS_FLAGGED;
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

void tttp_client_begin_handshake(tttp_client* self,
                                 const char* username,
                                 const uint8_t* public_key) {
  if(self->client_state == CS_DEAD) FATAL_DEAD_STATE(self);
  else if(self->client_state != CS_FLAGGED) FATAL_WRONG_STATE(self);
  if((self->negotiated_flags & TTTP_FLAG_ENCRYPTION) && !username)
    fatal(self, "%s: encryption only possible if you provide a (possibly blank) username", __FUNCTION__);
  if(username) {
    size_t username_len = strlen(username);
    if(username_len > 255)
      fatal(self, "%s: username too long", __FUNCTION__);
    uint8_t bytes[SRP_N_BYTES+username_len+3+4];
    self->tail = malloc(sizeof(struct srp_tail));
    if(!self->tail) {
      foul(self, "Memory allocation failed");
      return;
    }
    lsx_setup_sha256_expert(&SRP.sha256);
    if(username_len >= SHA256_BLOCKBYTES)
      lsx_input_sha256_expert(&SRP.sha256,
                              username, username_len / SHA256_BLOCKBYTES);
    lsx_finish_sha256_expert(&SRP.sha256,
                             username + (username_len / SHA256_BLOCKBYTES
                                         * SHA256_BLOCKBYTES),
                             username_len % SHA256_BLOCKBYTES,
                             SRP.H_I);
    lsx_destroy_sha256_expert(&SRP.sha256);
    tttp_set_active_fatal(self->fatal_callback, self->cbdata);
    mpz_init2(SRP.N, SRP_N_BITS);
    mpz_init_set_ui(SRP.g, SRP_g);
    mpz_init2(SRP.a, SRP_N_BITS);
    mpz_init2(SRP.A, SRP_N_BITS);
    mpz_init2(SRP.B, SRP_N_BITS);
    mpz_init2(SRP.u, SHA256_HASHBYTES*8);
    mpz_init2(SRP.x, SHA256_HASHBYTES*8);
    mpz_init2(SRP.S, SRP_N_BITS);
    mpz_init2(SRP.k, SRP_k_BITS);
    mpz_init2(SRP.h, SRP_N_BITS);
    mpz_init2(SRP.temp, SRP_N_BITS+SRP_g_BITS);
#if SHA256_HASHBYTES*2 > SRP_N_BYTES
#error Change the size of temp, above
#endif
    // N := (SRP parameter N defined in specification)
    mpz_import(SRP.N, SRP_N_BYTES, 1, 1, 1, 0, SRP_N);
    // k := (SRP parameter k defined in specification)
    mpz_import(SRP.k, SRP_k_BYTES, 1, 1, 1, 0, SRP_k);
    // h := server public key
    mpz_import(SRP.h, SRP_N_BYTES, 1, 1, 1, 0, public_key);
    if(mpz_cmp(SRP.h, SRP.N) >= 0)
      fatal(self, "%s: caller gave us an invalid public key!",
            __FUNCTION__);
    do {
      // a := random bytes
      lsx_get_random(bytes, SRP_N_BYTES);
      mpz_import(SRP.a, SRP_N_BYTES, 1, 1, 1, 0, bytes);
      if(mpz_cmp(SRP.a, SRP.N) >= 0) continue;
      // A := g^a
      mpz_powm_sec(SRP.A, SRP.g, SRP.a, SRP.N);
      // temp := kh
      mpz_mul(SRP.temp, SRP.k, SRP.h);
      // temp := kh + g^a
      mpz_add(SRP.temp, SRP.temp, SRP.A);
      // (modularize)
      mpz_fdiv_r(SRP.A, SRP.temp, SRP.N);
      // A will never be >= N; if A is 0, we were really unlucky, get another
      // set of random bytes
    } while(mpz_cmp_si(SRP.A, 0) == 0);
    uint8_t* p = bytes;
    *p++ = 'A'|0x80; *p++ = 'U'; *p++ = 'T'; *p++ = 'H';
    size_t total_len = SRP_N_BYTES + 1 + username_len;
    *p++ = (total_len >> 7) | 0x80;
    *p++ = total_len & 0x7F;
    tttp_export_and_zero_fill_Nsize(p, SRP.A);
    p += SRP_N_BYTES;
    *p++ = username_len;
    for(const char* q = username; *q;) {
      *p++ = *q++;
    }
    send_data(self, bytes, p-bytes);
    self->client_state = CS_AUTH;
  }
  else {
    uint8_t buf[4] = {'N','A','U','T'};
    send_data(self, buf, sizeof(buf));
    self->client_state = CS_NO_AUTH;
  }
  maybe_flush(self);
}

tttp_handshake_result tttp_client_pump_auth(tttp_client* self) {
  switch(self->client_state) {
  case CS_DEAD: FATAL_DEAD_STATE(self);
  case CS_AUTH: while(1) {
    switch(get_message(self)) {
    case -1: return TTTP_HANDSHAKE_ERROR;
    case 0: return TTTP_HANDSHAKE_CONTINUE;
    case 1:
      switch(self->message_type) {
      case 'NAUT':
        kill_state(self);
        return TTTP_HANDSHAKE_REJECTED;
      case 'AUTH':
        if(self->message_len < sizeof(SRP.s) + SRP_N_BYTES) {
          foul(self, "Handshake AUTH message too short");
          return TTTP_HANDSHAKE_ERROR;
        }
        memcpy(SRP.s, self->message_data_ptr, SHA256_HASHBYTES);
        tttp_set_active_fatal(self->fatal_callback, self->cbdata);
        mpz_import(SRP.B, SRP_N_BYTES, 1, 1, 1, 0, self->message_data_ptr + SHA256_HASHBYTES);
        if(mpz_cmp_si(SRP.B, 0) == 0 ||
           mpz_cmp(SRP.B, SRP.N) >= 0) {
          foul(self, "Server sent blatantly incorrect crypto parameters. The server is probably compromised!");
          return TTTP_HANDSHAKE_ERROR;
        }
        uint8_t bytes[SRP_N_BYTES];
        tttp_export_and_zero_fill_Nsize(bytes, SRP.A);
        lsx_setup_sha256_expert(&SRP.sha256);
        lsx_input_sha256_expert(&SRP.sha256,
                                bytes, SRP_N_BYTES / SHA256_BLOCKBYTES);
        lsx_input_sha256_expert(&SRP.sha256,
                                self->message_data_ptr+SHA256_HASHBYTES,
                                SRP_N_BYTES / SHA256_BLOCKBYTES);
        lsx_finish_sha256_expert(&SRP.sha256,
                                 NULL, 0, bytes);
        lsx_destroy_sha256_expert(&SRP.sha256);
        mpz_import(SRP.u, SHA256_HASHBYTES, 1, 1, 1, 0, bytes);
        if(mpz_cmp_si(SRP.u, 0) == 0) {
          foul(self, "Server sent a subtly incorrect crypto parameter (H(A,B) == 0). The server is probably compromised (or poorly written)!");
          return TTTP_HANDSHAKE_ERROR;
        }
        self->client_state = CS_AUTH_NEED_PASSWORD;
        return TTTP_HANDSHAKE_ADVANCE;
      default:
        if(self->unknown_callback) {
          self->unknown_callback(self->cbdata, self->message_type,
                                 self->message_data_ptr, self->message_len);
          /* they must make an error if we don't */
        }
        else if(self->message_type & 0x00200000) {
          foul(self, "Received an unknown critical message during handshake");
          return TTTP_HANDSHAKE_ERROR;
        }
        break;
      }
    }
  }
  default: FATAL_WRONG_STATE(self);
  }
}

void tttp_client_provide_password(tttp_client* self,
                                  const void* _password, size_t passlen) {
  if(self->client_state == CS_DEAD) FATAL_DEAD_STATE(self);
  else if(self->client_state != CS_AUTH_NEED_PASSWORD) FATAL_WRONG_STATE(self);
  tttp_set_active_fatal(self->fatal_callback, self->cbdata);
  const uint8_t* password = _password;
  lsx_setup_sha256_expert(&SRP.sha256);
  uint8_t bytes[SRP_N_BYTES+SHA256_BLOCKBYTES];
  memcpy(bytes, SRP.s, SHA256_HASHBYTES);
  if(passlen < SHA256_BLOCKBYTES - SHA256_HASHBYTES) {
    memcpy(bytes + SHA256_HASHBYTES, password, passlen);
    lsx_finish_sha256_expert(&SRP.sha256,
                             bytes, SHA256_HASHBYTES + passlen, bytes);
  }
  else {
    uint32_t blockoff = SHA256_BLOCKBYTES - SHA256_HASHBYTES;
    memcpy(bytes + SHA256_HASHBYTES, password, blockoff);
    lsx_input_sha256_expert(&SRP.sha256, bytes, 1);
    uint32_t blockcount = (passlen - blockoff) / SHA256_BLOCKBYTES;
    uint32_t tailcount = passlen - blockcount*SHA256_BLOCKBYTES - blockoff;
    if(blockcount > 0)
      lsx_input_sha256_expert(&SRP.sha256, password+blockoff,
                              blockcount);
    lsx_finish_sha256_expert(&SRP.sha256,
                             password+blockoff+blockcount*SHA256_BLOCKBYTES,
                             tailcount, bytes);
  }
  mpz_import(SRP.x, SHA256_HASHBYTES, 1, 1, 1, 0, bytes);
  // crunch time!
  // S := h^u
  mpz_powm_sec(SRP.S, SRP.h, SRP.u, SRP.N);
  // temp := v = g^x
  mpz_powm_sec(SRP.temp, SRP.g, SRP.x, SRP.N);
  // temp := kv
  mpz_mul(SRP.temp, SRP.k, SRP.temp);
  // temp := B-kv
  mpz_sub(SRP.temp, SRP.B, SRP.temp);
  // (modularize)
  mpz_fdiv_r(SRP.temp, SRP.temp, SRP.N);
  // temp := (B-kv)(h^u)
  mpz_mul(SRP.temp, SRP.temp, SRP.S);
  // (modularize into S)
  mpz_fdiv_r(SRP.S, SRP.temp, SRP.N);
  // temp := ux
  mpz_mul(SRP.temp, SRP.u, SRP.x);
  // temp := a + ux
  mpz_add(SRP.temp, SRP.a, SRP.temp);
  // S := ((B-kv)(h^u))^(a+ux)
  mpz_powm_sec(SRP.S, SRP.S, SRP.temp, SRP.N);
  // K := H(S), and set up the Twofish context
  tttp_export_and_zero_fill_Nsize(bytes, SRP.S);
  lsx_setup_sha256_expert(&SRP.sha256);
  lsx_input_sha256_expert(&SRP.sha256,
                          bytes, SRP_N_BYTES / SHA256_BLOCKBYTES);
  lsx_finish_sha256_expert(&SRP.sha256,
                           NULL, 0, SRP.K);
  lsx_setup_twofish256(&SRP.twofish, SRP.K);
#if SHA256_HASHBYTES*2 != SHA256_BLOCKBYTES
#error this section will need to be rewritten
#endif
  lsx_setup_sha256_expert(&SRP.sha256);
  // block 1 = H(N) xor H(G), H(I)
  memcpy(bytes, SRP_param_hash, SHA256_HASHBYTES);
  memcpy(bytes+SHA256_HASHBYTES, SRP.H_I, SHA256_HASHBYTES);
  lsx_input_sha256_expert(&SRP.sha256, bytes, 1);
  // block 2..a-1 = s, A
  memcpy(bytes, SRP.s, SHA256_HASHBYTES);
  tttp_export_and_zero_fill_Nsize(bytes+SHA256_HASHBYTES, SRP.A);
  lsx_input_sha256_expert(&SRP.sha256, bytes,
                          SRP_N_BYTES / SHA256_BLOCKBYTES);
  // block a..b-1 = A (tail), B
  // copy A's tail
  memcpy(bytes, bytes+SRP_N_BYTES, SHA256_HASHBYTES);
  tttp_export_and_zero_fill_Nsize(bytes+SHA256_HASHBYTES, SRP.B);
  lsx_input_sha256_expert(&SRP.sha256, bytes,
                          SRP_N_BYTES / SHA256_BLOCKBYTES);
  // block b = B (tail), K
  // almost done... copy B's tail
  memcpy(bytes, bytes+SRP_N_BYTES, SHA256_HASHBYTES);
  memcpy(bytes+SHA256_HASHBYTES, SRP.K, SHA256_HASHBYTES);
  lsx_input_sha256_expert(&SRP.sha256, bytes,
                          1);
  lsx_finish_sha256_expert(&SRP.sha256,
                           NULL, 0, bytes + SRP_N_BYTES);
  bytes[0] = 'A' | 0x80; bytes[1] = 'U'; bytes[2] = 'T'; bytes[3] = 'H';
  bytes[4] = SHA256_HASHBYTES;
  memcpy(bytes+5, bytes+SRP_N_BYTES, SHA256_HASHBYTES);
  send_data(self,bytes,SHA256_HASHBYTES+5);
  maybe_flush(self);
  tttp_export_and_zero_fill_Nsize(bytes, SRP.A);
  memcpy(bytes + SRP_N_BYTES + SHA256_HASHBYTES, SRP.K,
         SHA256_HASHBYTES);
  lsx_setup_sha256_expert(&SRP.sha256);
  lsx_input_sha256_expert(&SRP.sha256,
                          bytes,
                          SRP_N_BYTES / SHA256_BLOCKBYTES + 1);
  lsx_finish_sha256_expert(&SRP.sha256,
                           NULL, 0, SRP.H_I);
  lsx_destroy_sha256_expert(&SRP.sha256);
  self->client_state = CS_VERIFY;
}

tttp_handshake_result tttp_client_pump_verify(tttp_client* self) {
  switch(self->client_state) {
  case CS_DEAD: FATAL_DEAD_STATE(self);
  case CS_VERIFY:
  case CS_NO_AUTH: while(1) {
    switch(get_message(self)) {
    case -1: return TTTP_HANDSHAKE_ERROR;
    case 0: return TTTP_HANDSHAKE_CONTINUE;
    case 1:
      switch(self->message_type) {
      case 'NAUT':
        kill_state(self);
        return TTTP_HANDSHAKE_REJECTED;
      case 'AUTH':
        if(self->client_state == CS_VERIFY) {
          if(self->message_len < SHA256_HASHBYTES) {
            foul(self, "Server sent an inappropriately short AUTH packet");
            return TTTP_HANDSHAKE_ERROR;
          }
          if(slow_hash_check(self->message_data_ptr, SRP.H_I)) {
            foul(self, "Server lied about knowing our password. It is probably compromised.");
            return TTTP_HANDSHAKE_ERROR;
          }
          if(self->negotiated_flags & TTTP_FLAG_ENCRYPTION) {
            uint8_t k_x = 0;
            for(unsigned int n = 0; n < sizeof(SRP.K); ++n)
              k_x ^= SRP.K[n];
            /* We can't use realloc as it might leave some old remnants of
               sensitive data around */
            union tail* new_tail = malloc(sizeof(struct crypto_tail));
            if(new_tail == NULL) {
              foul(self, "Memory allocation failed");
              return TTTP_HANDSHAKE_ERROR;
            }
            memcpy(&new_tail->crypto.twofish, &SRP.twofish,
                   sizeof(lsx_twofish_context));
            mpz_clears(SRP.N, SRP.g, SRP.a, SRP.A, SRP.B, SRP.u, SRP.x, SRP.S,
                       SRP.k, SRP.h, SRP.temp, NULL);
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
            mpz_clears(SRP.N, SRP.g, SRP.a, SRP.A, SRP.B, SRP.u, SRP.x, SRP.S,
                       SRP.k, SRP.h, SRP.temp, NULL);
            lsx_explicit_bzero(&SRP, sizeof(SRP));
            free(self->tail);
          }
        }
        else {
          /* CS_NO_AUTH; no action needed */
        }
        goto complete;
      default:
        if(self->unknown_callback) {
          self->unknown_callback(self->cbdata, self->message_type,
                                 self->message_data_ptr, self->message_len);
          /* they must do the critical chunk check themselves */
        }
        else if(self->message_type & 0x00200000) {
          foul(self, "Received an unknown critical message during handshake");
          return TTTP_HANDSHAKE_ERROR;
        }
        break;
      }
    }
  }
  default: FATAL_WRONG_STATE(self);
  }
  /* NOTREACHED */
  fatal(self, "This code should never be reached");
 complete:
  self->client_state = CS_COMPLETE;
  self->zlib.zalloc = NULL;
  self->zlib.zfree = NULL;
  self->zlib.next_in = NULL;
  self->zlib.avail_in = 0;
  if(inflateInit(&self->zlib) != Z_OK) {
    foul(self, "zlib error");
    return TTTP_HANDSHAKE_ERROR;
  }
  self->zlib.opaque = (void*)-1; // tell kill_state that this needs to be freed
  if(self->queue_depth) {
    uint8_t buf[6] = {'Q' | 0x80, 'u', 'e', 'u', 1, self->queue_depth};
    send_data(self, buf, sizeof(buf));
  }
  if(self->preferred_width || self->preferred_height
     || self->maximum_width || self->maximum_height) {
    uint8_t buf[13] = {'S' | 0x80, 'c', 'r', 'n', 8,
                       self->preferred_width >> 8, self->preferred_width,
                       self->preferred_height >> 8, self->preferred_height,
                       self->maximum_width >> 8, self->maximum_width,
                       self->maximum_height >> 8, self->maximum_height};
    send_data(self, buf, sizeof(buf));
  }
  return TTTP_HANDSHAKE_ADVANCE;
}

uint32_t tttp_client_get_flags(tttp_client* self) {
  if(self->client_state == CS_DEAD) FATAL_DEAD_STATE(self);
  else if(self->client_state == CS_INITIALIZED
          || self->client_state == CS_FLAG) FATAL_WRONG_STATE(self);
  return self->negotiated_flags;
}

void tttp_client_set_core_callbacks(tttp_client* self,
                                    void(*pltt)(void* data,
                                                const uint8_t* colors),
                                    void(*fram)(void* data,
                                                uint32_t width,
                                                uint32_t height,
                                                uint32_t dirty_left,
                                                uint32_t dirty_top,
                                                uint32_t dirty_width,
                                                uint32_t dirty_height,
                                                void* framedata),
                                    void(*kick)(void* data,
                                                const uint8_t* text,
                                                size_t len)) {
  if(self->client_state == CS_DEAD) FATAL_DEAD_STATE(self);
  if(!pltt) FATAL_MISSING_CALLBACK(self, "pltt");
  if(!fram) FATAL_MISSING_CALLBACK(self, "fram");
  if(!kick) FATAL_MISSING_CALLBACK(self, "kick");
  self->pltt_callback = pltt;
  self->fram_callback = fram;
  self->kick_callback = kick;
}

void tttp_client_set_text_callback(tttp_client* self,
                                   void(*text)(void* data,
                                               const uint8_t* text,
                                               size_t len)) {
  if(self->client_state == CS_DEAD) FATAL_DEAD_STATE(self);
  self->text_callback = text;
}

void tttp_client_set_kyrp_callback(tttp_client* self,
                                   void(*kyrp)(void* data,
                                               uint32_t delay,
                                               uint32_t interval)) {
  if(self->client_state == CS_DEAD) FATAL_DEAD_STATE(self);
  self->kyrp_callback = kyrp;
}

void tttp_client_set_cdpt_callback(tttp_client* self,
                                   void(*cdpt)(void* data,
                                               const uint32_t encoding[256])) {
  if(self->client_state == CS_DEAD) FATAL_DEAD_STATE(self);
  self->cdpt_callback = cdpt;
}

void tttp_client_set_paste_mode_callback(tttp_client* self,
                                         void(*pmode)(void* data,
                                                      int enabled)) {
  if(self->client_state == CS_DEAD) FATAL_DEAD_STATE(self);
  self->pmode_callback = pmode;
}

void tttp_client_set_unknown_callback(tttp_client* self,
                                      void(*unknown)(void* data,
                                                     uint32_t msgid,
                                                     const uint8_t* msgdata,
                                                     uint32_t datalen)) {
  if(self->client_state == CS_DEAD) FATAL_DEAD_STATE(self);
  self->unknown_callback = unknown;
}

void tttp_client_set_autocp437(tttp_client* self, int mode) {
  if(self->client_state == CS_DEAD) FATAL_DEAD_STATE(self);
  if(!mode) {
    if(self->cp437_map && self->cp437_map != CP437_MAP_DEFAULT)
      free(self->cp437_map);
    self->cp437_map = NULL;
  }
  else if(!self->cp437_map) {
    if(self->client_state >= CS_COMPLETE)
      fatal(self, "%s: attempt to re-enable autocp437 after \"complete\""
            " state was entered", __FUNCTION__);
    self->cp437_map = CP437_MAP_DEFAULT;
  }
}

static uint8_t delta_decode(uint8_t prev, uint8_t delta) {
  return delta == 0 ? prev : delta == prev ? 0 : delta;
}

int tttp_client_pump(tttp_client* self) {
  if(self->client_state == CS_DEAD) FATAL_DEAD_STATE(self);
  else if(self->client_state != CS_COMPLETE) FATAL_WRONG_STATE(self);
  while(self->client_state == CS_COMPLETE) {
    switch(get_message(self)) {
    case -1: return 0;
    case 0: return 1;
    case 1:
      switch(self->message_type) {
      case 'PLTT':
        if(self->message_len == 0) self->have_valid_palette = 0;
        else if(self->message_len < 6) {
          foul(self, "Invalid PLTT message received");
          return 0;
        }
        else if(self->message_len >= 48) {
          if(!self->pltt_callback) FATAL_MISSING_CALLBACK(self, "pltt");
          self->pltt_callback(self->cbdata, self->message_data_ptr);
          self->have_valid_palette = 1;
        }
        else {
          uint8_t fakepltt[48];
          int num_colors = self->message_len / 3;
          memcpy(fakepltt, self->message_data_ptr, num_colors * 3);
          for(int n = num_colors * 3; n < 48; ++n) {
            fakepltt[n] = fakepltt[0];
            fakepltt[n+1] = fakepltt[1];
            fakepltt[n+2] = fakepltt[2];
          }
          self->pltt_callback(self->cbdata, fakepltt);
          self->have_valid_palette = 1;
        }
        break;
      case 'FRAM':
        if(!self->fram_callback) FATAL_MISSING_CALLBACK(self, "fram");
        if(self->message_len < 5) {
          foul(self, "Impossibly short FRAM message received");
          return 0;
        }
        else if(!(self->message_data_ptr[0] || self->message_data_ptr[1])
                || !(self->message_data_ptr[2] || self->message_data_ptr[3])) {
          foul(self, "FRAM message with a zero dimension received");
          return 0;
        }
        else {
          if(!self->have_valid_palette) {
            if(!self->pltt_callback) FATAL_MISSING_CALLBACK(self, "pltt");
            self->pltt_callback(self->cbdata, default_palette);
            self->have_valid_palette = 1;
          }
          uint16_t width = ((uint16_t)self->message_data_ptr[0] << 8)
            | self->message_data_ptr[1];
          uint16_t height = ((uint16_t)self->message_data_ptr[2] << 8)
            | self->message_data_ptr[3];
          // two framebuffers
          uint32_t total_bytes = ((uint32_t)width)*height*2;
          uint32_t needed_buffers = 2;
          if(self->negotiated_flags & TTTP_FLAG_UNICODE) total_bytes *= 2;
          if(width != self->last_width || height != self->last_height
             || !self->framebuffer) {
            if(self->framebuffer) free(self->framebuffer);
            self->framebuffer = calloc(total_bytes, needed_buffers);
            if(!self->framebuffer) {
              foul(self, "Memory allocation failed");
              return 0;
            }
          }
          self->zlib.avail_in = self->message_len-4;
          self->zlib.next_in = self->message_data_ptr+4;
          self->zlib.avail_out = total_bytes;
          self->zlib.next_out = self->framebuffer + total_bytes;
          int res = inflate(&self->zlib, Z_SYNC_FLUSH);
          if(res != Z_OK) {
            foul(self, "zlib error %i after consuming %u bytes", res,
                 (unsigned int)(self->zlib.next_in
                                - self->message_data_ptr + 4));
            return 0;
          }
          if(self->zlib.avail_out != 0 || self->zlib.avail_in != 0) {
            foul(self, "invalid zlib stream");
            return 0;
          }
          uint8_t* dstp = self->framebuffer,
            *srcp = self->framebuffer + total_bytes;
          uint32_t dirty_left = width, dirty_right = 0;
          uint32_t dirty_top = height, dirty_bot = 0;
          // TODO: skip XOR step when the framebuffer is fresh?
          /* could be optimized, but would become very slightly less portable*/
          if(self->negotiated_flags & TTTP_FLAG_UNICODE) {
            for(uint32_t y = 0; y < height; ++y) {
              for(uint32_t x = 0; x < width; ++x) {
                if(srcp[0] || srcp[1] || srcp[2] || srcp[3]) {
                  if(x < dirty_left) dirty_left = x;
                  if(x > dirty_right) dirty_right = x;
                  if(y < dirty_top) dirty_top = y;
                  if(y > dirty_bot) dirty_bot = y;
                }
                *dstp = delta_decode(*dstp, *srcp++); ++dstp;
                *dstp = delta_decode(*dstp, *srcp++); ++dstp;
                *dstp = delta_decode(*dstp, *srcp++); ++dstp;
                *dstp = delta_decode(*dstp, *srcp++); ++dstp;
              }
            }
          }
          else {
            for(uint32_t y = 0; y < height; ++y) {
              for(uint32_t x = 0; x < width; ++x) {
                if(*srcp) {
                  if(x < dirty_left) dirty_left = x;
                  if(x > dirty_right) dirty_right = x;
                  if(y < dirty_top) dirty_top = y;
                  if(y > dirty_bot) dirty_bot = y;
                }
                *dstp = delta_decode(*dstp, *srcp++); ++dstp;
              }
            }
            for(uint32_t y = 0; y < height; ++y) {
              for(uint32_t x = 0; x < width; ++x) {
                if(*srcp) {
                  if(x < dirty_left) dirty_left = x;
                  if(x > dirty_right) dirty_right = x;
                  if(y < dirty_top) dirty_top = y;
                  if(y > dirty_bot) dirty_bot = y;
                }
                *dstp = delta_decode(*dstp, *srcp++); ++dstp;
              }
            }
          }
          uint32_t dirty_width, dirty_height;
          if(dirty_left > dirty_right) { dirty_left = 0; dirty_width = 0; }
          else dirty_width = dirty_right - dirty_left + 1;
          if(dirty_top > dirty_bot) { dirty_top = 0; dirty_height = 0; }
          else dirty_height = dirty_bot - dirty_top + 1;
          if(!(self->negotiated_flags & TTTP_FLAG_UNICODE)
             && self->cp437_map != NULL
             && self->cp437_map != CP437_MAP_DEFAULT) {
            srcp = self->framebuffer;
            dstp = self->framebuffer + total_bytes;
            for(uint32_t y = 0; y < height; ++y) {
              for(uint32_t x = 0; x < width; ++y) {
                *dstp++ = *srcp++;
                *dstp++ = self->cp437_map[*srcp++];
              }
            }
            self->fram_callback(self->cbdata,
                                width, height,
                                dirty_left, dirty_top,
                                dirty_width, dirty_height,
                                self->framebuffer + total_bytes);
          }
          else
            self->fram_callback(self->cbdata,
                                width, height,
                                dirty_left, dirty_top,
                                dirty_width, dirty_height,
                                self->framebuffer);
          uint8_t buf[4] = {'O','N','E','S'};
          send_data(self, buf, sizeof(buf));
          maybe_flush(self);
        }
        break;
      case 'RSET':
        self->have_valid_palette = 0;
        inflateReset(&self->zlib);
        {
          uint8_t buf[4] = {'R','a','c','k'};
          send_data(self, buf, sizeof(buf));
        }
        if(self->queue_depth) {
          uint8_t buf[6] = {'Q' | 0x80, 'u', 'e', 'u', 1, self->queue_depth};
          send_data(self, buf, sizeof(buf));
        }
        if(self->preferred_width || self->preferred_height
           || self->maximum_width || self->maximum_height) {
          uint8_t buf[13] = {'S' | 0x80, 'c', 'r', 'n', 8,
                             self->preferred_width >> 8, self->preferred_width,
                             self->preferred_height>>8, self->preferred_height,
                             self->maximum_width >> 8, self->maximum_width,
                             self->maximum_height >> 8, self->maximum_height};
          send_data(self, buf, sizeof(buf));
        }
        if(self->kyrp_callback) {
          self->kyrp_callback(self->cbdata, ~(uint32_t)0, ~(uint32_t)0);
        }
        if(self->cp437_map && self->cp437_map != CP437_MAP_DEFAULT) {
          free(self->cp437_map);
          if(self->cdpt_callback && self->cp437_map != CP437_MAP_DEFAULT)
            self->cdpt_callback(self->cbdata, default_codepoint_table);
          self->cp437_map = CP437_MAP_DEFAULT;
        }
        /* fall through */
      case 'DFRM':
      destroy_frame:
        free(self->framebuffer);
        self->framebuffer = NULL;
        self->last_width = 0;
        self->last_height = 0;
        break;
      case 'KICK':
        if(!self->kick_callback) FATAL_MISSING_CALLBACK(self, "kick");
        self->kick_callback(self->cbdata, self->message_data_ptr,
                            self->message_len);
        return 0;
      case 'Kyrp':
        if(self->message_len < 8) {
          foul(self, "Received a 'Kyrp' message that was too short");
          return 0;
        }
        if(self->kyrp_callback)
          self->kyrp_callback(self->cbdata,
                              ((uint32_t)self->message_data_ptr[0] << 24)
                              | ((uint32_t)self->message_data_ptr[1] << 16)
                              | ((uint32_t)self->message_data_ptr[2] << 8)
                              | self->message_data_ptr[3],
                              ((uint32_t)self->message_data_ptr[4] << 24)
                              | ((uint32_t)self->message_data_ptr[5] << 16)
                              | ((uint32_t)self->message_data_ptr[6] << 8)
                              | self->message_data_ptr[7]);
        break;
      case 'CDPT':
        if(self->negotiated_flags & TTTP_FLAG_UNICODE) {
          /* do nothing */
        }
        else if(self->message_len < 1024) {
          foul(self, "Received a 'CDPT' message that was too short");
          return 0;
        }
        else {
          uint32_t codepoints[256];
          for(int n = 0; n < 256; ++n) {
            codepoints[n] = ((uint32_t)self->message_data_ptr[n*4]<<24)
              | ((uint32_t)self->message_data_ptr[n*4+1]<<16)
              | ((uint32_t)self->message_data_ptr[n*4+2]<<8)
              | (uint32_t)self->message_data_ptr[n*4+3];
          }
          if(self->cdpt_callback) self->cdpt_callback(self->cbdata,codepoints);
          if(self->cp437_map) {
            if(self->cp437_map == CP437_MAP_DEFAULT) {
              self->cp437_map = malloc(256);
              if(!self->cp437_map) {
                foul(self, "Memory allocation failed");
                return 0;
              }
            }
            if(!self->from_cp437_map) {
              self->from_cp437_map = calloc(256,1);
              if(!self->from_cp437_map) {
                foul(self, "Memory allocation failed");
                return 0;
              }
            }
            else memset(self->from_cp437_map, 0, 256);
            for(int n = 0; n < 256; ++n) {
              uint8_t code = codepoints[n] >> 24;
              self->cp437_map[n] = code;
              if(n && code && !self->from_cp437_map[code])
                self->from_cp437_map[code] = n;
              if(self->cp437_map[n] == 0) self->cp437_map[n] = '?';
            }
          }
        }
        goto destroy_frame;
      case 'Pon\0':
        if(self->pmode_callback) self->pmode_callback(self->cbdata, 1);
        self->paste_mode_enabled = 1;
        break;
      case 'Poff':
        if(self->pmode_callback) self->pmode_callback(self->cbdata, 0);
        self->paste_mode_enabled = 0;
        break;
      default:
        if(self->unknown_callback) {
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

void tttp_client_begin_paste(tttp_client* self) {
  if(self->client_state == CS_DEAD) FATAL_DEAD_STATE(self);
  else if(self->client_state != CS_COMPLETE
          || !self->paste_mode_enabled) FATAL_WRONG_STATE(self);
  uint8_t buf[4] = {'P', 'b', 'e', 'g'};
  send_data(self, buf, sizeof(buf));
  self->client_state = CS_PASTING;
}

void tttp_client_end_paste(tttp_client* self) {
  if(self->client_state == CS_DEAD) FATAL_DEAD_STATE(self);
  else if(self->client_state != CS_PASTING) FATAL_WRONG_STATE(self);
  uint8_t buf[4] = {'P', 'e', 'n', 'd'};
  send_data(self, buf, sizeof(buf));
  self->client_state = CS_PASTING;
}

void tttp_client_send_key(tttp_client* self, tttp_press_status status,
                          uint16_t scancode) {
  if(self->client_state == CS_DEAD) FATAL_DEAD_STATE(self);
  else if(self->client_state == CS_PASTING
          && scancode != '\n' && scancode != '\t')
    fatal(self, "%s: key message not involving enter or tab during paste",
          __FUNCTION__);
  else if(self->client_state != CS_COMPLETE) FATAL_WRONG_STATE(self);
  if(status == TTTP_PRESS || status == TTTP_TAP) {
    uint8_t buf[4] = {'K', 'p', scancode>>8, scancode};
    send_data(self, buf, sizeof(buf));
  }
  if(status == TTTP_RELEASE || status == TTTP_TAP) {
    uint8_t buf[4] = {'K', 'r', scancode>>8, scancode};
    send_data(self, buf, sizeof(buf));
  }
}

void tttp_client_send_text(tttp_client* self, uint8_t* text, size_t textlen) {
  if(self->client_state == CS_DEAD) FATAL_DEAD_STATE(self);
  else if(self->client_state != CS_COMPLETE
          && self->client_state != CS_PASTING) FATAL_WRONG_STATE(self);
  if(textlen == 0)
    fatal(self, "%s: Attempt to send empty 'Text'",__FUNCTION__);
  else if(textlen > TTTP_MAX_DATA_SIZE)
    fatal(self, "%s: Attempt to send too much 'Text'",__FUNCTION__);
  if(!(self->negotiated_flags & TTTP_FLAG_UNICODE) &&
     (self->cp437_map != NULL && self->cp437_map != CP437_MAP_DEFAULT)) {
    const uint8_t* inp = text;
    uint8_t* outp = text;
    size_t rem = textlen;
    while(rem-- > 0) {
      uint8_t code = self->from_cp437_map[*inp++];
      if(code) *outp++ = code;
      else --textlen;
    }
  }
  tttp_client_send_custom_message(self, 'Text', text, textlen);
}

void tttp_client_send_mouse_movement(tttp_client* self, int16_t x, int16_t y) {
  if(self->client_state == CS_DEAD) FATAL_DEAD_STATE(self);
  else if(self->client_state != CS_COMPLETE) FATAL_WRONG_STATE(self);
  uint8_t buf[9] = {'M'|0x80,'o','u','s',4,(uint16_t)x>>8,x,(uint16_t)y>>8,y};
  send_data(self, buf, sizeof(buf));
}

void tttp_client_send_mouse_button(tttp_client* self, tttp_press_status status,
                                   uint16_t button) {
  if(self->client_state == CS_DEAD) FATAL_DEAD_STATE(self);
  else if(self->client_state != CS_COMPLETE) FATAL_WRONG_STATE(self);
  if(status == TTTP_PRESS || status == TTTP_TAP) {
    uint8_t buf[4] = {'M', 'p', button>>8, button};
    send_data(self, buf, sizeof(buf));
  }
  if(status == TTTP_RELEASE || status == TTTP_TAP) {
    uint8_t buf[4] = {'M', 'r', button>>8, button};
    send_data(self, buf, sizeof(buf));
  }
}

void tttp_client_send_scroll(tttp_client* self, int8_t x, int8_t y) {
  if(self->client_state == CS_DEAD) FATAL_DEAD_STATE(self);
  else if(self->client_state != CS_COMPLETE) FATAL_WRONG_STATE(self);
  uint8_t buf[4] = {'S', 'c', x, y};
  send_data(self, buf, sizeof(buf));
}

void tttp_client_send_custom_message(tttp_client* self, uint32_t msgid,
                                     void* msgdata, size_t msglen) {
  if(self->client_state == CS_DEAD) FATAL_DEAD_STATE(self);
  if(msglen > TTTP_MAX_DATA_SIZE)
    fatal(self,"%s: Too much data provided",__FUNCTION__);
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
