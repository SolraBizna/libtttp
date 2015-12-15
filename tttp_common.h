#ifndef TTTP_COMMON_H
#define TTTP_COMMON_H

#include <stdint.h>
#include <stdlib.h>

#if __cplusplus
extern "C" {
#endif
#if 0
} /* make emacs happy */
#endif

/* The default TCP port to use for TTTP servers. */
#define TTTP_STANDARD_PORT 7028
/* The length, in bytes, of a salt. */
#define TTTP_SALT_LENGTH 32
/* The length, in bytes, of a password verifier, public key, or private key. */
#define TTTP_KEY_LENGTH 384
/* The length, in bytes, of a password verifier. (Not counting the salt) */
#define TTTP_VERIFIER_LENGTH TTTP_KEY_LENGTH
/* The length, in bytes, of a server's public key. */
#define TTTP_PUBLIC_KEY_LENGTH TTTP_KEY_LENGTH
/* The length, in bytes, of a server's private key. */
#define TTTP_PRIVATE_KEY_LENGTH TTTP_KEY_LENGTH
/* The size, in bytes, of a buffer large enough to store a "canonical" key
   fingerprint */
#define TTTP_FINGERPRINT_BUFFER_SIZE 48 // 32 digits, 15 colons, and a NUL
/* The size, in bytes, of a buffer large enough to store a "canonical" Base64-
   encoded key */
#define TTTP_KEY_BASE64_BUFFER_SIZE (512+8) // 512 chars, 7 linebreaks, & a NUL
/* The smallest possible size for a valid, Base64-encoded key. */
#define TTTP_KEY_BASE64_MIN_SIZE 512

/* Whether to attempt to use encryption on this connection. For clients,
   encryption should be default when authentication is being used. (This
   includes guest authentication, which should generally be used instead of no
   authentication.)
   Servers might, whether on a user-by-user basis
   or in general, refuse to accept non-encrypted connections entirely. */
#define TTTP_FLAG_ENCRYPTION 0x00000001
/* Whether we are in Unicode mode. */
#define TTTP_FLAG_UNICODE 0x00000002
/* Flags currently not supported. Will be used in future, and will keep their
   current names. */
#define TTTP_FLAG_FUTURE_UNICODE 0x00000004
#define TTTP_FLAG_FUTURE_CRYPTO 0x80000000

/* A bitmask containing every "known" flag. Servers receiving requests for
   other flags will ignore them. Clients receiving a 'FLAG' message from the
   server containing other flags will error out. */
#define TTTP_KNOWN_FLAGS ((uint32_t)0x00000003)

/* Mouse buttons identifiers */
#define TTTP_LEFT_MOUSE_BUTTON 0
#define TTTP_MIDDLE_MOUSE_BUTTON 1
#define TTTP_RIGHT_MOUSE_BUTTON 2
#define TTTP_EXTENDED_MOUSE_BUTTON(n) (3+(n))

/* Maximum length of message data */
#define TTTP_MAX_DATA_SIZE ((1<<21)-1)

/* Returned from handshake functions */
typedef enum tttp_handshake_result {
  /* all data was consumed but the handshake is not over */
  TTTP_HANDSHAKE_CONTINUE,
  /* we are ready to move on to the next stage of the handshake */
  TTTP_HANDSHAKE_ADVANCE,
  /* the server rejected us (client only)
     the client gave the wrong password (server only) */
  TTTP_HANDSHAKE_REJECTED,
  /* your receive callback indicated an error, or there was a foul */
  TTTP_HANDSHAKE_ERROR
} tttp_handshake_result;

typedef struct tttp_thread_local_block {
  void(*fp)(void*,const char*);
  void* d;
} tttp_thread_local_block;

/* Your application must call this exactly once before calling any other
   functions (preferably early in startup). This will initialize GMP in a
   secure state, and perform other setup that must be done before any threading
   shenanigans unfold.

   This function sets up GMP to erase memory whenever it is deallocated, and to
   call `fatal` instead of aborting the program when memory allocation fails.
   This is the only circumstance where `fatal` will be called for a reason
   other than incorrect usage of the library.

   If you use GMP yourself, you MUST call `tttp_set_active_fatal` with an
   appropriate error handler before any calls to GMP functions, and assume that
   a libtttp function call clobbers this handler. */
void tttp_init();

/* Sets the active "fatal error handler" for GMP's memory allocation functions
   in the current thread. You ONLY need to call this if you are using GMP
   yourself.
   The given handler will be called if a memory allocation fails, and MUST NOT
   RETURN. (It should use longjmp / an exception / some other means to ensure
   this.)
   You may pass NULL as the handler, to use a default "print and abort program"
   handler. Do NOT assume that it is already NULL if you have called any
   libtttp functions, as they can set their own fatal error handlers! */
void tttp_set_active_fatal(void(*)(void* d, const char* what), void* d);

/* Your application must define this function. It must return a pointer to a
   unique `tttp_thread_local_block` for each thread. If your application is not
   multithreaded (or at least does not call libtttp functions from more than
   one thread), it is enough to return a pointer to a `static
   tttp_thread_local_block` variable.

   A `tttp_thread_local_block` does not need to be treated as anything but
   plain data---it does not need to be destroyed in a special way (other than
   being deallocated) when a thread terminates. It also does not need to be
   allocated before the first time `tttp_get_thread_local_block` is called for
   a given thread. */
tttp_thread_local_block* tttp_get_thread_local_block();

/* Converts a password into a verifier, also creating a salt.

   This should be computed at password entry time and stored on the server. The
   server SHOULD NOT store the password, even in hashed form. The verifier is
   all that is needed. (The verifier cannot be used to impersonate the user,
   but the password CAN---even if hashed!)

   Do NOT try to use the same verifier or salt for more than one user.
   Do NOT try to preserve the salt for any reason; if the password changes, the
   salt must also change.

   You should provide a (non-returning, such as via an exception or longjmp)
   `fatal_callback` if you do not want the program to terminate because of a
   memory allocation failure. (If you don't mind that happening, feel free to
   pass NULL here.) */
void tttp_password_to_verifier(void(*fatal_callback)(void*,const char*),
                               void* callback_data,
                               const uint8_t* password,
                               size_t passwordlen,
                               uint8_t salt[TTTP_SALT_LENGTH],
                               uint8_t verifier[TTTP_VERIFIER_LENGTH]);
/* Converts a "private key" into a "public key", or rejects it.
   Steps to generate a private/public key pair for a server:
   # Get TTTP_PRIVATE_KEY_LENGTH random bytes of the best available quality
   # Call `tttp_generate_public_key`... if it rejects the private key, start
   over
   The public key need not be stored, it can be generated from a stored private
   key at startup using this function. `tttp_generate_public_key` will never
   reject a key it previously accepted, unless new restrictions on private keys
   are found.

   This function WILL reject a key consisting of all zeroes. The only use of
   such a key is to "opt out" of server authentication entirely. You probably
   don't want to do that. If you do, use 0000...0000 as your private key and
   0000...0001 as your public key.

   Returns: non-zero if the private key was valid and a public counterpart was
   generated; 0 if the private key was invalid and nothing was put into
   `public`

   You should provide a (non-returning, such as via an exception or longjmp)
   `fatal_callback` if you do not want the program to terminate because of a
   memory allocation failure. (If you don't mind that happening, feel free to
   pass NULL here.) */
int tttp_generate_public_key(void(*fatal_callback)(void*,const char*),
                             void* callback_data,
                             const uint8_t privatekey[TTTP_PRIVATE_KEY_LENGTH],
                             uint8_t publickey[TTTP_PUBLIC_KEY_LENGTH]);

/* Makes a "key fingerprint" for a key for display. Key fingerprints are
   intended to be used by HUMANS to verify the correctness of a key. */
void tttp_get_key_fingerprint(const uint8_t key[TTTP_KEY_LENGTH],
                              char buf[TTTP_FINGERPRINT_BUFFER_SIZE]);

/* Base64-encodes a key. */
void tttp_key_to_base64(const uint8_t key[TTTP_KEY_LENGTH],
                        char buf[TTTP_KEY_BASE64_BUFFER_SIZE]);

/* Attempts to extract a key from a Base64 stream. If there were not enough
   valid Base64 bytes, or if the key was >= N, returns 0. Otherwise, returns
   1. `key` is clobbered no matter what.

   Does NOT check for an all-zeroes or 0000..0001 key! You must perform this
   check yourself, depending on whether you're reading a private or public key
   (respectively)! */
int tttp_key_from_base64(const char* str,
                         uint8_t key[TTTP_KEY_LENGTH]);

/* Returns non-zero if the key is the 0000..0001 key (null public key), 0
   otherwise.*/
int tttp_key_is_null_public_key(const uint8_t key[TTTP_PUBLIC_KEY_LENGTH]);
/* Returns non-zero if the key is all zeroes (null private key), 0 otherwise.*/
int tttp_key_is_null_private_key(const uint8_t key[TTTP_PUBLIC_KEY_LENGTH]);

#if __cplusplus
}
#endif

#endif
