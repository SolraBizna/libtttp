#ifndef TTTP_SERVER_H
#define TTTP_SERVER_H

#include "tttp_common.h"

#if __cplusplus
extern "C" {
#endif
#if 0
} /* make emacs happy */
#endif

typedef struct tttp_server tttp_server;

/* Create a new tttp_server instance, using the given callbacks for IO.
   The tttp_server is in the "initialized" state.

   May return NULL, but only if malloc fails.

   data: An opaque pointer that is passed to all callbacks.

   receive: Attempt to receive data. Returns -1 if the connection has closed or
   another fatal error has occurred, 0 if there is no data currently waiting
   (optional), or the number of bytes actualy read. If a positive value is
   returned, the library assumes that all currently-available data has been
   received.
   If the connection errors out or closes, the library doesn't provide an easy
   way to detect that. Watch your own sockets.
   libtttp buffers data, typically reading about 1KB at a time.

   send: Attempt to send data. Returns -1 if the connection has closed or
   another fatal error has occurred, or 0 if the bytes were sent (or at least
   buffered) successfully.
   Many functions that call this one for small writes will ignore errors. You
   should ensure that subsequent `send`/`receive` calls will also return errors
   instead of doing something regrettable.
   The caller should be prepared to buffer as much data as we provide. The
   buffer will probably not get very full, unless you give excessive amounts
   of data to send...

   flush: (May be NULL) If you provide this callback, it will be called at the
   proper time to logically flush the send buffer. It is up to you to ensure
   that any data that remains in the buffer after this call gets flushed
   "eventually", not just the next time we call flush.
   This is only called as a hint; everything will work correctly as long as you
   flush the buffers "eventually".

   fatal: A callback used when a fatal usage error occurs. This will only be
   used when TTTP API functions are called in the wrong order, etc. `why`
   will be freed when the `tttp_server` is.
   If `fatal` is NULL or if it returns, the error will be printed to stderr
   and abort() will be called.
   After `fatal` is called, the ONLY legal operation on the this particular
   `tttp_server` is `tttp_server_fini`. Anything else will fail.

   foul: A callback used when a fatal error occurs that is NOT the fault of the
   calling program. As with `fatal`, the message is freed when the
   `tttp_server` is.
   If `foul` is NULL, the message will be printed to stderr. Regardless of its
   value, the connection will "die". */
tttp_server* tttp_server_init(void* data,
                              int(*receive)(void* data,
                                            void* buf, size_t bufsz),
                              int(*send)(void* data,
                                         const void* buf, size_t bufsz),
                              void(*flush)(void* data),
                              void(*fatal)(void* data,
                                           const char* why),
                              void(*foul)(void* data,
                                          const char* why));
/* Frees all memory associated with a given tttp_server*. */
void tttp_server_fini(tttp_server* self);
/* Change the data pointer used by the callbacks. */
void tttp_server_change_data_pointer(tttp_server* self, void* data);
/* Operate the `tttp_server` instance in the "initialized" state.
   Returns a TTTP_HANDSHAKE_* value. `TTTP_HANDSHAKE_ADVANCE` means you should
   either call `tttp_server_accept_no_auth`, `tttp_server_begin_auth`, or
   `tttp_server_reject_auth`.

   flagfilter: Callback used when the client requests a certain set of feature
   flags. Should return the subset that are acceptable to your server.
   It is an error if the return value contains any 1 bits that were not 1 in
   the parameter.
   Note that this may be called more than once (if a client tries to negotiate
   a specific restricted set of feature flags). Do not use this callback to
   make allocation decisions, etc. Instead, wait until
   `tttp_server_pump_beginning` returns `TTTP_HANDSHAKE_ADVANCE`, and use
   `tttp_server_get_flags`.

   servername/servernamelen: If servername is not NULL, we will respond to
   queries with our public key and the given server name. If it is NULL, we
   will give a negative response to queries, keeping our public key from being
   automatically added.

   username: Output parameter, written with a pointer to the username.
   Will be NULL if authentication was not requested. Will be non-NULL if
   authentication was requested, even if the username was empty.
   This pointer will only remain valid until the next call to a `tttp_server`
   method that reads a message, or a call to `tttp_server_fini`. If you need
   the username for longer than this, copy it out.

   usernamelen: Output parameter, written with the length of the username.
   Will be zero if the username was empty OR if authentication was not
   requested. (Check whether `username` was NULL to distinguish these two
   cases.)

   private_key/public_key: A valid public/private key pair, where the public
   key was given by `tttp_generate_public_key` and the private key was vetted
   by it. If you want to opt out of server authentication, provide all
   zeroes for private_key and all zeroes with the last byte 1 for public_key.*/
tttp_handshake_result tttp_server_pump_beginning(tttp_server* self,
                                               uint32_t(*flagfilter)(uint32_t),
                            const uint8_t private_key[TTTP_PRIVATE_KEY_LENGTH],
                            const uint8_t public_key[TTTP_PUBLIC_KEY_LENGTH],
                                                 const uint8_t* servername,
                                                 size_t servernamelen,
                                                 uint8_t** username,
                                                 size_t* usernamelen);
/* Returns the flags that were actually negotiated with the client. Can only be
   called after `tttp_server_pump_beginning` returns `TTTP_HANDSHAKE_ADVANCE`.
*/
uint32_t tttp_server_get_flags(tttp_server* self);
/* Accept a connection on which no authentication was used. This moves the
   server to the "complete" state. Note that whether `TTTP_FLAG_ENCRYPTION`
   was in the flags or not, encryption will NOT be enabled on a
   non-authenticated connection! (In addition, after calling this function,
   `tttp_server_get_flags` will never include `TTTP_FLAG_ENCRYPTION`,
   regardless of what was negotiated. */
void tttp_server_accept_no_auth(tttp_server* self);
/* Reject a connection on the grounds of incorrect authentication. This
   includes:
   # Non-authenticated connection, where authentication is required.
   # Authentication attempt with empty username, where guest authentication is
   not allowed.
   # Authentication attempt with non-empty username, where this software does
   not support users.
   # Authentication attempt without encryption, where encryption is required
   for the entire server.
   # Authentication attempt where verification failed.
   # Authentication attempt for a username that is not registered. (only AFTER
   `tttp_server_pump_auth` returns `TTTP_HANDSHAKE_ADVANCE`!)
   It is weakly recommended not to include:
   # Authenticated connection without encryption, where encryption is required
   for this particular user. (This difference in behavior can be used to
   determine that the particular user exists; caveat admin.)
   This should not include:
   # Authenticated connection with a username that is banned, or locked out.
   (Kick the client after authentication instead.)
   Calling this function ends the connection. */
void tttp_server_reject_auth(tttp_server* self);
/* Proceed with a connection on which authentication is being used.
   This moves the server to the "auth" state.

   salt: 32 bytes of random data, specific to that user. If the user is
   registered (or is a guest with guest authentication enabled), this should be
   the salt for that user's password verifier. If the user is not registered,
   this should be random bytes which are the same for the same username on
   subsequent attempts, but different for different usernames, and different
   for different servers. One way to accomplish this is to store a random
   nonce when the server is first set up, and use H(nonce, username) here.
   (If you do that, the nonce must be cryptographically random, or it can be
   determined by an attacker in seconds. And regardless, try to prevent timing
   attacks...such as by always calculating a "fake salt" for a user, and merely
   discarding it if they are real.)

   verifier: The (precomputed) verifier for this user (g^H(salt,password)).
   Provide garbage data if there is no such registered user. */
void tttp_server_begin_auth(tttp_server* self,
                            const uint8_t salt[TTTP_SALT_LENGTH],
                            const uint8_t verifier[TTTP_VERIFIER_LENGTH]);
/* Operate the `tttp_server` in the "auth" state.
   Returns a TTTP_HANDSHAKE_* value. `TTTP_HANDSHAKE_ADVANCE` means you may
   call `tttp_server_reject_auth` (if it was a nonexistent user) or
   `tttp_server_accept_auth`. `TTTP_HANDSHAKE_REJECTED` means you must call
   `tttp_server_reject_auth`. (Please don't forget about the
   `TTTP_HANDSHAKE_ADVANCE` case when the username isn't valid...) */
tttp_handshake_result tttp_server_pump_auth(tttp_server* self);
/* Accept a connection on which the authentication check has passed. This puts
   the `tttp_server` into the "complete" state. */
void tttp_server_accept_auth(tttp_server* self);
/* Must be called at some point before `tttp_server_pump` is called.
   Sets the callback called whenever a 'ONES' message is received. The client
   sends these messages whenever it receives a 'FRAM'. Once this message is
   received, you can proceed under the assumption that a frame has arrived.
   (Please beware of a hypothetical client that sends nothing but ONESONESONES
   ONESONESONESONESONESONES...) */
void tttp_server_set_ones_callback(tttp_server* self,
                                   void(*ones)(void* data));
/* Sets the callback called whenever a 'Queu' message is received, indicating
   the desired number of frames deep the in-flight frame queue should be. 0
   indicates the default behavior shold be used. (You are free to ignore this
   value, or cap it at a maximum.) */
void tttp_server_set_queue_depth_callback(tttp_server* self,
                                          void(*queue_depth)(void* data,
                                                             uint8_t depth));
/* Sets the callback called whenever a 'Scrn' message is received, indicating
   the preferred values for screen size and hard limits for same. If either
   dimension of a pair is 0, the pair is unspecified. Interpretation of these
   values is up to the server, but it is an error to send a 'FRAM' message with
   dimensions larger than the maximum specified here. (At least 80x24 is always
   guaranteed.) */
void tttp_server_set_screen_params_callback
(tttp_server* self, void(*screen_params)(void* data,
                                         uint16_t preferred_width,
                                         uint16_t preferred_height,
                                         uint16_t maximum_width,
                                         uint16_t maximum_height));
/* Sets the callback called whenever a 'Kp__'/'Kr__' message is received. The
   client sends these messages in response to keyboard keys being pressed/
   released. See "tttp_scancodes.h" and the protocol documentation for more
   information. */
void tttp_server_set_key_callback(tttp_server* self,
                                  void(*key)(void* data,
                                             int pressed,
                                             uint16_t scancode));
/* Sets the callback called when a 'Text' message is received. Whether the
   passed value is a UTF-8 string or an 8-bit-encoded string depends on
   whether our handshake resulted in Unicode mode. (May be NULL) */
void tttp_server_set_text_callback(tttp_server* self,
                                   void(*text)(void* data,
                                               const uint8_t* text,
                                               size_t len));
/* Sets the callback called when a 'Mous' message is received. This indicates
   a new absolute mouse location, in character cells. */
void tttp_server_set_mouse_motion_callback(tttp_server* self,
                                           void(*mous)(void* data,
                                                       int16_t x, int16_t y));
/* Sets the callback called whenever a 'Mp__'/'Mr__' message is received. The
   client sends these messages in response to mouse buttons being pressed/
   released. `button` is a TTTP_*_MOUSE_BUTTON value. It is permitted to ignore
   these before the first 'Mous' message is received. */
void tttp_server_set_mouse_button_callback(tttp_server* self,
                                           void(*mbtn)(void* data,
                                                       int pressed,
                                                       uint16_t button));
/* Sets the callback called when a 'Scrl' message is received. This indicates
   a scrolling input, such as a mouse wheel or a multitouch device. Positive
   `x` is right, positive `y` is up/away. One unit corresponds to a single
   detente on a mousewheel. */
void tttp_server_set_scroll_callback(tttp_server* self,
                                     void(*scrl)(void* data,
                                                 int8_t x, int8_t y));
/* Sets the callbacks called when the client begins (`pbeg`) or ends (`pend`) a
   paste. During a paste, only key messages (involving enter/tab) and text
   messages will be received. Pastes will never be received unless you call
   `tttp_server_allow_paste`. */
void tttp_server_set_paste_callbacks(tttp_server* self,
                                     void(*pbeg)(void* data),
                                     void(*pend)(void* data));
/* Sets the callback called when a message with an unknown identifier is
   received. (May be NULL)
   Unlike most other callbacks, this will be called WHENEVER a message with
   unknown identifier is received, in any stage. Other callbacks are only
   called in appropriate stages. If a message would be "known" in another
   stage, but isn't "known" in the current stage, this callback is called!
   If this callback is NULL, any unknown critical message results in an error.
   If it is not NULL, ALL unknown messages get sent through the callback, and
   YOU must raise an error if it is critical and you don't handle it! (A
   message is critical when `msgid & 0x00200000` is nonzero.) */
void tttp_server_set_unknown_callback(tttp_server* self,
                                      void(*unknown)(void* data,
                                                     uint32_t msgid,
                                                     const uint8_t* msgdata,
                                                     uint32_t datalen));

/* Operates the tttp_server instance in the "complete" state.
   Returns: 1 if the connection is still alive and kicking, 0 if it is over. */
int tttp_server_pump(tttp_server* self);

/* Sends a 'Pon\0' message to the client, indicating that pasting is currently
   possible. Pastes will be ignored unless this is called. You should not call
   this unless the cursor is *currently* inside a text field, or some logically
   equivalent situation; when pasting is allowed, the client will process and
   suppress the inputs that lead to a paste, in a platform-specific way!

   It is NOT an error to call this when pasting is already allowed, and such a
   call will NOT result in a spurious 'Pon\0' message being sent. However, no
   matter how many times `tttp_server_allow_paste` is called, a single
   `tttp_server_forbid_paste` will disable pasting. The calls are not counted.
*/
void tttp_server_allow_paste(tttp_server* self);
/* Sends a 'Poff' message to the client, indicating that pasting is no longer
   possible.

   It is NOT an error to call this when pasting is already forbidden, and such
   a call will NOT result in a spurious 'Poff' message being sent. */
void tttp_server_forbid_paste(tttp_server* self);
/* Send a palette to the client. If this is never called, the default palette
   will be assumed.

   The protocol is fairly lenient as to what constitutes a valid 'PLTT'
   message, but the library is stricter. You must either specify no colors at
   all (to revert to the default palette) or between 2 and 16 colors.

   colors: An array of sRGB colors in RGB order.

   colorcount: A number between 2 and 16 inclusive, indicating how many colors
   are specified. */
void tttp_server_send_palette(tttp_server* self,
                              const uint8_t* colors, uint8_t colorcount);
/* Sends a complete frame to the client.

   width: The width of the frame, in character cells. Must be greater than 0,
   and should not be greater than `maximum_width` from a 'Scrn' message.

   height: The height of the frame, in character cells. Must be greater than 0,
   and should not be greater than `maximum_height` from a 'Scrn' message.

   framedata: The frame data to send. Whether it is in the packed Unicode
   format or the planar 8-bit format depends on whether Unicode mode is in use.
*/
void tttp_server_send_frame(tttp_server* self,
                            uint16_t width, uint16_t height,
                            const uint8_t* framedata);
/* Destroys the currently stored frame on the client, so that the next frame
   will not be XOR'ed against previous data. This is a slight optimization if
   used just before a frame that mostly destroys information from the previous
   frame without adding much (such as a cleared screen). */
void tttp_server_destroy_previous_frame(tttp_server* self);
/* Resets all post-handshake connection state. The client will discard its
   framebuffer, forget any previous key repeat setting and custom encoding, and
   resend 'Queu'/'Scrn' if it cares about them. YOU are responsible for
   forgetting any relevant client-side state.

   After calling this, you should call `tttp_server_pump_reset` until it
   returns `TTTP_HANDSHAKE_ADVANCE`.
 
   This is useful when implementing a proxy. */
void tttp_server_reset(tttp_server* self);
/* Operates the `tttp_server` instance during a reset. Ignores all client
   messages until it receives a 'Rack'. Returns `TTTP_HANDSHAKE_ADVANCE` once
   the reset is complete. */
tttp_handshake_result tttp_server_pump_reset(tttp_server* self);
/* Explicitly kill a connection, with an optional human-readable message as to
   why the connection is being killed. The message is always in UTF-8,
   regardless of Unicode mode.
   (Naturally, after calling this function, the only valid function to call is
   `tttp_server_fini`) */
void tttp_server_kick(tttp_server* self, uint8_t* msg, size_t msglen);
/* Send a key repeat hint, indicating that you want key repeats to begin after
   a certain specific `delay` and repeat every `interval` thereafter. The time
   unit is the millisecond. Either value being zero means "no repeats", and
   either being all ones (0xFFFFFFFF) means "default behavior".
   This is only a hint. Clients are free to ignore this hint. */
void tttp_server_request_key_repeat(tttp_server* self,
                                    uint32_t delay, uint32_t interval);
/* Send human-readable status text. Clients are not required to make this text
   visible, and if they do, they may do it in a modal message box of some sort.

   The text is UTF-8 if Unicode mode has been negotiated, the negotiated 8-bit
   encoding otherwise.

   text: The text to send. Note that this is NOT `const`; if encryption is in
   use, the buffer will be _overwritten_ with the encrypted data.

   textlen: The number of bytes of text to send. It is not legal to send an
   empty 'Text' message. */
void tttp_server_send_text(tttp_server* self, uint8_t* text, size_t textlen);
/* Set the 8-bit encoding currently in use with a 'CDPT' message. It is an
   error to call this on a connection where Unicode mode is active. Future
   frames will use this encoding, and any previous frame will be destroyed.

   See the protocol documentation for the meaning of the `encoding` array. */
void tttp_server_send_cdpt(tttp_server* self, const uint32_t encoding[256]);
/* Send a custom message. This is not validated; you can synthesize messages
   (such as 'FRAM') that will subsequently result in incorrect library state.
   Best to stick to nonstandard messages, probably.

   Unlike most functions, this one does not require a certain state. (It still
   cannot be called after an error has occurred.)

   msgid: The message identifier to send. Should be a multi-character constant.
   See the protocol documentation for restrictions. The library will set or
   clear the "data present" bit as needed.

   msgdata: The data to send. May be NULL if msglen is 0. Note that this is NOT
   `const`; if encryption is in use, the buffer will be _overwritten_ with the
   encrypted data.

   msglen: The amount of data to send. If zero, no data will be sent. Bear in
   mind that in the current version of the protocol no more than
   TTTP_MAX_MESSAGE_LEN bytes (about 2.1MB) may be sent; this function will
   call `fatal` if you try. */
void tttp_server_send_custom_message(tttp_server* self, uint32_t msgid,
                                     void* msgdata, size_t msglen);

#if __cplusplus
}
#endif

#endif
