#ifndef TTTP_CLIENT_H
#define TTTP_CLIENT_H

#include "tttp_common.h"

#if __cplusplus
extern "C" {
#endif
#if 0
} /* make emacs happy */
#endif

typedef enum tttp_press_status {
  TTTP_PRESS, TTTP_RELEASE, TTTP_TAP
} tttp_press_status;

typedef struct tttp_client tttp_client;

/* Create a new tttp_client instance, using the given callbacks for IO.
   The tttp_client is in the "initialized" state.
   
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
   will be freed when the `tttp_client` is.
   If `fatal` is NULL or if it returns, the error will be printed to stderr
   and abort() will be called.
   After `fatal` is called, the ONLY legal operation on the this particular
   `tttp_client` is `tttp_client_fini`. Anything else will fail.

   foul: A callback used when a fatal error occurs that is NOT the fault of the
   calling program. As with `fatal`, the message is freed when the
   `tttp_client` is.
   If `foul` is NULL, the message will be printed to stderr. Regardless of its
   value, the connection will "die". */
tttp_client* tttp_client_init(void* data,
                              int(*receive)(void* data,
                                            void* buf, size_t bufsz),
                              int(*send)(void* data,
                                         const void* buf, size_t bufsz),
                              void(*flush)(void* data),
                              void(*fatal)(void* data,
                                           const char* why),
                              void(*foul)(void* data,
                                          const char* why));
/* Frees all memory associated with a given tttp_client*. */
void tttp_client_fini(tttp_client* self);
/* Change the data pointer used by the callbacks. */
void tttp_client_change_data_pointer(tttp_client* self, void* data);
/* Call as soon as possible to set the desired queue depth of a given
   `tttp_client` instance. The default is not to send a 'Queu' message,
   allowing the server to manage our queue however it sees fit.
   May be called at any time on a `tttp_client` in a positive state. */
void tttp_client_set_queue_depth(tttp_client* self, uint8_t depth);
/* Call as soon as possible to set the 'Scrn' parameters of a given
   `tttp_client` instance. The default is not to send a 'Scrn' message.
   May be called at any time on a `tttp_client` in a positive state. (For
   instance, you may want to call it with different values after the user
   resizes your window.)
   If either dimension of a pair is 0, the pair is taken as "unspecified".
   Will cause the connection to close with a fatal error if a 'FRAM' is
   received that is larger than either maximum dimension, if maximum dimensions
   are specified! */
void tttp_client_set_screen_params(tttp_client* self,
                                   uint16_t preferred_width,
                                   uint16_t preferred_height,
                                   uint16_t maximum_width,
                                   uint16_t maximum_height);
/* Call if you wish to query a server for a public key rather than using one on
   file. Returns a `tttp_handshake_result` value; `TTTP_HANDSHAKE_ADVANCE`
   means `public_key` and `servername` were filled out and you may proceed,
   `TTTP_HANDSHAKE_REJECTED` means the server did not provide a public key or
   server name, but you may still continue with the connection if you use a
   public key you have on file, or do not use authentication / encryption.

   Will call `foul` if the server provides an invalid public key.

   If `public_key` is filled out with all zeroes, except that the last byte is
   one, the server is not authenticating itself at all and a Scary Warning
   should be shown.

   `servername` and `servernamelen`, if not NULL, are filled in with a pointer
   to the server's human-readable name in UTF-8, if the server provides one, as
   well as its length. The pointer remains valid until the next `tttp_*` call
   on this client. If either is NULL, neither is altered! */
tttp_handshake_result tttp_client_query_server(tttp_client* self,
                                    uint8_t public_key[TTTP_PUBLIC_KEY_LENGTH],
                                               const uint8_t** servername,
                                               size_t* servernamelen);
/* Called while the `tttp_client` instance is either in the "initialized" state
   or the "flagged" state. Moves it to the "flag" state and provides a set of
   flags to try to negotiate.

   flags: Bitwise-OR combination of TTTP_FLAG_* values. A reasonable
   default is TTTP_FLAG_ENCRYPTION.

   If you want to negotiate encryption, you MUST use authentication. If you
   want to use authentication, you MUST provide a public key to
   `tttp_client_begin_handshake`. */
void tttp_client_request_flags(tttp_client* self,
                               uint32_t flags);
/* Operate the tttp_client instance in the "flag" state.
   Returns a TTTP_HANDSHAKE_* value. `TTTP_HANDSHAKE_ADVANCE` means you should
   call `tttp_client_begin_handshake` to proceed with the negotiated flags,
   `tttp_client_request_flags` to attempt further flag negotiation, or kill the
   connection if the server is insisting on flags you do not support. */
tttp_handshake_result tttp_client_pump_flags(tttp_client* self);
/* Returns the flags that were actually negotiated with the server. Can be
   called after tttp_client_pump_flags returns `TTTP_HANDSHAKE_ADVANCE`.
   If the return value contains any set bits that were not set in the last
   `tttp_client_request_flags` call, those bits are required on this server and
   the connection cannot proceed without them. */
uint32_t tttp_client_get_flags(tttp_client* self);
/* Move the `tttp_client` instance from the "flagged" state to the "auth" state
   (with non-NULL username) or the "verify" state (NULL username).

   username: The username, in UTF-8, to authenticate as. Empty string ("") for
   guest authentication. NULL for no authentication, in which case encryption
   will also be impossible, regardless of the flags.

   public_key: The public key that corresponds to this server. This should be
   a value that was returned by `tttp_client_query_server`, whether on this
   exact connection or on a previous connection to the same server. If this is
   NULL, username must also be NULL. */
void tttp_client_begin_handshake(tttp_client* self, const char* username,
                             const uint8_t public_key[TTTP_PUBLIC_KEY_LENGTH]);
/* Operate the tttp_client instance in the "auth" state.
   Returns a TTTP_HANDSHAKE_* value. `TTTP_HANDSHAKE_ADVANCE` means you should
   call `tttp_client_provide_password` to advance to the "verify" state. */
tttp_handshake_result tttp_client_pump_auth(tttp_client* self);
/* Call after `tttp_client_pump_auth` returns `TTTP_HANDSHAKE_ADVANCE` to
   provide a password to authenticate with. You should destroy the password
   as soon after this call as possible.
   Moves the `tttp_client` instance to the "verify" state. */
void tttp_client_provide_password(tttp_client* self,
                                  const void* password, size_t passlen);
/* Operate the `tttp_client` instance in the "verify" state.
   Returns a TTTP_HANDSHAKE_* value. `TTTP_HANDSHAKE_ADVANCE` means the
   instance has moved to the "complete" state, and the remaining
   `tttp_client_*` functions may be called.
   `TTTP_HANDSHAKE_REJECTED` means the authentication process failed; our key
   proof was rejected. This either means the password was wrong, or
   the public key being used was wrong. (In the latter case, if you used
   `tttp_client_assume_public_key`, you can believe you gave a wrong public
   key.) */
tttp_handshake_result tttp_client_pump_verify(tttp_client* self);
/* Should be called at some point before `tttp_client_pump` is called. Provides
   callbacks for `tttp_client_pump` to use when certain core messages are
   received.

   pltt: Called when a 'PLTT' message is received. See the protocol
   documentation for more on how to handle palettes. Will also be called
   automatically, with the default palette, if a 'FRAM' message is received
   without a 'PLTT' message coming first. (This means that the caller does not
   have to care about setting a default palette.)
   Note that this is always called with 16 colors, no matter how many were in
   the 'PLTT' packet.

   fram: Called when a 'FRAM' message is received. The message is fully
   decoded, including decompression and (if needed) XOR reversal. Whether the
   passed buffer is in the Unicode format or in the 8-bit planar format depends
   on whether we negotiated Unicode mode. The dirty_* parameters are a hint,
   the region that was actually modified this frame, which some clients will be
   able to use for incremental updates.

   kick: Called when a 'KICK' message is received. After this callback returns,
   the state will enter a dead state, similar to when a handshake is rejected.
   The passed value is always a UTF-8 string. */
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
                                                size_t len));
/* Sets the callback called when a 'Text' message is received. Whether the
   passed value is a UTF-8 string or an 8-bit-encoded string depends on
   whether our handshake resulted in Unicode mode. (May be NULL) */
void tttp_client_set_text_callback(tttp_client* self,
                                   void(*text)(void* data,
                                               const uint8_t* text,
                                               size_t len));
/* Sets the callback called when a 'Kyrp' message is received. (May be NULL) */
void tttp_client_set_kyrp_callback(tttp_client* self,
                                   void(*kyrp)(void* data,
                                               uint32_t delay,
                                               uint32_t interval));
/* Sets the callback called when a 'CDPT' message is received. You should also
   call `tttp_client_set_autocp437(client, 0)` if you provide a non-NULL
   callback and intend to do translation yourself.

   See the protocol documentation for the meaning of the `encoding` array. */
void tttp_client_set_cdpt_callback(tttp_client* self,
                                   void(*cdpt)(void* data,
                                               const uint32_t encoding[256]));
/* Sets the callback called when a 'Pon\0'/'Poff' message is received,
   indicating that the server is or is not (respectively) receptive to pastes.
   It is an error to send a paste when not between 'Pon\0' and 'Poff'. */
void tttp_client_set_paste_mode_callback(tttp_client* self,
                                         void(*pmode)(void* data,
                                                      int enabled));
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
void tttp_client_set_unknown_callback(tttp_client* self,
                                      void(*unknown)(void* data,
                                                     uint32_t msgid,
                                                     const uint8_t* msgdata,
                                                     uint32_t datalen));
/* Controls whether automatic translation to CP437 occurs. The default is to
   perform it; you should call this with a `0` parameter if you intend to
   support non-CP437 8-bit encodings in frame data and `Text` packets.
   It is an error to set this to non-zero if it is currently zero and the
   instance is in the "complete" state. */
void tttp_client_set_autocp437(tttp_client* self, int mode);
/* Operates the `tttp_client` instance in its "complete" state.
   Returns: 1 if the connection is still alive and kicking, 0 if it is over. */
int tttp_client_pump(tttp_client* self);
/* Begins a "paste". This must only be done when the pmode callback has been
   called with 1 as parameter, and not subsequently called with 0.
   During a paste, only `tttp_client_send_key` (involving KEY_ENTER/KEY_TAB)
   and `tttp_client_send_text` may be called. The paste will end when
   `tttp_client_end_paste` is called. */
void tttp_client_begin_paste(tttp_client* self);
/* Ends a "paste". */
void tttp_client_end_paste(tttp_client* self);

/* Send a key press, key release, or both to the server.

   status: TTTP_PRESS (for a press), TTTP_RELEASE (for a release), or TTTP_TAP
   (to send a press, then a release)

   scancode: A valid scancode. See the protocol documentation for a list of
   scancodes. Please read it carefully, then use "tttp_scancodes.h". */
void tttp_client_send_key(tttp_client* self, tttp_press_status status,
                          uint16_t scancode);
/* Send text input. Fairly self-explanatory. The text is UTF-8 if Unicode mode
   has been negotiated, the negotiated 8-bit encoding otherwise.

   text: The text to send. Note that this is NOT `const`; if encryption is in
   use, the buffer will be _overwritten_ with the encrypted data.

   textlen: The number of bytes of text to send. It is not legal to send an
   empty 'Text' message. */
void tttp_client_send_text(tttp_client* self, uint8_t* text, size_t textlen);
/* Send a mouse movement. Positions are absolute character cell coordinates,
   and MAY fall outside the window. */
void tttp_client_send_mouse_movement(tttp_client* self, int16_t x, int16_t y);
/* Send a mouse button status change. If you want a click to land in a certain
   character cell, and that character cell is not the location of the previous
   `tttp_client_send_mouse_movement` call, make one first. (In addition, most
   servers will ignore mouse button presses if a movement has not been sent
   first.)

   status: `TTTP_PRESS` (for a press), `TTTP_RELEASE` (for a release), or
   `TTTP_TAP` (to send a press, then a release)

   button: A `TTTP_*_MOUSE_BUTTON` macro, corresponding to the button that is
   involved. */
void tttp_client_send_mouse_button(tttp_client* self, tttp_press_status status,
                                   uint16_t button);
/* Send a scroll event, as from a mousewheel / multitouch screen. Positive `x`
   is right, positive `y` is up/away. One unit should correspond to a single
   detente on a mousewheel. */
void tttp_client_send_scroll(tttp_client* self, int8_t x, int8_t y);

/* Send a custom message. This is not validated; you can synthesize messages
   (such as 'ONES') that will subsequently result in incorrect library state.
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
void tttp_client_send_custom_message(tttp_client* self, uint32_t msgid,
                                     void* msgdata, size_t msglen);

#if __cplusplus
}
#endif

#endif
