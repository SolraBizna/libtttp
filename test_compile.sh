#!/bin/sh

gcc -x c -pedantic -std=c99 -Wall -Werror -Wno-multichar -I../lsx/include tttp_common.c -c -o /dev/null
gcc -x c -pedantic -std=c99 -Wall -Werror -Wno-multichar -I../lsx/include tttp_client.c -c -o /dev/null
gcc -x c -pedantic -std=c99 -Wall -Werror -Wno-multichar -I../lsx/include tttp_server.c -c -o /dev/null
gcc -x c -pedantic -std=c99 -Wall -Werror -Wno-multichar -I../lsx/include tttp_scancodes.c -c -o /dev/null
