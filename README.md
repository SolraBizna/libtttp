This is a C99 library fully implementing both ends of the TTTP protocol, along with the specification for the protocol itself. TTTP is a protocol intended for remote display of games and other applications based on "textual art", such as NetHack or Dwarf Fortress. It provides the following benefits:

- Play a CPU-intensive game on a weak machine by running it on a strong machine
- Allow spectators to view your game, separately from the actual player(s)
- "Networked" multiplayer without state replication code

For way too much information, see [the protocol documentation](doc/protocol.html).

Users of TTTP applications need only install a TTTP client in order to make use of a server being run by someone else. By the time you read this, there should be a suitable client one repository over, in the `tttpclient` repository.

The API for the library itself is, _technically_, documented inside the headers. Decent documentation will be written as soon as anyone asks for it. The interface is clumsy and the code is ugly, but the overhead (of the library itself) is _incredibly_ small. Actual use of this library requires `lsx`, available one repository over.

I've been playing Dwarf Fortress over previous incarnations of this protocol for over five years, including over relatively crappy Internet links. The protocol's design was heavily informed by that experience. As for the crypto portions... I am not a cryptographer, but I spent over a month researching, attacking, refining, and improving upon the crypto before arriving at what is now documented. I hope it isn't terrible.
