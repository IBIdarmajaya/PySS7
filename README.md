# PySS7

*This is a work-in-stalled-progress. Attempting to be a Python implimentation of the SS7 / Sigtran stack. The eventual aim of this project, would be to allow working with SS7 links in a similar manner to sockets, where the lower layers are abstracted away.*

This library handles SS7 messaging used in telecommunications networks.

Combined with an SCTP stack we can support many of the common SS7 protocols in many different splits.

Each of the modules for each of the layers automatically handles all the nitty-gritty stuff so it can be used to transfer data to develop applications, rather than fiddling around with getting links up.

At the moment this entails support for:

* M2PA Message Transfer Part 2 (MTP2) - User Peer-to-Peer Adaptation Layer (M2PA) as described in [RFC4165](https://datatracker.ietf.org/doc/html/rfc4165)
