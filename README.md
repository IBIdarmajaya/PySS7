#PySS

Python SS7 MTP2 / MTP3 stack.

Redis is where we store the messages to send out.

The Client listens and comes up with Basic MTP2 / MTP3 responses.

To send messages using upper layers, you need to add the raw bytes to Redis, then they will be sent.