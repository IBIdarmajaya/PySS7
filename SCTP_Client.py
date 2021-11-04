import sys
import socket
#Values to change / tweak
hostname = "10.0.1.24"                                                         #IP of Remote Diameter Host

import sctp
clientsocket = sctp.sctpsocket_tcp(socket.AF_INET)
print("Connecting to " + str(hostname))
try:
    clientsocket.connect((hostname,5050))
except Exception as e:
    print("Failed to connect to server - Error: " + str(e))
    sys.exit()
