import socket
import sctp
import M2PA
import MTP3
from socket import htonl
import sys

#VMNet2
host = '192.168.212.1'
port = 1026



sock = sctp.sctpsocket_tcp(socket.AF_INET)

sock.bind((host, port))
sock.listen(1)

while True:  
    # wait for a connection
    print ('waiting for a connection')
    connection, client_address = sock.accept()

    try:
        # show who connected to us
        print('connection from', client_address)
        # receive the data in small chunks and print it
        while True:
            data = connection.recv(999).hex()
            if data:
                # output received data
                print ("Data: %s" % str(data))
                m2pa_header = M2PA.decode(data)
                #print(m2pa_header)
                if m2pa_header['message_type'] == 'Link Status':
                    #print("This is a link status message, so we'll echo it back.")
                    connection.sctp_send(bytes.fromhex(data), ppid=htonl(5))
                else:
                    #print("This has a payload in it, let's parse the payload!")
                    print(m2pa_header['payload'])
                    mtp3_header = MTP3.decode(m2pa_header['payload'])
                    if 'response' in mtp3_header:
                        print("Got back a response on the MTP3 layer, sending that...")
                        connection.sctp_send(bytes.fromhex(mtp3_header['response']), ppid=htonl(5))
            else:
                # no more data -- quit the loop
                print ("no more data.")
                break
    finally:
        # Clean up the connection
        connection.close()   
