import socket
import sctp
import M2PA

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
                print(m2pa_header)
                connection.sendall(bytes.fromhex(data))
            else:
                # no more data -- quit the loop
                print ("no more data.")
                break
    finally:
        # Clean up the connection
        connection.close()   
