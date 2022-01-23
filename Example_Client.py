import logtool
import logging
import M2PA
import MTP3_Decoder
import threading
import socket
import sctp
from socket import htonl
import time
logtool.setup_logger('M2PA Handler', 'M2PA.log', 'DEBUG')
testlogger = logging.getLogger('M2PA Handler')
import sys

m2pa_handler = M2PA.M2PA()



#Setup Server Connection
sock_server = sctp.sctpsocket_tcp(socket.AF_INET)

#Setup Server Connection
sock_server.bind(('10.0.1.252', 1027))
sock_server.listen(1)

testlogger.info('Waiting for an SCTP connection...')
server_connection, client_address = sock_server.accept()
testlogger.info('connection from ' + str(client_address))
# receive the data in small chunks and print it
while True:
    data = server_connection.recv(999).hex()
    if data:
        testlogger.debug("Recieved raw SCTP data: %s" % str(data))

        #Decode M2PA Headers into a dict
        m2pa_dict = m2pa_handler.decodePDU(data)
        data = m2pa_handler.handle(data)

        #Handle any MTP3 Payload Data
        if 'payload' in m2pa_dict:
            testlogger.debug("Got MTP3 Payload: " + str(m2pa_dict['payload']))
            mtp3_dict = MTP3_Decoder.MTP3_Decode(str(m2pa_dict['payload']))
            testlogger.debug(mtp3_dict)
        #Send response
        server_connection.sendall(bytes.fromhex(data))
        


        
