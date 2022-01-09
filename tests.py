#Generic PyTest Test Cases
import logtool
import logging
import M2PA
import threading
import socket
import sctp
from socket import htonl
import time
logtool.setup_logger('M2PA Handler', 'M2PA.log', 'DEBUG')
testlogger = logging.getLogger('M2PA Handler')
import sys

m2pa_handler = M2PA.M2PA()


def fakeClient(data):
    #Fake SCTP client for testing server functions.
    #Takes Hex data to send as input and waits 500 miliseconds before sending data
    print("Starting fakeClient with data: " + str(data))
    time.sleep(0.5)
    sock_client = sctp.sctpsocket_tcp(socket.AF_INET)
    sock_client.connect(("127.0.0.2", 1027))

    print("Sending Message to server")

    #sock_client.sctp_send(msg=data)
    sock_client.sendall(bytes.fromhex(data))
    sock_client.shutdown(0)

    sock_client.close()

    return

def test_Server():
    #Setup Server Connection
    sock_server = sctp.sctpsocket_tcp(socket.AF_INET)

    #Setup Server Connection
    sock_server.bind(('127.0.0.2', 1027))
    sock_server.listen(1)

    #Get Fake Client Ready
    fakeClient_thread = threading.Thread(target=fakeClient, args=("01000b020000001400ffffff00ffffff00000001",))
    fakeClient_thread.start()    

    testlogger.info('Waiting for an SCTP connection...')
    server_connection, client_address = sock_server.accept()
    testlogger.info('connection from ' + str(client_address))
    # receive the data in small chunks and print it
    while True:
        data = server_connection.recv(999).hex()
        if data:
            testlogger.debug("Recieved raw SCTP data: %s" % str(data))
            #Close Socket
            sock_server.close()

            #Set expected values
            expected_dict = {'version': 1, 'spare': 0, 'message_class': 11, 'message_type': 2, 'message_length': 20, 'unused1': 0, 'bsn': 16777215, 'unused2': 0, 'fsn': 16777215, 'link_state': 1, 'payload': ''}
            testlogger.debug("Expected Dict is: " + str(expected_dict))

            #Decode M2PA Headers into a dict
            recieved_dict = m2pa_handler.decodePDU(data)
            testlogger.debug("Recieved Dict is: " + str(recieved_dict))

            #Test
            assert expected_dict == recieved_dict


