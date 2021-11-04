import socket
import sctp
import M2PA
import MTP3
from socket import htonl
import sys
import logtool
import logging
import yaml
import redis
with open("config.yaml", 'r') as stream:
    yaml_config = (yaml.safe_load(stream))


logtool.setup_logger('SCTP Handler', 'SCTP.log', 'DEBUG')
sctp_logger = logging.getLogger('SCTP Handler')
sctp_logger.info("SCTP_Handler_logger Log Initialised.")

sctp_logger.info("YAML config values: ")
for keys in yaml_config['sctp']:
    sctp_logger.info("\tKey: " + str(keys) + "\t Value: " + str(yaml_config['sctp'][keys]))

sock = sctp.sctpsocket_tcp(socket.AF_INET)

sock.bind((str(yaml_config['sctp']['bind_ip']), int(yaml_config['sctp']['bind_port'])))
sock.listen(1)

while True:  
    # wait for a connection
    sctp_logger.info('Waiting for an SCTP connection...')
    connection, client_address = sock.accept()

    try:
        # show who connected to us
        sctp_logger.info('connection from ' + str(client_address))
        # receive the data in small chunks and print it
        while True:
            data = connection.recv(999).hex()
            if data:
                # output received data
                stream_id = connection.get_streamid()
                sctp_logger.debug("Recieved raw SCTP data: %s" % str(data))
                
                #Decode M2PA Headers into a dict
                m2pa_header = M2PA.decode(data)
                
                #If the message is a Link Status Message then as a dirty trick we just echo back what we recieved and that brings the link up.
                if m2pa_header['message_type'] == 'Link Status':
                    sctp_logger.info("This is a link status message, so we'll echo it back.")
                    #Echo back Link Status Message to Sender
                    connection.set_streamid(stream_id)
                    connection.sctp_send(bytes.fromhex(data), ppid=htonl(5))
                    sctp_logger.info("no more data.")
                    continue

                sctp_logger.info("This has a payload in it, let's parse the payload!")
                mtp3_header = MTP3.decode(m2pa_header)
                if 'response' in mtp3_header:
                    sctp_logger.info("Got back a response on the MTP3 layer, sending that...")
                    for response in mtp3_header['response']:
                        connection.set_streamid(1)
                        connection.sctp_send(bytes.fromhex(response), ppid=htonl(5))                          
            else:
                # no more data -- quit the loop
                sctp_logger.info("no more data.")
                break
    finally:
        # Clean up the connection
        connection.close()
        sctp_logger.warning("Closing connection")
