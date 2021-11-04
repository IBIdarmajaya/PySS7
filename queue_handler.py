import yaml
with open("config.yaml", 'r') as stream:
    yaml_config = (yaml.safe_load(stream))
import logtool
import logging
import redis
import time
from socket import htonl
import socket
import sctp


logtool.setup_logger('Redis Queue Handler', 'Redis.log', 'DEBUG')
redis_queue_logger = logging.getLogger('Redis Queue Handler')
redis_queue_logger.info("redis_queue_logger Log Initialised.")

redis_store = redis.Redis(host=str(yaml_config['redis']['host']), port=str(yaml_config['redis']['port']), db=0)

def Add_Queue(message_queue_name, message_body):
    redis_queue_logger.info("Inserting into message_queue_name: " + str(message_queue_name) + " contents: " + str(message_body))
    redis_store.lpush(message_queue_name, message_body)

def Message_Queue_Monitor(connection, message_queue_name, wait_time):
    redis_queue_logger.info("Starting Message_Queue_Monitor() thread for connection " + str(connection) + " monitoring Redis Queue " + str(message_queue_name) + " every " + str(wait_time) + " seconds.")
    while True:
        time.sleep(wait_time)
        #sctp_logger.info("Reading from Redis time!")
        for i in range(0, redis_store.llen(message_queue_name)):
            msg_to_send = redis_store.lindex(message_queue_name, i)

            #Remove this key from Redis List
            redis_store.lrem(message_queue_name, 1, msg_to_send)

            redis_queue_logger.info("Sending outbound message from " + str(message_queue_name) + " ... value is " + str(msg_to_send))
            connection.set_streamid(1)
            connection.sctp_send(msg_to_send, ppid=htonl(5))
            redis_queue_logger.info("Sent!")
            