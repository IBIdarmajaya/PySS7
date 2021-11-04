import logging
import yaml
import redis
import sys
with open("config.yaml", 'r') as stream:
    yaml_config = (yaml.safe_load(stream))

def setup_logger(logger_name, log_file, level=logging.DEBUG):
    l = logging.getLogger(logger_name)
    formatter = logging.Formatter('%(asctime)s  %(name)s \t %(levelname)s \t %(message)s')
    #fileHandler = logging.FileHandler(log_file, mode='a+')
    #fileHandler.setFormatter(formatter)
    streamHandler = logging.StreamHandler()
    streamHandler.setFormatter(formatter)
    l.setLevel(level)
    #l.addHandler(fileHandler)
    l.addHandler(streamHandler)



logging.debug("Redis support enabled")
import redis
import json
import pickle
redis_store = redis.Redis(host=str(yaml_config['redis']['host']), port=str(yaml_config['redis']['port']), db=0)
try:
    redis_store.incr('restart_count')
    if yaml_config['redis']['clear_stats_on_boot'] == True:
        logging.debug("Clearing all Redis keys")
        redis_store.flushall()
    else:
        logging.debug("Leaving prexisting Redis keys")
    #Clear ActivePeerDict
    redis_store.delete('ActivePeerDict')
    logging.info("Connected to Redis server")
except:
    logging.fatal("Failed to connect to Redis server - Aborting")
    sys.exit()
        
#function for handling incrimenting Redis counters with error handling
def RedisIncrimenter(name):
    if yaml_config['redis']['enabled'] == True:
        try:
            redis_store.incr(name)
        except:
            logging.error("failed to incriment " + str(name))

def RedisStore(key, value):
    if yaml_config['redis']['enabled'] == True:
        try:
            redis_store.set(key, value)
        except:
            logging.error("failed to set Redis key " + str(key) + " to value " + str(value))    

def RedisGet(key):
    if yaml_config['redis']['enabled'] == True:
        try:
            return redis_store.get(key)
        except:
            logging.error("failed to set Redis key " + str(key))    



def RedisStoreDict(key, value):
    if yaml_config['redis']['enabled'] == True:
        try:
            redis_store.set(str(key), pickle.dumps(value))
        except:
            logging.error("failed to set Redis dict " + str(key) + " to value " + str(value))    

def RedisGetDict(key):
    if yaml_config['redis']['enabled'] == True:
        try:
            read_dict = redis_store.get(key)
            return pickle.loads(read_dict)
        except:
            logging.error("failed to hmget Redis key " + str(key))    

