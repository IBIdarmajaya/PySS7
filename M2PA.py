
import logtool
import logging
logtool.setup_logger('M2PA Handler', 'M2PA.log', 'DEBUG')
m2pa_logger = logging.getLogger('M2PA Handler')
m2pa_logger.info("M2PA_Handler_logger Log Initialised.")

from socket import EWOULDBLOCK
def BinConvert(data, number_of_bits):
    return bin(int(str(data), 16))[2:].zfill(number_of_bits)

Link_Status_Alignment = "01000b020000001400ffffff00ffffff00000001"
Link_Status_Emergency = "01000b020000001400ffffff00ffffff00000003"
Link_Status_Normal = "01000b020000001400ffffff00ffffff00000002"

LinkStatus = {'1':"Alignment", '2' : "Proving Normal", '3' : "Proving Emergency", '4':"Ready", '5':"Processor Outage", '6':"Processor Recovered", '7':"Busy", '8':"Busy Ended", '9':"Out of Service"}
MessageClass = {'0b' : "M2PA"}
MessageType = {'1':"User Data", '2' : "Link Status"}

def decode(data):
    m2pa_logger.info("Decoding M2PA data: " + str(data))
    try:
        m2pa_header = {}
        position = 0
        m2pa_header['version'] = data[position:position+2]
        position = position+2
        m2pa_header['spare'] = data[position:position+2]
        position = position+2
        m2pa_header['message_class'] = data[position:position+2]
        m2pa_header['message_class'] = MessageClass[str(m2pa_header['message_class'])]
        position = position+2
        m2pa_header['message_type'] = data[position:position+2]
        m2pa_header['message_type'] = MessageType[str(int(m2pa_header['message_type']))]
        position = position+2
        m2pa_header['message_length'] = data[position:position+8]
        m2pa_header['message_length'] = int(m2pa_header['message_length'], 16)
        position = position+8
        m2pa_header['unused1'] = data[position:position+2]
        position = position+2
        m2pa_header['bsn'] = int(str(data[position:position+6]), 16)
        position = position+6
        m2pa_header['unused2'] = data[position:position+2]
        position = position+2
        m2pa_header['fsn'] = int(str(data[position:position+6]), 16)
        position = position+6
        if m2pa_header['message_type'] == "Link Status":
            m2pa_header['link_status'] = data[position:position+8]
            m2pa_header['link_status'] = LinkStatus[str(int(m2pa_header['link_status']))]
            position = position+8
            m2pa_header['payload'] = data[position:]
        elif m2pa_header['message_type'] == "User Data":
            m2pa_header['priority'] = data[position:position+2]
            position = position+2
            m2pa_header['payload'] = data[position:]
    except Exception as E:
        m2pa_logger.error("Stumbled processing M2UA Header: " + str(data))
        m2pa_logger.error(E)
        m2pa_logger.error(m2pa_header)
        m2pa_logger.error("Stalled Position: " + str(position))
        m2pa_logger.error("Stalled Data Remaining: " + str(data[position:]))
        raise "Error processing M2UA Header"
    m2pa_logger.info("Decoded - Output " + str(m2pa_header))
    return m2pa_header


def encode(m2pa_header):
    m2pa_logger.info("Encoding M2PA header with inputs " + str(m2pa_header))
    hexout = ''
    hexout+= '01' + '00' + '0b' + '01' #Version 1, M2PA carrying user data
    # if 'length' in m2pa_header:
    #     overall_length = m2pa_header['length']
    # else:
    overall_length = 17 + (len(m2pa_header['payload'])/2)
    if (overall_length % 2) == 0:
        m2pa_logger.debug("overall_length is even number, passing")
        pass
    else:
        m2pa_logger.debug("overall_length is odd number, rouding up")
        overall_length+= 1
    m2pa_logger.debug("overall length should be " + str(overall_length))
    hexout+= format(int(overall_length), 'x').zfill(8)    #Length encoded onto 4 bits
    hexout+= '00'       #Unused bit
    hexout+= format(m2pa_header['bsn'], 'x').zfill(6)    #Backwards Sequence Number
    hexout+= '00'       #Unused bit
    hexout+= format(m2pa_header['fsn'], 'x').zfill(6)     #Forwards Sequence Number
    hexout+= str(m2pa_header['priority'])
    m2pa_logger.info("Final output is " + str(hexout))
    return hexout

#m2pa_header = {"payload" : "0111d8040211201112", "bsn" : 16777215, "fsn" : 0, "priority" : "09"}
#encode(m2pa_header)
###01000b010000001600000001000000010613480406 #Desired
###01000b010000001a00ffffff0000000009


#print(decode("01000b010000001a00ffffff00000000090111d8040211201112"))
