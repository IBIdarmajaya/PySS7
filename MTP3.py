import logtool
import logging
import queue_handler
logtool.setup_logger('MTP3 Handler', 'M2PA.log', 'DEBUG')
mtp3_logger = logging.getLogger('MTP3 Handler')
mtp3_logger.info("MTP3_Handler_logger Log Initialised.")

import MTP3_Decoder
import sys
import M2PA
def BinConvert(data, number_of_bits):
    return bin(int(str(data), 16))[2:].zfill(number_of_bits)

NetworkIndicator = {
    '00' : "International network",
    '01' : "Spare (for international use only)",
    '10' : "National network",
    '11' : "Reserved for national use",
}

ServiceIndicator = {
    '0000' : "Signalling network management messages",
    '0001' : "Signalling network testing and maintenance messages",
    '0010' : "Spare",
    '0011' : "SCCP",
    '0100' : "Telephone User Part",
    '0101' : "ISDN User Part",
    '0110' : "Data User Part (call and circuit-related messages)",
    '0111' : "Data User Part (facility registration and cancellation messages)",
    '1000' : "Reserved for MTP Testing User Part",
    '1001' : "Broadband ISDN User Part",
    '1010' : "Satellite ISDN User Part"
}

def FSN_Inc(input):
    if input == 16777215:
        return 1
    else:
        return input + 1


def Respond_MTP3_Management(m2pa_header, mtp3_header):
    mtp3_logger.info("Processing MTP3 Management Header")
    mtp3_logger.debug("MTP2 Header: " + str(m2pa_header))
    mtp3_logger.debug("MTP3 Header: " + str(mtp3_header))

    if (int(mtp3_header['mpt3_management']['message']) == 1) and (int(mtp3_header['mpt3_management']['message_group']) == 1):
        #Signaling Link-Check Message - Change to response then echo back what we recieved.
        mtp3_logger.info("MTP3 Management 'Signaling Link-Check Message' recieved. Generating echo response with swapped Point Codes......")

        #Common MTP3 Header
        mtp3_header_bin = MTP3_Decoder.MTP3_Routing_Indicator_Encode({'sio_data': {'network_indicator': 0, 'service_indicator' : 1}, \
            'routing_label': {'opc': mtp3_header['routing_label']['dpc'], 'dpc': mtp3_header['routing_label']['opc'], 'link_selector': 0}})
        
        mtp3_logger.debug("mtp3_header_bin is " + str(mtp3_header_bin))
        
        m2pa_header_new = {"payload" : str(mtp3_header_bin) + str(mtp3_header['payload']), "bsn" : 16777215, "fsn" : 0, "priority" : "09"}       #BSN at ends as this is first message
        m2pa_header_bin = M2PA.encode(m2pa_header_new)
        mtp3_header['response'].append(m2pa_header_bin + mtp3_header_bin + mtp3_header['payload'])    #Send SLTM / Signaling Link Test Message

    elif (int(mtp3_header['mpt3_management']['message']) == 2) and (int(mtp3_header['mpt3_management']['message_group']) == 1):
        #Signaling Link-Check Acknowledgement - Change to response then echo back what we recieved.
        mtp3_logger.info("MTP3 Management 'Signaling Link-Check Acknowledgement' recieved. Generating echo response with swapped Point Codes......")

        #Common MTP3 Header
        mtp3_header_bin = MTP3_Decoder.MTP3_Routing_Indicator_Encode({'sio_data': {'network_indicator': 0, 'service_indicator' : 1}, \
            'routing_label': {'opc': mtp3_header['routing_label']['dpc'], 'dpc': mtp3_header['routing_label']['opc'], 'link_selector': 0}})
        
        mtp3_logger.debug("mtp3_header_bin is " + str(mtp3_header_bin))
        
        m2pa_header_new = {"payload" : str(mtp3_header_bin) + str(mtp3_header['payload']), "bsn" : 16777215, "fsn" : 0, "priority" : "09"}       #BSN at ends as this is first message
        m2pa_header_bin = M2PA.encode(m2pa_header_new)
        mtp3_header['response'].append(m2pa_header_bin + mtp3_header_bin + mtp3_header['payload'])    #Send SLTM / Signaling Link Test Message

    elif (int(mtp3_header['mpt3_management']['message']) == 4) and (int(mtp3_header['mpt3_management']['message_group']) == 1):
        mtp3_logger.info("Transfer prohibited allowed - Link now in Service!")


    elif (int(mtp3_header['mpt3_management']['message']) == 7) and (int(mtp3_header['mpt3_management']['message_group']) == 1):
        mtp3_logger.info("Traffic restart allowed - Link now in Service!")


    else:
        mtp3_logger.error("No idea how to handle this")
        mtp3_logger.error(mtp3_header)
        return

    mtp3_logger.info("mtp3_header['response']: " + str(mtp3_header['response']))
    return mtp3_header


def decode(m2pa_header):
    mtp3_logger.info("Decoding MTP3")
    mtp3_header = MTP3_Decoder.MTP3_Decode(m2pa_header['payload'])
    mtp3_logger.info("mtp3_header value: " + str(mtp3_header))
    mtp3_header['payload'] = m2pa_header['payload'][10:]
    mtp3_header['response'] = []
    if mtp3_header['sio_data']['service_indicator'] == 0:
        mtp3_logger.info("MTP3 Signaling Network Mangement Message (SNM)")
        #MTP3 link is now up in Healthy state

        # #Generate some ISUP Traffic
        # #Common MTP3 Header
        # mtp3_header_bin = MTP3_Decoder.MTP3_Routing_Indicator_Encode({'sio_data': {'network_indicator': 0, 'service_indicator' : 5}, \
        #     'routing_label': {'opc': mtp3_header['routing_label']['dpc'], 'dpc': mtp3_header['routing_label']['opc'], 'link_selector': 0}})
        # isup_header_bin = "0e00011100000a03020907039040380982990a06031317734508007989"
        # m2pa_header_new = {"payload" : str(mtp3_header_bin) + str(isup_header_bin), "bsn" : 16777215, "fsn" : 0, "priority" : "09"}       #BSN at ends as this is first message
        # m2pa_header_bin = M2PA.encode(m2pa_header_new)
        # mtp3_header['response'].append(m2pa_header_bin + mtp3_header_bin + isup_header_bin)
        # mtp3_logger.info("Generated ISUP Body to send!")
        return

    if mtp3_header['sio_data']['service_indicator'] == 1:
        mtp3_logger.info("MTP3 Maintainence Message (MTN)")
        mpt3_management = {}
        mpt3_management['b1'] = BinConvert(mtp3_header['payload'][0:2], 8)
        mpt3_management['message_group'] = int(mpt3_management['b1'][4:8], 2)
        mpt3_management['message'] = int(mpt3_management['b1'][0:4], 2)
        mpt3_management['length'] = 2       #ToDo - Fix this
        mpt3_management['payload'] = mtp3_header['payload'][10:]
        mtp3_header['mpt3_management'] = mpt3_management
        return Respond_MTP3_Management(m2pa_header, mtp3_header)  


    if mtp3_header['sio_data']['service_indicator'] == 8:
        mtp3_logger.info("MTP3 Testing User Part (Ping)")
        mtp3_header_bin = MTP3_Decoder.MTP3_Routing_Indicator_Encode({'sio_data': {'network_indicator': 0, 'service_indicator' : 8}, \
             'routing_label': {'opc': mtp3_header['routing_label']['dpc'], 'dpc': mtp3_header['routing_label']['opc'], 'link_selector': 0}})
        mtp3_logger.info("Length of payload is " + str(len(mtp3_header['payload'])))
        if int(len(mtp3_header['payload'])/2) == 19:
            mtp3_logger.info("Incrimenting first bit and returning.")
            #If length is 19 bytes incriment the first bit and return
            mtp3_payload_bin = ''
            mtp3_payload_bin += str(int(mtp3_header['payload'][0:1])+1)
            mtp3_payload_bin += mtp3_header['payload'][1:]
        else:
            mtp3_logger.info("Returning as-is.")
            mtp3_payload_bin = mtp3_header['payload']
        m2pa_header_new = {"payload" : str(mtp3_header_bin) + str(mtp3_payload_bin), "bsn" : 16777215, "fsn" : 0, "priority" : "09"}       #BSN at ends as this is first message
        m2pa_header_bin = M2PA.encode(m2pa_header_new)
        #mtp3_header['response'].append(m2pa_header_bin + mtp3_header_bin + mtp3_payload_bin)        
        queue_handler.Add_Queue("isup_msg_queue", mtp3_header)
        return mtp3_header

    else:
        mtp3_logger.info("Contains upper layer protocol. Passing on for further processing.")
        return mtp3_header


class MTP3:
    def __init__(self) -> None:
        pass

    def decodePDU(self, data):
        mtp3_header = {}
        mtp3_header['payload'] = data
        mtp3_header['response'] = []
        if mtp3_header['sio_data']['service_indicator'] == 0:
            mtp3_logger.info("MTP3 Signaling Network Mangement Message (SNM)")
            #MTP3 link is now up in Healthy state
            return

        if mtp3_header['sio_data']['service_indicator'] == 1:
            mtp3_logger.info("MTP3 Maintainence Message (MTN)")
            mpt3_management = {}
            mpt3_management['b1'] = BinConvert(mtp3_header['payload'][0:2], 8)
            mpt3_management['message_group'] = int(mpt3_management['b1'][4:8], 2)
            mpt3_management['message'] = int(mpt3_management['b1'][0:4], 2)
            mpt3_management['length'] = 2       #ToDo - Fix this
            mpt3_management['payload'] = mtp3_header['payload'][10:]
            mtp3_header['mpt3_management'] = mpt3_management
            return Respond_MTP3_Management(m2pa_header, mtp3_header)  


        if mtp3_header['sio_data']['service_indicator'] == 8:
            mtp3_logger.info("MTP3 Testing User Part (Ping)")
            mtp3_header_bin = MTP3_Decoder.MTP3_Routing_Indicator_Encode({'sio_data': {'network_indicator': 0, 'service_indicator' : 8}, \
                'routing_label': {'opc': mtp3_header['routing_label']['dpc'], 'dpc': mtp3_header['routing_label']['opc'], 'link_selector': 0}})
            mtp3_logger.info("Length of payload is " + str(len(mtp3_header['payload'])))
            if int(len(mtp3_header['payload'])/2) == 19:
                mtp3_logger.info("Incrimenting first bit and returning.")
                #If length is 19 bytes incriment the first bit and return
                mtp3_payload_bin = ''
                mtp3_payload_bin += str(int(mtp3_header['payload'][0:1])+1)
                mtp3_payload_bin += mtp3_header['payload'][1:]
            else:
                mtp3_logger.info("Returning as-is.")
                mtp3_payload_bin = mtp3_header['payload']
            m2pa_header_new = {"payload" : str(mtp3_header_bin) + str(mtp3_payload_bin), "bsn" : 16777215, "fsn" : 0, "priority" : "09"}       #BSN at ends as this is first message
            m2pa_header_bin = M2PA.encode(m2pa_header_new)
            #mtp3_header['response'].append(m2pa_header_bin + mtp3_header_bin + mtp3_payload_bin)        
            queue_handler.Add_Queue("isup_msg_queue", mtp3_header)
            return mtp3_header

        else:
            mtp3_logger.info("Contains upper layer protocol. Passing on for further processing.")
            return mtp3_header


# m2pa_header = {}
# m2pa_header['payload'] = "0011d8040217"
# print(decode(m2pa_header))
