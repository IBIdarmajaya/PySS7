import logtool
import logging
import queue_handler
logtool.setup_logger('MTP3 Handler', 'M2PA.log', 'DEBUG')
mtp3_logger = logging.getLogger('MTP3 Handler')
mtp3_logger.info("MTP3_Handler_logger Log Initialised.")

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
        self.mtp3_header = {}
        pass

    def service_indicator_offset(self, sio_dict):
        #Add NetworkIndicator Description
        sio_dict['NetworkIndicator_Description'] = NetworkIndicator[str(sio_dict['network_indicator'])]
        #Add ServiceIndicator Description
        ServiceIndicator_padded = str(sio_dict['ServiceIndicator']).zfill(4)
        sio_dict['ServiceIndicator_Description'] = ServiceIndicator[ServiceIndicator_padded]
        self.mtp3_header['sio'] = sio_dict


    def routing_label(self, routing_label):
        self.mtp3_header['routing_label'] = dict(routing_label)

    def encodePDU(self):
        hexout = ''
        
        #Set Service Indicator Octet
        sio_binary = ''
        sio_binary += bin(int(self.mtp3_header['sio']['network_indicator']))[2:].zfill(2)
        sio_binary += "00"      #Spare Bits
        sio_binary += bin(self.mtp3_header['sio']['ServiceIndicator'])[2:].zfill(2)
        hexout += sio_binary

        #Set Routing Label
        #We are using 14 bit point codes. This would need to change for ANSI support....
        opc_binary = format(self.mtp3_header['routing_label']['opc'], 'b').zfill(14)
        dpc_binary = format(self.mtp3_header['routing_label']['dpc'], 'b').zfill(14)
        mtp3_logger.debug("opc_binary: " + str(opc_binary))
        routing_label_byte_1_binary = dpc_binary[6:]
        routing_label_byte_2_binary = ''
        routing_label_byte_2_binary += opc_binary[12:14]
        routing_label_byte_2_binary += dpc_binary[0:6]
        routing_label_byte_3_binary = opc_binary[4:12]        
        routing_label_byte_4_binary = ''
        routing_label_byte_4_binary += format(self.mtp3_header['routing_label']['sls'], 'b').zfill(4)
        routing_label_byte_4_binary += opc_binary[0:4]
        mtp3_logger.debug("routing_label_byte_1_binary: " + str(routing_label_byte_1_binary))
        mtp3_logger.debug("routing_label_byte_2_binary: " + str(routing_label_byte_2_binary))
        mtp3_logger.debug("routing_label_byte_3_binary: " + str(routing_label_byte_3_binary))
        mtp3_logger.debug("routing_label_byte_4_binary: " + str(routing_label_byte_4_binary))
        
        routing_label_byte_1_hex = format(int(routing_label_byte_1_binary, 2), 'x')
        routing_label_byte_2_hex = format(int(routing_label_byte_2_binary, 2), 'x')
        routing_label_byte_3_hex = format(int(routing_label_byte_3_binary, 2), 'x')
        routing_label_byte_4_hex = format(int(routing_label_byte_4_binary, 2), 'x')
        routing_label_hex = routing_label_byte_1_hex + routing_label_byte_2_hex + routing_label_byte_3_hex + routing_label_byte_4_hex
        mtp3_logger.debug("routing_label_hex: " + str(routing_label_hex))
        hexout += routing_label_hex
        
        mtp3_logger.debug(hexout)
        return hexout
        

    def decodePDU(self, data):
        mtp3_logger.info("Decoding MTP3 data: " + str(data))
        try:
            mtp3_header = {}
            position = 0

            #Service Indicator Octet
            sio_raw = data[position:2]
            position += 2
            sio_binary = bin(int(sio_raw, 16))[2:].zfill(8)
            sio_dict = {}
            sio_dict['network_indicator'] = sio_binary[0:2]
            sio_dict['spare'] = sio_binary[2:4]
            sio_dict['ServiceIndicator'] = int(sio_binary[4:8])
            self.service_indicator_offset(sio_dict)

            #Routing Label
            routing_label_dict = {}
            routing_label_raw = data[position:16]
            position += 8
            mtp3_logger.debug(routing_label_raw)

            routing_label_byte_1 = routing_label_raw[0:2]
            routing_label_byte_1_binary = bin(int(routing_label_byte_1, 16))[2:].zfill(8)
            routing_label_byte_2 = routing_label_raw[2:4]
            routing_label_byte_2_binary = bin(int(routing_label_byte_2, 16))[2:].zfill(8)
            routing_label_byte_3 = routing_label_raw[4:6]
            routing_label_byte_3_binary = bin(int(routing_label_byte_3, 16))[2:].zfill(8)
            routing_label_byte_4 = routing_label_raw[6:8]
            routing_label_byte_4_binary = bin(int(routing_label_byte_4, 16))[2:].zfill(8)
            #Signaling Link Selector
            routing_label_dict['sls'] = int(bin(int(routing_label_byte_4, 16))[2:].zfill(8)[0:4], base=16)

            #Point Codes
            mtp3_logger.debug("routing_label_byte_1_binary: " + str(routing_label_byte_1_binary))
            mtp3_logger.debug("routing_label_byte_2_binary: " + str(routing_label_byte_2_binary))
            mtp3_logger.debug("routing_label_byte_3_binary: " + str(routing_label_byte_3_binary))
            mtp3_logger.debug("routing_label_byte_4_binary: " + str(routing_label_byte_4_binary))
            routing_label_dict['opc'] = int(routing_label_byte_4_binary[-4:] + routing_label_byte_3_binary + routing_label_byte_2_binary[:2], 2)
            routing_label_dict['dpc'] = int(routing_label_byte_2_binary[2:] + routing_label_byte_1_binary, 2)
            self.routing_label(routing_label_dict)
            
        except Exception as E:
            mtp3_logger.error("Stumbled while processing MTP3 Header: " + str(data))
            mtp3_logger.error(E)
            mtp3_logger.error(mtp3_header)
            mtp3_logger.error("Stalled Position: " + str(position))
            mtp3_logger.error("Stalled Data Remaining: " + str(data[position:]))
            raise "Error processing M2PA Header"
        mtp3_logger.info("Completed Decoding - Output " + str(self.mtp3_header))
        return dict(self.mtp3_header)

    def getDict(self):
        return self.mtp3_header

    def setDict(self, dict):
        self.routing_label(dict['routing_label'])
        self.service_indicator_offset(dict['sio'])
        mtp3_logger.info("Set MTP3 values from Dict: " + str(dict))

    def handle(self, data):
        pass

a = MTP3()
#Maintaince Regular Message / Signaling Link Test Message
a.decodePDU("0111d8040211201112")
a.setDict({'sio': {'network_indicator': '00', 'spare': '00', 'ServiceIndicator': 1}, 'routing_label': {'sls': 0, 'opc': 2067, 'dpc': 6161}})
a.encodePDU()


def test_Decompile_LinkStatus():
    a = MTP3()
    #Maintaince Regular Message / Signaling Link Test Message
    assert a.decodePDU("0111d8040211201112") == {'sio': {'network_indicator': '00', 'spare': '00', 'ServiceIndicator': 1, 'NetworkIndicator_Description': 'International network', 'ServiceIndicator_Description': 'Signalling network testing and maintenance messages'}, 'routing_label': {'sls': 0, 'opc': 2067, 'dpc': 6161}}


def test_Compile_LinkStatus():
    a = MTP3()
    