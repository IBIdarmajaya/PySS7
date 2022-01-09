#M2PA Handler
import logtool
import logging
logtool.setup_logger('M2PA Handler', 'M2PA.log', 'DEBUG')
m2pa_logger = logging.getLogger('M2PA Handler')
m2pa_logger.info("M2PA_Handler_logger Log Initialised.")

from socket import EWOULDBLOCK
def BinConvert(data, number_of_bits):
    return bin(int(str(data), 16))[2:].zfill(number_of_bits)

link_state_Alignment = "01000b020000001400ffffff00ffffff00000001"
link_state_Emergency = "01000b020000001400ffffff00ffffff00000003"
link_state_Normal = "01000b020000001400ffffff00ffffff00000002"

LinkStatus = {1 :"Alignment", 2 : "Proving Normal", 3 : "Proving Emergency", 4 :"Ready", 5 :"Processor Outage", 6 :"Processor Recovered", 7 :"Busy", 8 :"Busy Ended", 9 :"Out of Service"}
MessageClass = {'0b' : "M2PA"}
MessageType = {1 :"User Data", 2 : "Link Status"}

class M2PA:

    def __init__(self, **kwargs):
        self.m2pa_header = {}
        self.link_state(9)
        if 'version' not in self.m2pa_header:
            self.version(1)
        self.spare()
        self.unused1()
        self.unused2()
        if 'message_class' not in self.m2pa_header:
            self.message_class(11)
        if 'message_type' not in self.m2pa_header:
            self.message_type(2)
        if 'fsn' not in self.m2pa_header:
            self.fsn(1)
        if 'bsn' not in self.m2pa_header:
            self.bsn(16777214)
        if 'priority' not in self.m2pa_header:
            self.priority(1)
        if 'payload' not in self.m2pa_header:
            self.payload('')

    def link_state(self, link_state):
        #Check valid Link Status
        if link_state not in LinkStatus:
            raise ValueError("Invalid Link Status State - Out of range.")
        #Set default value if unset
        if 'link_state' not in self.m2pa_header:
            self.m2pa_header['link_state'] = link_state
        #Log on state change
        if link_state != self.m2pa_header['link_state']:
            m2pa_logger.warning("Link State changed to " + str(LinkStatus[link_state]))
        self.m2pa_header['link_state'] = link_state

    def version(self, version):
        version = int(version)
        if version != 1:
            raise ValueError("Invalid version " + str(version) + " - Only version 1 are valid per RFC4165")
        self.m2pa_header['version'] = version

    def spare(self):
        self.m2pa_header['spare'] = 0

    def unused1(self):
        self.m2pa_header['unused1'] = 0

    def unused2(self):
        self.m2pa_header['unused2'] = 0

    def message_class(self, message_class):
        message_class = int(message_class)
        if message_class != 11:
            raise ValueError("Invalid message class - Only Message Class 11 (M2PA Messages) are valid per RFC4165")      
        self.m2pa_header['message_class'] = message_class

    def message_type(self, message_type):
        message_type = int(message_type)
        if message_type not in [1, 2]:
            raise ValueError("Invalid message type " + str(message_type) + " - Only Message Types 1 & 2 (1 User Data & 2 Link Status) are valid per RFC4165")      

        m2pa_logger.info("Message Type is " + str(message_type) + " " + MessageType[message_type])
        self.m2pa_header['message_type'] = message_type

    def bsn(self, bsn):
        #Check valid range for BSN
        if bsn not in range(0, 16777216):
            raise ValueError("Invalid BSN - Out of range.")
        self.m2pa_header['bsn'] = bsn

    def fsn(self, fsn):
        #Check valid range for FSN
        if fsn not in range(0, 16777216):
            raise ValueError("Invalid FSN - Out of range.")
        self.m2pa_header['fsn'] = fsn

    def priority(self, priority):
        self.m2pa_header['priority'] = priority

    def payload(self, payload):
        self.m2pa_header['payload'] = payload

    def getDict(self):
        if self.m2pa_header['message_type'] == 2:
        #If the message type is 2 then drop the Priority
            if 'priority' in self.m2pa_header:
                self.m2pa_header.pop('priority')
        return self.m2pa_header

    def setDict(self, dict):
        if 'version' not in dict:
            self.version(1)
        else:
            self.version(dict['version'])

        if 'message_class' not in dict:
            self.message_class(11)
        else:
            self.message_class(dict['message_class'])   

        if 'message_type' not in dict:
            self.message_type(2)
        else:
            self.message_type(dict['message_type'])            

        if 'fsn' not in dict:
            self.fsn(1)
        else:
            self.fsn(dict['fsn'])            

        if 'bsn' not in dict:
            self.bsn(16777214)
        else:
            self.bsn(dict['bsn'])            

        if 'priority' not in dict:
            self.priority(1)
        else:
            self.priority(dict['priority'])

        if 'payload' not in dict:
            self.payload('')
        else:
            self.payload(dict['payload'])

        if 'link_state' in dict:
            self.link_state(dict['link_state'])

    def encodePDU(self):
        m2pa_logger.info("Encoding M2PA header with inputs " + str(self.m2pa_header))
        hexout = ''
        hexout+= format(self.m2pa_header['version'], 'x').zfill(2)              #Version - Release 1
        hexout+= format(self.m2pa_header['spare'], 'x').zfill(2)                #Spare Bit - Unused in RFC
        hexout+= format(self.m2pa_header['message_class'], 'x').zfill(2)        #Message Class (11 / M2PA)
        hexout+= format(self.m2pa_header['message_type'], 'x').zfill(2)         #Message Type (Valid values 1 &2)

        #Force the payload on Link Status 
        if self.m2pa_header['message_type'] == 2:
        #If the message type is 2 then drop the Payload if set
            m2pa_logger.warning("This is a M2PA Link Status Message but the payload is set. Clearing payload")
            self.m2pa_header['payload'] = format(self.m2pa_header['link_state'], 'x').zfill(8)
            m2pa_logger.info("Payload is set to " + str(self.m2pa_header['payload']))
            #If Priority is present in Link Status clear it as well
            if 'priority' in self.m2pa_header:
                m2pa_logger.warning("This is a M2PA Link Status Message but the priority is set. Clearing priority")
                self.m2pa_header.pop('priority')

        #Handle setting Length
        overall_length = 16 + (len(self.m2pa_header['payload'])/2)
        if (overall_length % 2) == 0:
            m2pa_logger.debug("overall_length is even number, leaving unchnaged")
            pass
        else:
            m2pa_logger.debug("overall_length is odd number, rouding up")
            overall_length+= 1
        m2pa_logger.debug("overall length should be " + str(overall_length))

        hexout+= format(int(overall_length), 'x').zfill(8)                      #Length encoded onto 4 bits
        hexout+= format(self.m2pa_header['unused1'], 'x').zfill(2)              #Unused bit1
        hexout+= format(self.m2pa_header['bsn'], 'x').zfill(6)                  #Backwards Sequence Number
        hexout+= format(self.m2pa_header['unused2'], 'x').zfill(2)              #Unused bit2
        hexout+= format(self.m2pa_header['fsn'], 'x').zfill(6)                  #Forwards Sequence Number
        if 'priority' in self.m2pa_header:
            m2pa_logger.debug("Priotity being added")
            hexout+= str(self.m2pa_header['priority'])                          #ToDo - Better handling of this

        hexout+= self.m2pa_header['payload']

        m2pa_logger.info("Final output is " + str(hexout))
        return hexout

    def decodePDU(self, data):
        m2pa_logger.info("Decoding M2PA data: " + str(data))
        try:
            m2pa_header = {}
            position = 0
            m2pa_header['version'] = int(data[position:position+2])
            position = position+2
            m2pa_header['spare'] = int(data[position:position+2])
            position = position+2
            m2pa_header['message_class'] = data[position:position+2]
            m2pa_header['message_class'] = int(str(m2pa_header['message_class']), base=16)
            position = position+2
            m2pa_header['message_type'] = data[position:position+2]
            m2pa_header['message_type'] = int(str(m2pa_header['message_type']), base=16)
            position = position+2
            m2pa_header['message_length'] = data[position:position+8]
            m2pa_header['message_length'] = int(m2pa_header['message_length'], 16)
            position = position+8
            m2pa_header['unused1'] = int(data[position:position+2])
            position = position+2
            m2pa_header['bsn'] = int(str(data[position:position+6]), 16)
            position = position+6
            m2pa_header['unused2'] = int(data[position:position+2])
            position = position+2
            m2pa_header['fsn'] = int(str(data[position:position+6]), 16)
            position = position+6
            m2pa_logger.info("Message type is " + str(MessageType[m2pa_header['message_type']]))
            if m2pa_header['message_type'] == 2:
                m2pa_header['link_state'] = int(data[position:position+8])
                self.link_state(m2pa_header['link_state'])
                position = position+8
                m2pa_header['payload'] = data[position:]
            elif m2pa_header['message_type'] == 1:
                m2pa_header['priority'] = data[position:position+2]
                position = position+2
                m2pa_header['payload'] = data[position:]
            else:
                m2pa_logger.error("Failed to determine message type")
        except Exception as E:
            m2pa_logger.error("Stumbled processing M2PA Header: " + str(data))
            m2pa_logger.error(E)
            m2pa_logger.error(m2pa_header)
            m2pa_logger.error("Stalled Position: " + str(position))
            m2pa_logger.error("Stalled Data Remaining: " + str(data[position:]))
            raise "Error processing M2PA Header"
        m2pa_logger.info("Completed Decoding - Output " + str(m2pa_header))
        self.m2pa_header = m2pa_header
        #self.setDict(m2pa_header)
        return dict(m2pa_header)

    def handle(self, data):
        m2pa_logger.info("Handling recieved message with raw content: " + str(data))
        #Decode message
        self.decodePDU(data)
        #Handle "User Data" message types
        if self.m2pa_header['message_type'] == 1:
            #ToDo
            pass
        #Handle "Link Status" message types
        elif self.m2pa_header['message_type'] == 2:
            #M2PA expects the Link Status messages to be echoed straight back to it.
            m2pa_logger.warning("Link State changed to " + str(LinkStatus[self.m2pa_header['link_state']]))
            return self.encodePDU()


def test_CheckDict():
    #Check Default Dictionary Values
    a = M2PA()
    assert a.getDict() == {'bsn': 16777214, 'link_state' : 9, 'spare' : 0, 'unused1': 0, 'unused2': 0, 'fsn': 1, 'message_class': 11, 'message_type': 2, 'payload': '', 'version': 1}

def test_Compile_LinkStatus():
    a = M2PA()
    #Check Link Status - Alignment
    a.setDict({'version': 1, 'spare': 0, 'message_class': 11, 'message_type': 2, 'unused1': 0, 'bsn': 16777215, 'unused2': 0, 'fsn': 16777215, 'link_state': 1, 'payload': ''})
    assert "01000b020000001400ffffff00ffffff00000001" == a.encodePDU()

    #Check Link Status - Proving Emergency
    a.setDict({'version': 1, 'spare': 0, 'message_class': 11, 'message_type': 2, 'message_length': 20, 'unused1': 0, 'bsn': 16777215, 'unused2': 0, 'fsn': 16777215, 'link_state': 3, 'payload': ''})
    assert "01000b020000001400ffffff00ffffff00000003" == a.encodePDU()

    #Check Link Status - Proving Normal
    a.setDict({'version': 1, 'spare': 0, 'message_class': 11, 'message_type': 2, 'message_length': 20, 'unused1': 0, 'bsn': 16777215, 'unused2': 0, 'fsn': 16777215, 'link_state': 2, 'payload': ''})
    assert "01000b020000001400ffffff00ffffff00000002" == a.encodePDU()

    #Check Link Status - Ready
    a.setDict({'version': 1, 'spare': 0, 'message_class': 11, 'message_type': 2, 'message_length': 20, 'unused1': 0, 'bsn': 16777215, 'unused2': 0, 'fsn': 16777215, 'link_state': 4, 'payload': ''})
    assert "01000b020000001400ffffff00ffffff00000004" == a.encodePDU()



def test_Decompile_LinkStatus():
    a = M2PA()
    #Check Link Status - Alignment
    assert a.decodePDU("01000b020000001400ffffff00ffffff00000001") == {'version': 1, 'spare': 0, 'message_class': 11, 'message_type': 2, 'message_length': 20, 'unused1': 0, 'bsn': 16777215, 'unused2': 0, 'fsn': 16777215, 'link_state': 1, 'payload': ''}

    #Check Link Status - Proving Emergency
    assert a.decodePDU("01000b020000001400ffffff00ffffff00000003") == {'version': 1, 'spare': 0, 'message_class': 11, 'message_type': 2, 'message_length': 20, 'unused1': 0, 'bsn': 16777215, 'unused2': 0, 'fsn': 16777215, 'link_state': 3, 'payload': ''}

    #Check Link Status - Proving Normal
    assert a.decodePDU("01000b020000001400ffffff00ffffff00000002") == {'version': 1, 'spare': 0, 'message_class': 11, 'message_type': 2, 'message_length': 20, 'unused1': 0, 'bsn': 16777215, 'unused2': 0, 'fsn': 16777215, 'link_state': 2, 'payload': ''}

    #Check Link Status - Ready
    assert a.decodePDU("01000b020000001400ffffff00ffffff00000004") == {'version': 1, 'spare': 0, 'message_class': 11, 'message_type': 2, 'message_length': 20, 'unused1': 0, 'bsn': 16777215, 'unused2': 0, 'fsn': 16777215, 'link_state': 4, 'payload': ''}

def test_Decompile_UserData():
    #Check M2PA message with MTP3 payload
    a = M2PA()
    assert a.decodePDU("01000b010000001a0000000000000000090113880b0811201112") == {'bsn': 0, 'fsn': 0, 'message_class': 11, 'message_length': 26, 'message_type': 1, 'payload': '0113880b0811201112', 'priority': '09', 'spare': 0, 'unused1': 0, 'unused2': 0, 'version': 1}

def test_Compile_UserData():
    #Check M2PA message with MTP3 payload
    a = M2PA()
    a.setDict({'bsn': 0, 'fsn': 0, 'message_class': 11, 'message_length': 26, 'message_type': 1, 'payload': '0113880b0811201112', 'priority': '09', 'spare': 0, 'unused1': 0, 'unused2': 0, 'version': 1})
    assert a.encodePDU() == "01000b010000001a0000000000000000090113880b0811201112"