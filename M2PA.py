
from socket import EWOULDBLOCK


Link_Status_Alignment = "01000b020000001400ffffff00ffffff00000001"
Link_Status_Emergency = "01000b020000001400ffffff00ffffff00000003"
Link_Status_Normal = "01000b020000001400ffffff00ffffff00000002"

LinkStatus = {'1':"Alignment", '2' : "Proving Normal", '3' : "Proving Emergency", '4':"Ready", '5':"Processor Outage", '6':"Processor Recovered", '7':"Busy", '8':"Busy Ended", '9':"Out of Service"}
MessageClass = {'0b' : "M2PA"}
MessageType = {'1':"User Data", '2' : "Link Status"}

def decode(data):
    print("Decoding M2PA")
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
        m2pa_header['bsn'] = data[position:position+6]
        position = position+6
        m2pa_header['unused2'] = data[position:position+2]
        position = position+2
        m2pa_header['fsn'] = data[position:position+6]
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
        print("Stumbled processing M2UA Header: " + str(data))
        print(E)
        print(m2pa_header)
        print("Stalled Position: " + str(position))
        print("Stalled Data Remaining: " + str(data[position:]))
        raise "Error processing M2UA Header"

    return m2pa_header

#print(decode("01000b010000001a00ffffff00000000090111d8040211201112"))