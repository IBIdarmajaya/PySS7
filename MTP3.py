import MTP3_Decoder
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

def decode(data):
    print("Decoding MTP3")
    mtp3_header = MTP3_Decoder.MTP3_Decode(data)
    mtp3_header['payload'] = data[10:]
    if mtp3_header['sio_data']['service_indicator'] == 1:
        print("MTP3 Management Layer present!")
        mpt3_management = {}
        mpt3_management['b1'] = BinConvert(mtp3_header['payload'][0:2], 8)
        mpt3_management['message_group'] = mpt3_management['b1'][4:8]
        mpt3_management['message'] = mpt3_management['b1'][0:4]
        if mpt3_management['message'] = '01':
            #Signaling Link-Check Message - Change to response then echo back what we recieved.
            print("MTP3 Management Message Response - 'Signaling Link-Check Message' Generated")
            mpt3_management['mtp3_management_response'] = mtp3_header['payload']
        elif mpt3_management['message'] = '01':
            #Signaling Link-Check Message - Echo back what we recieved.
            print("MTP3 Management Message Response - 'Signaling Link-Check Message' Generated")
            mpt3_management['mtp3_management_response'] = mtp3_header['payload']            
        mpt3_management['length'] = 2       #ToDo - Fix this
        mpt3_management['payload'] = mtp3_header['payload']
        mtp3_header['mpt3_management'] = mpt3_management

    return mtp3_header


print(decode("0111d8040211201112"))
