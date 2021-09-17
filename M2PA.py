
Link_Status_Alignment = "01000b020000001400ffffff00ffffff00000001"
Link_Status_Emergency = "01000b020000001400ffffff00ffffff00000003"
Link_Status_Normal = "01000b020000001400ffffff00ffffff00000002"

def decode(data):
    print("Decoding M2PA")
    m2pa_header = {}
    position = 0
    m2pa_header['version'] = data[position:position+2]
    position = position+2
    m2pa_header['spare'] = data[position:position+2]
    position = position+2
    m2pa_header['message_class'] = data[position:position+2]
    position = position+2
    m2pa_header['message_type'] = data[position:position+2]
    position = position+2
    m2pa_header['message_length'] = data[position:position+8]
    position = position+8
    m2pa_header['unused1'] = data[position:position+2]
    position = position+2
    m2pa_header['bsn'] = data[position:position+6]
    position = position+6
    m2pa_header['unused2'] = data[position:position+2]
    position = position+2
    m2pa_header['fsn'] = data[position:position+6]
    position = position+6
    m2pa_header['link_status'] = data[position:position+6]
    position = position+8
    m2pa_header['payload'] = data[position:]
    return m2pa_header

#print(decode("01000b020000001400ffffff0000000100000009"))