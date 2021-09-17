
import struct

def Convert_Decimal_To_Bin(decimal_value, length):
        bin_value = bin(decimal_value)[2:]
        end_of_padding = False
        while not end_of_padding:
                if len(bin_value) != length:
                        bin_value = "0" + bin_value
                else:
                        end_of_padding = True
        return bin_value


def Convert_Routing_Label_Data(dpc, opc, link_selector):
        dpc = Convert_Decimal_To_Bin(dpc, length=14)
        print("dpc converted to decimal is " + str(dpc))
        opc = Convert_Decimal_To_Bin(opc, length=14)
        print("opc converted to decimal is " + str(opc))
        link_selector = Convert_Decimal_To_Bin(link_selector, length=4)
        print("link_selector converted to decimal is " + str(link_selector))
        
        byte4_value = int(opc[:4], 2) + (int(link_selector,2) << 4)
        byte3_value = int(opc[4:12], 2)
        byte2_value = int(dpc[:6], 2) + (int(opc[-2:], 2) << 6)
        byte1_value = int(dpc[-8:],2)
        bytes_values = (byte1_value, byte2_value, byte3_value, byte4_value)
        print(bytes_values)

        
        mtp3_routing_label_pattern = struct.Struct(">B B B B")
        #print("mtp3_routing_label_pattern: " + str(mtp3_routing_label_pattern))
        binary_routing_label_data = mtp3_routing_label_pattern.pack(*bytes_values)
        print("binary_routing_label_data: " + str(binary_routing_label_data))
        return binary_routing_label_data

print(Convert_Routing_Label_Data(6161, 2067, 0))


#Reverser
bytes_values = (17, 216, 4, 2)
mtp3_routing_label_pattern = struct.Struct(">B B B B")
binary_routing_label_data = mtp3_routing_label_pattern.pack(*bytes_values)



def MTP3_Spare_Check(self, spare):
        if spare != 0:
                raise M2UA_Error("mtp3 spare is not zero value")

def MTP3_Service_Indicator_Check(self, mtp3_object, service_indicator):
        service_indicators = mtp3_object.Define_Service_Indicator_Values()
        for indicator in service_indicators.keys():
                if service_indicator == indicator:
                        break
        else:
                raise M2UA_Error("\"%s\" is unknown mtp3 service indicator value" % service_indicator)

def MTP3_Network_Indicator_Check(self, mtp3_object, network_indicator):
        network_indicators = mtp3_object.Define_Network_Indicator_Values()
        for indicator in network_indicators.keys():
                if network_indicator == indicator:
                        break
        else:
                raise M2UA_Error("\"%s\" is unknown mtp3 network indicator value" % network_indicator)

def MTP3_SIO_Data_Check(self, mtp3_object, network_indicator, spare, service_indicator):
        self.MTP3_Network_Indicator_Check(mtp3_object, network_indicator)
        self.MTP3_Spare_Check(spare)
        self.MTP3_Service_Indicator_Check(mtp3_object, service_indicator)

def Service_Data_Forming(self, service_indicator, binary_data):
        service_data_handlers = self.Define_Service_Data_Handlers()
        for indicator, handler in service_data_handlers.items():
                if indicator == service_indicator:
                        service_data = service_data_handlers[service_indicator](binary_data)
                        break
        else:
                service_data = binary_data
        return service_data

def MTP3_Service_Information_Octet_Forming(self, mtp3_object, binary_sio_data):
        sio_value = int.from_bytes(binary_sio_data, byteorder="big")
        network_indicator = (sio_value & self.sio_network_indicator_mask) >> 6
        spare = sio_value & self.sio_spare_mask
        service_indicator = sio_value & self.sio_service_indicator_mask
        self.MTP3_SIO_Data_Check(mtp3_object, network_indicator, spare, service_indicator)
        sio_data = mtp3_object.Service_Information_Octet(network_indicator=network_indicator, spare=spare, service_indicator=service_indicator)
        return sio_data

def Add_Bit_Paddings(bin_value):
        end_of_padding = False
        while not end_of_padding:
                if len(bin_value) != 8:
                        bin_value = "0" + bin_value
                else:
                        end_of_padding = True
        return bin_value

def DPC_Value_Forming(binary_data):
        byte1 = Add_Bit_Paddings(bin(binary_data[0])[2:])
        byte2 = Add_Bit_Paddings(bin(binary_data[1])[2:])
        dpc_value = int(byte2[2:] + byte1, 2)
        return dpc_value

def OPC_Value_Forming(binary_data):
        byte2 = Add_Bit_Paddings(bin(binary_data[1])[2:])
        byte3 = Add_Bit_Paddings(bin(binary_data[2])[2:])
        byte4 = Add_Bit_Paddings(bin(binary_data[3])[2:])
        opc_value = int(byte4[-4:] + byte3 + byte2[:2], 2)
        return opc_value

def Link_Selector_Value_Forming(binary_data):
        byte4 = Add_Bit_Paddings(bin(binary_data[3])[2:])
        link_selector_value = int(byte4[:4], 2)
        return link_selector_value

#def MTP3_Routing_Label_Forming(self, mtp3_object, binary_routing_label_data):
def MTP3_Routing_Label_Forming(mtp3_object, binary_routing_label_data):
        dpc = DPC_Value_Forming(binary_routing_label_data)
        opc = OPC_Value_Forming(binary_routing_label_data)
        print("DPC is: " + str(dpc))
        print("OPC is: " + str(opc))
        link_selector = Link_Selector_Value_Forming(binary_routing_label_data)
        print("Link Selector is: " + str(link_selector))
        routing_label = mtp3_object.Routing_Label(dpc=dpc, opc=opc, link_selector=link_selector)
        return routing_label

mtp3_data = MTP3_Data()
mtp3_data.sio = MTP3_Service_Information_Octet_Forming(mtp3_object=mtp3_data, binary_sio_data=binary_protocol_data[:1])
mtp3_object = []
MTP3_Routing_Label_Forming(mtp3_object, b'\x11\xd8\x04\x02')
