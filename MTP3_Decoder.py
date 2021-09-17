from jsonschema import Draft4Validator
import jsonschema
import argparse
import random
import json
import math
import sys
import os
import struct
import binascii


####Decode
##a = Message_Parser()
##b = a.M2UA_Protocol_Data_Handling(bytes.fromhex('0111d8040211201112'))
##print(b.routing_label.dpc)

####Encode
#mtp3_data = MTP3_Data()
#mtp3_data.sio = MTP3_Service_Information_Octet_Forming(mtp3_object=mtp3_data, binary_sio_data=binary_protocol_data[:1])



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





class MTP3_Data:

	def __init__(self):
		self.sio = None
		self.routing_label = None
		self.service_data = None

	class Service_Information_Octet:
		def __init__(self, network_indicator, service_indicator=None, spare=0):
			self.network_indicator = network_indicator
			self.spare = spare
			self.service_indicator = service_indicator

	class Routing_Label:
		def __init__(self, dpc, opc, link_selector):
			self.dpc = dpc
			self.opc = opc
			self.link_selector = link_selector

	def Define_Network_Indicator_Values(self):
		values = {
		  0 : "International network",
		  2 : "National network",
		}
		return values

	def Define_Service_Indicator_Values(self):
		values = {
		  0 : "Signaling network management messages",
		  1 : "Signaling network testing and maintenance messages",
		  3 : "SCCP",
		  4 : "Telephone User Part",
		  5 : "ISDN User Part",
		  6 : "Data User Part (call and circuit-related messages)",
		  7 : "Data User Part (facility registration and cancellation messages)",
		  9 : "Broadband ISDN User Part",
		 10 : "Satellite ISDN User Part"
		}
		return values



class Message_Parser:

	def __init__(self):
		
		self.sio_network_indicator_mask = 0b11000000
		self.sio_spare_mask = 0b00110000
		self.sio_service_indicator_mask = 0b00001111
		self.routing_label_dpc_mask = 16383
		self.routing_label_opc_mask = 268419072
		self.routing_label_link_selector_mask = 4026531840

	def Define_M2UA_Parameter_Handlers(self):
		handlers = {
		  (1,11,12,13,17,19,770,771,772,773,774,775,776,778,779,780,782,784) : self.Int_M2UA_Parameter_Value_Handling,
		  (3,4) : self.Str_M2UA_Parameter_Value_Handling,
		  (8,) : self.Int_Range_M2UA_Parameter_Value_Handling,
		  (7,9) : self.Polymorphic_M2UA_Parameter_Value_Handling,
		  (768,) : self.M2UA_Protocol_Data_Handling,
		  (769,) : self.M2UA_TTC_Protocol_Data_Handling,
		  (777,781,783) : self.M2UA_Composite_Parameters_Handling
		}
		return handlers

	def Define_Service_Data_Handlers(self):
		handlers = {
		  3 : self.SCCP_Data_Forming,
		  5 : self.ISUP_Data_Forming
		}
		return handlers

	def Get_M2UA_Class_Description(self, object_message):
		classes = object_message.Define_Message_Classes()
		for class_number,description in classes.items():
		    if object_message.mes_class == class_number:
		    	class_description = description
		    	break
		else:
			raise M2UA_Error("m2ua class \"%s\" does not supported" % object_message.mes_class)
		return class_description

	def Get_M2UA_Message_Types(self, object_message):
		if object_message.mes_class == 0:
			message_types = object_message.Define_MGMT_Message_Types()
		elif object_message.mes_class == 3:
			message_types = object_message.Define_ASPSM_Message_Types()
		elif object_message.mes_class == 4:
			message_types = object_message.Define_ASPTM_Message_Types()
		elif object_message.mes_class == 6:
			message_types = object_message.Define_MAUP_Message_Types()
		elif object_message.mes_class == 10:
			message_types = object_message.Define_IIM_Message_Types()
		else:
			raise M2UA_Error("m2ua class \"%s\" does not supported" % object_message.mes_class)
		return message_types

	def Get_M2UA_Type_Description(self, object_message):
		message_types = self.Get_M2UA_Message_Types(object_message)
		for type_number, description in message_types.items():
			if object_message.mes_type == type_number:
				type_description = description
				break
		else:
			raise M2UA_Error("\"%s\" is unknown m2ua message type" % object_message.mes_type)
		return type_description

	def Get_Message_Info(self, object_message):
		print("----------------Message Info ----------------")
		print("Version:", object_message.version)
		print("Spare:", object_message.spare)
		print("Class:", object_message.mes_class)
		print("     -", self.Get_M2UA_Class_Description(object_message))
		print("Type:", object_message.mes_type)
		print("     -", self.Get_M2UA_Type_Description(object_message))
		print("---------------------------------------------")

	def M2UA_Message_Class_Check(self, m2ua_header):
		message_classes = m2ua_header.Define_Message_Classes()
		for class_number in message_classes.keys():
			if m2ua_header.mes_class == class_number:
				break
		else:
			raise M2UA_Error("\"%s\" is unknown m2ua class" % m2ua_header.mes_class)

	def M2UA_Message_Type_Check(self, m2ua_header):
		message_types = self.Get_M2UA_Message_Types(m2ua_header)
		for type_number in message_types.keys():
			if m2ua_header.mes_type == type_number:
				break
		else:
			raise M2UA_Error("\"%s\" is unknown m2ua message type" % m2ua_header.mes_type)

	def M2UA_Message_Length_Check(self, m2ua_header):
		if m2ua_header.length < 8:
			raise M2UA_Error("m2ua message length \"%s\" is too short" % m2ua_header.length)

	def M2UA_Header_Check(self, m2ua_header):
		if m2ua_header.version != 1:
			raise M2UA_Error("m2ua version \"%s\" is not 1" % m2ua_header.version)
		if m2ua_header.spare != 0:
			raise M2UA_Error("m2ua spare \"%s\" is not zero" % m2ua_header.spare)
		self.M2UA_Message_Class_Check(m2ua_header)
		self.M2UA_Message_Type_Check(m2ua_header)
		self.M2UA_Message_Length_Check(m2ua_header)

	def M2UA_Header_Forming(self, binary_header):
		try:
			unpacked_data = self.common_m2ua_header_pattern.unpack(binary_header)
		except struct.error:
			if not binary_header:
				raise M2UA_Error("message was not received")
			else:
				raise M2UA_Error("received message is not m2ua message")
		else:
			m2ua_header = M2UA_Message(version=unpacked_data[0], spare=unpacked_data[1], message_class=unpacked_data[2], message_type=unpacked_data[3])
			m2ua_header.length = unpacked_data[4]
			self.M2UA_Header_Check(m2ua_header)
			return m2ua_header

	def SCCP_Data_Forming(self, binary_data):
		sccp_data = SCCP_Data()
		sccp_data.data = binary_data
		return sccp_data

	def ISUP_Data_Forming(self, binary_data):
		isup_data = self.isup_parser.Parse_Protocol_Data(binary_data)
		return isup_data

	def Padding_Bytes_Counting(self, parameter_length):
		initial_parameter_length = parameter_length
		for i in range(1,4):
			parameter_length = initial_parameter_length + i
			if parameter_length % 4 == 0:
				multiple_length = parameter_length
				break
		else:
			raise M2UA_Error("padding bytes counting error")
		paddings_number = multiple_length - initial_parameter_length
		return paddings_number

	def M2UA_Parameters_Shifting(self, m2ua_data, parameter_length):
		m2ua_data = m2ua_data[parameter_length:]
		return m2ua_data

	def M2UA_Parameter_Padding_Removing(self, m2ua_data, parameter_length):
		paddings_number = self.Padding_Bytes_Counting(parameter_length)
		m2ua_data = m2ua_data[:parameter_length] + m2ua_data[parameter_length + paddings_number:]
		return m2ua_data

	def M2UA_Parameter_Tag_Check(self, m2ua_parameter):
		parameter_tags = m2ua_parameter.Define_Parameter_Tags()
		for tag_number in parameter_tags.keys():
			if m2ua_parameter.tag == tag_number:
				break
		else:
			raise M2UA_Error("\"%s\" is unknown m2ua parameter tag value" % m2ua_parameter.tag)

	def M2UA_TTC_Protocol_Data_Handling(self, binary_protocol_data):
		raise M2UA_Error("mtp3 ttc data parsing not supported now")

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
		sio_data = {}
		sio_data['network_indicator'] = network_indicator
		sio_data['spare'] = network_indicator
		sio_data['network_indicator'] = service_indicator
		#sio_data = mtp3_object.Service_Information_Octet(network_indicator=network_indicator, spare=spare, service_indicator=service_indicator)
		return sio_data

	def Add_Bit_Paddings(self, bin_value):
		end_of_padding = False
		while not end_of_padding:
			if len(bin_value) != 8:
				bin_value = "0" + bin_value
			else:
				end_of_padding = True
		return bin_value

	def DPC_Value_Forming(self, binary_data):
		byte1 = self.Add_Bit_Paddings(bin(binary_data[0])[2:])
		byte2 = self.Add_Bit_Paddings(bin(binary_data[1])[2:])
		dpc_value = int(byte2[2:] + byte1, 2)
		return dpc_value

	def OPC_Value_Forming(self, binary_data):
		byte2 = self.Add_Bit_Paddings(bin(binary_data[1])[2:])
		byte3 = self.Add_Bit_Paddings(bin(binary_data[2])[2:])
		byte4 = self.Add_Bit_Paddings(bin(binary_data[3])[2:])
		opc_value = int(byte4[-4:] + byte3 + byte2[:2], 2)
		return opc_value

	def Link_Selector_Value_Forming(self, binary_data):
		byte4 = self.Add_Bit_Paddings(bin(binary_data[3])[2:])
		link_selector_value = int(byte4[:4], 2)
		return link_selector_value

	def MTP3_Routing_Label_Forming(self, mtp3_object, binary_routing_label_data):
		print("At MTP3_Routing_Label_Forming")
		dpc = self.DPC_Value_Forming(binary_routing_label_data)
		opc = self.OPC_Value_Forming(binary_routing_label_data)
		link_selector = self.Link_Selector_Value_Forming(binary_routing_label_data)
		routing_label = {}
		routing_label['opc'] = opc
		routing_label['dpb'] = dpc
		routing_label['link_selector'] = link_selector
		print("Completed Routing Label output of " + str(routing_label))	
		return routing_label

	def MTP3_Protocol_Data_Handling(self, binary_protocol_data):
		print("Called MTP3_Protocol_Data_Handling")
		#MTP3 object building
		mtp3_data = MTP3_Data()
		print("Defined mtp3_data: " + str(mtp3_data))
		output = {}
		#Building SIO data
		output['sio_data'] = self.MTP3_Service_Information_Octet_Forming(mtp3_object=mtp3_data, binary_sio_data=binary_protocol_data[:1])
		#Building routing label
		output['routing_label'] = self.MTP3_Routing_Label_Forming(mtp3_object=mtp3_data, binary_routing_label_data=binary_protocol_data[1:5])
		return output


print("\n\n\n")
a = Message_Parser()
b = a.MTP3_Protocol_Data_Handling(bytes.fromhex('0111d8040211201112'))
print(b)
