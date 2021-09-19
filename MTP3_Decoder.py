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
        #print("dpc converted to decimal is " + str(dpc))
        opc = Convert_Decimal_To_Bin(opc, length=14)
        #print("opc converted to decimal is " + str(opc))
        link_selector = Convert_Decimal_To_Bin(link_selector, length=4)
        #print("link_selector converted to decimal is " + str(link_selector))
        
        byte4_value = int(opc[:4], 2) + (int(link_selector,2) << 4)
        byte3_value = int(opc[4:12], 2)
        byte2_value = int(dpc[:6], 2) + (int(opc[-2:], 2) << 6)
        byte1_value = int(dpc[-8:],2)
        bytes_values = (byte1_value, byte2_value, byte3_value, byte4_value)
        #print(bytes_values)

        
        mtp3_routing_label_pattern = struct.Struct(">B B B B")
        #print("mtp3_routing_label_pattern: " + str(mtp3_routing_label_pattern))
        binary_routing_label_data = mtp3_routing_label_pattern.pack(*bytes_values)
        #print("binary_routing_label_data: " + str(binary_routing_label_data))
        return binary_routing_label_data


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
        #print("DPC is: " + str(dpc))
        #print("OPC is: " + str(opc))
        link_selector = Link_Selector_Value_Forming(binary_routing_label_data)
        #print("Link Selector is: " + str(link_selector))
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

	def MTP3_Service_Information_Octet_Forming(self, mtp3_object, binary_sio_data):
		sio_value = int.from_bytes(binary_sio_data, byteorder="big")
		network_indicator = (sio_value & self.sio_network_indicator_mask) >> 6
		spare = sio_value & self.sio_spare_mask
		service_indicator = sio_value & self.sio_service_indicator_mask
		#self.MTP3_SIO_Data_Check(mtp3_object, network_indicator, spare, service_indicator)
		sio_data = {}
		sio_data['network_indicator'] = network_indicator
		sio_data['spare'] = network_indicator
		sio_data['service_indicator'] = service_indicator
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
		#print("At MTP3_Routing_Label_Forming")
		dpc = self.DPC_Value_Forming(binary_routing_label_data)
		opc = self.OPC_Value_Forming(binary_routing_label_data)
		link_selector = self.Link_Selector_Value_Forming(binary_routing_label_data)
		routing_label = {}
		routing_label['opc'] = opc
		routing_label['dpc'] = dpc
		routing_label['link_selector'] = link_selector
		#print("Completed Routing Label output of " + str(routing_label))	
		return routing_label

	def MTP3_Protocol_Data_Handling(self, binary_protocol_data):
		#print("Called MTP3_Protocol_Data_Handling")
		#MTP3 object building
		mtp3_data = MTP3_Data()
		#print("Defined mtp3_data: " + str(mtp3_data))
		output = {}
		#Building SIO data
		output['sio_data'] = self.MTP3_Service_Information_Octet_Forming(mtp3_object=mtp3_data, binary_sio_data=binary_protocol_data[:1])
		#Building routing label
		output['routing_label'] = self.MTP3_Routing_Label_Forming(mtp3_object=mtp3_data, binary_routing_label_data=binary_protocol_data[1:5])
		return output



def MTP3_Decode(data):
	a = Message_Parser()
	b = a.MTP3_Protocol_Data_Handling(bytes.fromhex(str(data)))
	return b


def MTP3_Routing_Indicator_Encode(data):
	print("Encoding data " + str(data))
	sio = str("{0:b}".format(data['sio_data']['network_indicator']).zfill(2)) + "00" + str("{0:b}".format(data['sio_data']['service_indicator']).zfill(4))
	sio_hex = hex(int(sio, 2))[2:].zfill(2)
	print(sio_hex)
	routing_label = (Convert_Routing_Label_Data(\
		data['routing_label']['dpc'], \
		data['routing_label']['opc'], \
		data['routing_label']['link_selector'])\
		)
	return sio_hex + str(routing_label.hex())

#print(MTP3_Routing_Indicator_Decode('0111d8040211201112'))
#print(MTP3_Routing_Indicator_Encode({'sio_data': {'network_indicator': 0, 'service_indicator' : 1}, \
#            'routing_label': {'opc': 2067, 'dpc': 6161, 'link_selector': 0}}))