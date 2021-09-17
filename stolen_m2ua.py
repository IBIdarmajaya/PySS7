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

class M2UA_Message:

	def __init__(self, message_class, message_type, version=1, spare=0):
		self.version = version
		self.spare = spare
		self.mes_class = message_class
		self.mes_type = message_type
		self.length = None
		self.parameters = []

	def Define_Message_Classes(self):
		classes = {
		  0 : "Management message (MGMT)",
		  1 : "Transfer messages (TRANSF)",
		  2 : "SS7 signalling network management messages (SSNM)",
		  3 : "ASP state maintenance messages (ASPSM)",
		  4 : "ASP traffic maintenance messages (ASPTM)",
		  5 : "Q.921/Q.931 boundary primitives transport (QPTM)",
		  6 : "MTP2 User Adaptation messages (MAUP)",
		  7 : "Connectionless messages (CLM)",
		  8 : "Connection-oriented messages (COM)",
		  9 : "Routing key management messages (RKM)",
		  10 : "Interface Identifier management messages (IIM)",
                  11 : "MTP3"
		}
		return classes

	def Define_MAUP_Message_Types(self):
		types = {
		  1 : "Data (DATA)",
		  2 : "Establish Request (ESTAB REQ)",
		  3 : "Establish Confirm (ESTAB CONF)",
		  4 : "Release Request (RELEASE REQ)",
		  5 : "Release Confirm (RELEASE CONF)",
		  6 : "Release Indication (RELEASE IND)",
		  7 : "State Request (STATE REQ)",
		  8 : "State Confirm (STATE CONF)",
		  9 : "State Indication (STATE IND)",
		  10 : "Data Retrieval Request (DATA RETR REQ)",
		  11 : "Data Retrieval Confirm (DATA RETR CONF)",
		  12 : "Data Retrieval Indication (DATA RETR IND)",
		  13 : "Data Retrieval Complete Indication (DATA RETR COMPL IND)",
		  14 : "Congestion Indication (CONGESTION IND)",
		  15 : "Data Acknowledge (DATA ACK)"
		}
		return types

	def Define_ASPSM_Message_Types(self):
		types = {
		  1 : "ASP Up (ASP UP)",
		  2 : "ASP Down (ASP DOWN)",
		  3 : "Heartbeat (BEAT)",
		  4 : "ASP Up Ack (ASP UP ACK)",
		  5 : "ASP Down Ack (ASP DOWN ACK)",
		  6 : "Heartbeat Ack (BEAT ACK)"
		}
		return types

	def Define_ASPTM_Message_Types(self):
		types = {
		  1 : "ASP Active (ASP ACTIVE)",
		  2 : "ASP Inactive (ASP INACTIVE)",
		  3 : "ASP Active Ack (ASP ACTIVE ACK)",
		  4 : "ASP Inactive Ack (ASP INACTIVE ACK)"
		}
		return types

	def Define_MGMT_Message_Types(self):
		types = {
		  0 : "Error (ERR)",
		  1 : "Notify (NTFY)"
		}
		return types

	def Define_IIM_Message_Types(self):
		types = {
		  1 : "Registration Request (REG REQ)",
		  2 : "Registration Response (REG RSP)",
		  3 : "Deregistration Request (DEREG REQ)",
		  4 : "Deregistration Response (DEREG RSP)"
		}
		return types

class M2UA_Parameter:

	def __init__(self, tag):
		self.tag = tag
		self.length = 8
		self.value = None

	def Define_Parameter_Tags(self):
		tags = {
		  1 : "Interface Identifier (Integer)",
		  3 : "Interface Identifier (Text)",
		  4 : "Info String",
		  7 : "Diagnostic Information",
		  8 : "Interface Identifier (Integer Range)",
		  9 : "Heartbeat Data",
		  11 : "Traffic Mode Type",
		  12 : "Error Code",
		  13 : "Status Type/Information",
		  17 : "ASP Identifier",
		  19 : "Correlation Id",
		  768 : "Protocol Data 1",
		  769 : "Protocol Data 2 (TTC)",
		  770 : "State Request",
		  771 : "State Event",
		  772 : "Congestion Status",
		  773 : "Discard Status",
		  774 : "Action",
		  775 : "Sequence Number",
		  776 : "Retrieval Result",
		  777 : "Link Key",
		  778 : "Local-LK-Identifier",
		  779 : "Signalling Data Terminal (SDT) Identifier",
		  780 : "Signalling Data Link (SDL) Identifier",
		  781 : "Registration Result",
		  782 : "Registration Status",
		  783 : "De-Registration Result",
		  784 : "De-Registration Status"
		}
		return tags

	def Define_State_Parameter_Values(self):
		values = {
		  0 : "STATUS_LPO_SET",
		  1 : "STATUS_LPO_CLEAR",
		  2 : "STATUS_EMER_SET",
		  3 : "STATUS_EMER_CLEAR",
		  4 : "STATUS_FLUSH_BUFFERS",
		  5 : "STATUS_CONTINUE",
		  6 : "STATUS_CLEAR_RTB",
		  7 : "STATUS_AUDIT",
		  8 : "STATUS_CONG_CLEAR",
		  9 : "STATUS_CONG_ACCEPT",
		  10 : "STATUS_CONG_DISCARD"
		}
		return values

	def Define_Event_Parameter_Values(self):
		values = {
		  1 : "EVENT_RPO_ENTER",
		  2 : "EVENT_RPO_EXIT",
		  3 : "EVENT_LPO_ENTER",
		  4 : "EVENT_LPO_EXIT"
		}
		return values

	def Define_Congestion_And_Discard_Status_Values(self):
		values = {
		  0 : "LEVEL_NONE",
		  1 : "LEVEL_1",
		  2 : "LEVEL_2",
		  3 : "LEVEL_3"
		}
		return values

	def Define_Action_Values(self):
		values = {
		  1 : "ACTION_RTRV_BSN",
		  2 : "ACTION_RTRV_MSGS"
		}
		return values

	def Define_Result_Values(self):
		values = {
		  0 : "RESULT_SUCCESS",
		  1 : "RESULT_FAILURE"
		}
		return values

	def Define_Traffic_Mode_Type_Values(self):
		values = {
		  1 : "Override",
		  2 : "Load-share",
		  3 : "Broadcast"
		}
		return values

	def Define_Error_Code_Values(self):
		values = {
		  1 : "Invalid Version",
		  2 : "Invalid Interface Identifier",
		  3 : "Unsupported Message Class",
		  4 : "Unsupported Message Type",
		  5 : "Unsupported Traffic Handling Mode",
		  6 : "Unexpected Message",
		  7 : "Protocol Error",
		  8 : "Unsupported Interface Identifier Type",
		  9 : "Invalid Stream Identifier",
		  13 : "Refused - Management Blocking",
		  14 : "ASP Identifier Required",
		  15 : "Invalid ASP Identifier",
		  16 : "ASP Active for Interface Identifier(s)",
		  17 : "Invalid Parameter Value",
		  18 : "Parameter Field Error",
		  19 : "Unexpected Parameter",
		  22 : "Missing Parameter"
		}
		return values

	def Define_Status_Type_Values(self):
		types = {
		  1 : "AS State Change",
		  2 : "Other"
		}
		return types

	def Define_AS_State_Change_Status_Information_Values(self):
		values = {
		  2 : "AS_Inactive",
		  3 : "AS_Active",
		  4 : "AS_Pending"
		}
		return values

	def Define_Other_Status_Information_Values(self):
		values = {
		  1 : "Insufficient ASP resources active in AS",
		  2 : "Alternate ASP Active",
		  3 : "ASP Failure"
		}
		return values

	def Define_Registration_Status_Values(self):
		values = {
		  0 : "Successfully Registered",
		  1 : "Unknown",
		  2 : "Invalid SDLI",
		  3 : "Invalid SDTI",
		  4 : "Invalid Link Key",
		  5 : "Permission Denied",
		  6 : "Overlapping Link Key",
		  7 : "Link Key not Provisioned",
		  8 : "Insufficient Resources"
		}
		return values

	def Define_Deregistration_Status_Values(self):
		values = {
		  0 : "Successfully De-registered",
		  1 : "Unknown",
		  2 : "Invalid Interface Identifier",
		  3 : "Permission Denied",
		  4 : "Not Registered"
		}
		return values

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

class SCCP_Data:

	def __init__(self):
		self.data = None

class SCCP_Message_Builder:
	
	def __init__(self):
		pass

class SCCP_Binary_Convertor:

	def __init__(self):
		pass

	def Convert_Service_Data(self, service_data):
		binary_service_data = b""
		service_data_length = 0
		return (binary_service_data, service_data_length)

class SCCP_Message_Parser:

	def __init__(self):
		pass

class ISUP_Data:

	def __init__(self, cic, mes_type):
		self.cic = cic
		self.mes_type = mes_type
		self.mandatory_parameters = []
		self.optional_parameters = []

class Nature_Of_Connection_Indicators:

	def __init__(self, value):
		self.satellite_indicator = value & 0b00000011
		self.continuity_check_indicator = (value & 0b00001100) >> 2
		self.echo_control_device_indicator = (value & 0b00010000) >> 4
		self.spare = (value & 0b11100000) >> 5

class Forward_Call_Indicators:

	def __init__(self, value):
		self.national_international_call_indicator = (value & 0b0000000100000000) >> 8
		self.end_to_end_method_indicator = (value & 0b0000011000000000) >> 9
		self.interworking_indicator = (value & 0b0000100000000000) >> 11
		self.end_to_end_information_indicator = (value & 0b0001000000000000) >> 12
		self.isdn_user_part_indicator = (value & 0b0010000000000000) >> 13
		self.isdn_user_part_preference_indicator = (value & 0b1100000000000000) >> 14
		self.isdn_access_indicator = value & 0b0000000000000001
		self.sccp_method_indicator = (value & 0b0000000000000110) >> 1
		self.spare = (value & 0b0000000000001000) >> 3
		self.for_national_use = (value & 0b0000000011110000) >> 4

class Calling_Party_Category:

	def __init__(self, value):
		self.value = value

class Transmission_Medium_Requirement:

	def __init__(self, value):
		self.value = value

class Called_Party_Number:

	def __init__(self):
		self.odd_even_indicator = None
		self.nature_of_address_indicator = None
		self.inn_indicator = None
		self.numbering_plan_indicator = None
		self.spare = None
		self.digits = []

	def Build(self, value):
		self.odd_even_indicator = (value[0] & 0b10000000) >> 7
		self.nature_of_address_indicator = value[0] & 0b01111111
		self.inn_indicator = (value[1] & 0b10000000) >> 7
		self.numbering_plan_indicator = (value[1] & 0b01110000) >> 4
		self.spare = value[1] & 0b00001111
		if type(value) == bytes:
			self.digits = self.Extract_Digits(value[2:])
		elif type(value) == list:
			self.digits = list(value[2])
		return self

	def Extract_Digits(self, binary_value):
		digits_list = []
		for signal_pair in binary_value:
			address_signal1 = signal_pair & 0b00001111
			digits_list.append(address_signal1)
			address_signal2 = (signal_pair & 0b11110000) >> 4
			digits_list.append(address_signal2)
		if self.odd_even_indicator == 1:
			del digits_list[-1]
		return digits_list

class Backward_Call_Indicators:
	
	def __init__(self, value):
		self.charge_indicator = (value & 0b0000001100000000) >> 8
		self.called_party_status_indicator = (value & 0b0000110000000000) >> 10
		self.called_party_category_indicator = (value & 0b0011000000000000) >> 12
		self.end_to_end_method_indicator = (value & 0b1100000000000000) >> 14
		self.interworking_indicator = value & 0b0000000000000001
		self.end_to_end_information_indicator = (value & 0b0000000000000010) >> 1
		self.isdn_user_part_indicator = (value & 0b0000000000000100) >> 2
		self.holding_indicator = (value & 0b0000000000001000) >> 3
		self.isdn_access_indicator = (value & 0b0000000000010000) >> 4
		self.echo_control_device_indicator = (value & 0b0000000000100000) >> 5
		self.sccp_method_indicator = (value & 0b0000000011000000) >> 6

class Cause_Indicators:
	
	def __init__(self):
		self.location = None
		self.spare = None
		self.coding_standard = None
		self.cause_value = None
		self.diagnostic = None

	def Build(self, value):
		self.location = value[0] & 0b00001111
		self.spare = (value[0] & 0b00010000) >> 4
		self.coding_standard = (value[0] & 0b01100000) >> 5
		self.cause_value = value[1] & 0b01111111
		if type(value) == bytes:
			self.diagnostic = self.Diagnostic_Handling(value[3:], (value[0] & 0b10000000) >> 7, (value[1] & 0b10000000) >> 7)
		elif type(value) == list:
			self.diagnostic = value[2]
		return self

	def Diagnostic_Handling(self, diagnostic_info, *extentions):
		if extentions == (1,1):
			return None
		else:
			return self.Diagnostic(diagnostic_info)

	class Diagnostic:

		def __init__(self, info):
			self.info = info

class Subsequent_Number:

	def __init__(self):
		self.spare = None
		self.odd_even_indicator = None
		self.digits = []

	def Build(self, value):
		if type(value) == list:
			self.digits = value
		elif type(value) == bytes:
			self.spare = value[0] & 0b01111111
			self.odd_even_indicator = (value[0] & 0b10000000) >> 7
			self.digits = self.Extract_Digits(value[1:])
		return self

	def Extract_Digits(self, binary_value):
		digits_list = []
		for signal_pair in binary_value:
			address_signal1 = signal_pair & 0b00001111
			digits_list.append(address_signal1)
			address_signal2 = (signal_pair & 0b11110000) >> 4
			digits_list.append(address_signal2)
		if self.odd_even_indicator == 1:
			del digits_list[-1]
		return digits_list

class Information_Request_Indicators:

    def __init__(self):
         self.calling_party_address_request_indicator = None
         self.holding_indicator = None
         self.calling_party_category = None
         self.charge_information_request_indicator = None
         self.malicious_call_identification_request_indicator = None
         self.spare = None

class Information_Indicators:
    
    def __init__(self):
        self.calling_party_address_response_indicator = None
        self.hold_provided_indicator = None
        self.calling_party_category_response_indicator = None
        self.charge_information_response_indicator = None
        self.solicited_information_indicator = None
        self.spare = None	

class ISUP_Message_Parser:

	def __init__(self):
		self.parameters_handlers = {
		  1 : self.IAM_Parameters_Handler,
		  2 : self.SAM_Parameters_Handler,
		  6 : self.ACM_Parameters_Handler,
		  9 : self.ANM_Parameters_Handler,
		  12 : self.REL_Parameters_Handler,
		  16 : self.RLC_Parameters_Handler,
		  47 : self.CFN_Parameters_Handler
		}

	def Get_Variable_Parameters(self, binary_data):
		try:
			number_of_pointers = binary_data[0]
		except IndexError:
			raise ISUP_Error("no pointers to parameters")
		if number_of_pointers == 1:
			return [binary_data[1:]]
		elif number_of_pointers == 0:
			return [b""]
		variable_parameters = []
		end_of_pointers = False
		pointers_counter = 0
		while not end_of_pointers:
			pointer = int.from_bytes(binary_data[pointers_counter : pointers_counter + 1], byteorder="big")
			#print("   -pointer:", pointer)
			length_position = pointers_counter + pointer
			length = binary_data[length_position]
			#print("   -length:", length)
			pointers_counter += 1
			if pointers_counter == number_of_pointers:
				if pointer == 0:
					value = b""
				else:
					value = binary_data[length_position:]
				variable_parameters.append(value)
				end_of_pointers = True
			else:
				value = binary_data[length_position + 1 : length_position + 1 + length]
				variable_parameters.append(value)
		return variable_parameters

	def IAM_Parameters_Handler(self, binary_data):
		pattern = struct.Struct("> B H B B")
		try:
			unpacked_data = pattern.unpack(binary_data[:5])
		except struct.error:
			raise ISUP_Error("invalid IAM fixed mandatory part")
		else:
			#Сборка обязательных фиксированных параметров
			connection_indicators = Nature_Of_Connection_Indicators(unpacked_data[0])
			#print("satellite_indicator:", connection_indicators.satellite_indicator)
			#print("continuity_check_indicator:", connection_indicators.continuity_check_indicator)
			#print("echo_control_device_indicator:", connection_indicators.echo_control_device_indicator)
			#print("spare:", connection_indicators.spare)
			forward_call_indicators = Forward_Call_Indicators(unpacked_data[1])
			#print("isdn_access_indicator:", forward_call_indicators.isdn_access_indicator)
			#print("sccp_method_indicator:", forward_call_indicators.sccp_method_indicator)
			#print("spare:", forward_call_indicators.spare)
			#print("for_national_use:", forward_call_indicators.for_national_use)
			#print("national_international_call_indicator:", forward_call_indicators.national_international_call_indicator)
			#print("end_to_end_method_indicator:", forward_call_indicators.end_to_end_method_indicator)
			#print("interworking_indicator:", forward_call_indicators.interworking_indicator)
			#print("end_to_end_information_indicator:", forward_call_indicators.end_to_end_information_indicator)
			#print("isdn_user_part_indicator:", forward_call_indicators.isdn_user_part_indicator)
			#print("isdn_user_part_preference_indicator:", forward_call_indicators.isdn_user_part_preference_indicator)
			calling_party_category = Calling_Party_Category(unpacked_data[2])
			transmission_medium_requirement = Transmission_Medium_Requirement(unpacked_data[3])
			#Сборка обязательных переменных параметров
			variable_parameters = self.Get_Variable_Parameters(binary_data[5:])
			called_party_number = Called_Party_Number().Build(variable_parameters[0])
			#Сборка опциональных параметров
			optional_parameters = self.Optional_Parameters_Handler(variable_parameters[1])
			#print("nature_of_address_indicator:", called_party_number.nature_of_address_indicator)
			#print("odd_even_indicator:", called_party_number.odd_even_indicator)
			#print("spare:", called_party_number.spare)
			#print("numbering_plan_indicator:", called_party_number.numbering_plan_indicator)
			#print("inn_indicator:", called_party_number.inn_indicator)
			#print("digits:", called_party_number.digits)
			#Формирование списков параметров
			mandatory_parameters = [connection_indicators, forward_call_indicators, calling_party_category, transmission_medium_requirement, called_party_number]
			return (mandatory_parameters, optional_parameters)

	def ACM_Parameters_Handler(self, binary_data):
		pattern = struct.Struct("> H")
		try:
			unpacked_data = pattern.unpack(binary_data[:2])
		except struct.error:
			raise ISUP_Error("invalid ACM fixed mandatory part")
		else:
			#Сборка обязательных фиксированных параметров
			backward_call_indicators = Backward_Call_Indicators(unpacked_data[0])
			#print("interworking_indicator:", backward_call_indicators.interworking_indicator)
			#print("end_to_end_information_indicator:", backward_call_indicators.end_to_end_information_indicator)
			#print("isdn_user_part_indicator:", backward_call_indicators.isdn_user_part_indicator)
			#print("holding_indicator:", backward_call_indicators.holding_indicator)
			#print("isdn_access_indicator:", backward_call_indicators.isdn_access_indicator)
			#print("echo_control_device_indicator:", backward_call_indicators.echo_control_device_indicator)
			#print("sccp_method_indicator:", backward_call_indicators.sccp_method_indicator)
			#print("charge_indicator:", backward_call_indicators.charge_indicator)
			#print("called_party_status_indicator:", backward_call_indicators.called_party_status_indicator)
			#print("called_party_category_indicator:", backward_call_indicators.called_party_category_indicator)
			#print("end_to_end_method_indicator:", backward_call_indicators.end_to_end_method_indicator)
			#Сборка опциональных параметров
			variable_parameters = self.Get_Variable_Parameters(binary_data[2:])
			optional_parameters = self.Optional_Parameters_Handler(variable_parameters[0])
			#Формирование списков параметров
			mandatory_parameters = [backward_call_indicators]
			return (mandatory_parameters, optional_parameters)

	def ANM_Parameters_Handler(self, binary_data):
		#Сообщение ANM не содержит обязательных параметров
		mandatory_parameters = []
		#Сборка опциональных параметров
		variable_parameters = self.Get_Variable_Parameters(binary_data)
		optional_parameters = self.Optional_Parameters_Handler(variable_parameters[0])
		return (mandatory_parameters, optional_parameters)

	def REL_Parameters_Handler(self, binary_data):
		#Сборка обязательных переменных параметров
		variable_parameters = self.Get_Variable_Parameters(binary_data)
		cause_indicators = Cause_Indicators().Build(variable_parameters[0])
		#print("location:", cause_indicators.location)
		#print("spare", cause_indicators.spare)
		#print("coding_standard:", cause_indicators.coding_standard)
		#print("cause_value:", cause_indicators.cause_value)
		#print("diagnostic:", cause_indicators.diagnostic)
		mandatory_parameters = [cause_indicators]
		#Сборка опциональных параметров
		optional_parameters = self.Optional_Parameters_Handler(variable_parameters[1])
		return (mandatory_parameters, optional_parameters)

	def RLC_Parameters_Handler(self, binary_data):
		#Сообщение RLC не содержит обязательных параметров
		mandatory_parameters = []
		#Сборка опциональных параметров
		variable_parameters = self.Get_Variable_Parameters(binary_data)
		optional_parameters = self.Optional_Parameters_Handler(variable_parameters[0])
		return (mandatory_parameters, optional_parameters)

	def CFN_Parameters_Handler(self, binary_data):
		#Сборка обязательных переменных параметров
		variable_parameters = self.Get_Variable_Parameters(binary_data)
		cause_indicators = Cause_Indicators().Build(variable_parameters[0])
		#print("location:", cause_indicators.location)
		#print("spare", cause_indicators.spare)
		#print("coding_standard:", cause_indicators.coding_standard)
		#print("cause_value:", cause_indicators.cause_value)
		#print("diagnostic:", cause_indicators.diagnostic)
		mandatory_parameters = [cause_indicators]
		#Сборка опциональных параметров
		optional_parameters = self.Optional_Parameters_Handler(variable_parameters[1])
		return (mandatory_parameters, optional_parameters)

	def SAM_Parameters_Handler(self, binary_data):
		#Сборка обязательных переменных параметров
		variable_parameters = self.Get_Variable_Parameters(binary_data)
		subsequent_number = Subsequent_Number().Build(variable_parameters[0])
		#print("#----------------------------------------#")
		#print("    spare:", subsequent_number.spare)
		#print("    odd_even_indicator:", subsequent_number.odd_even_indicator)
		#print("    digits:", subsequent_number.digits)
		#print("#----------------------------------------#")
		mandatory_parameters = [subsequent_number]
		#Сборка опциональных параметров
		optional_parameters = self.Optional_Parameters_Handler(variable_parameters[1])
		return (mandatory_parameters, optional_parameters)

	def Optional_Parameters_Handler(self, binary_data):
		return binary_data

	def Add_Bit_Paddings(self, bin_value):
		end_of_padding = False
		while not end_of_padding:
			if len(bin_value) != 8:
				bin_value = "0" + bin_value
			else:
				end_of_padding = True
		return bin_value

	def Parse_CIC_Value(self, cic_bytes):
		byte1 = bin(int.from_bytes(cic_bytes[:1], byteorder="big"))[2:]
		byte2 = bin(int.from_bytes(cic_bytes[1:], byteorder="big"))[2:]
		byte1 = self.Add_Bit_Paddings(byte1)
		cic_value = int((byte2 + byte1), 2)
		return cic_value

	def Parse_Protocol_Data(self, binary_data):
		#Извлечение значений cic и message type
		cic = self.Parse_CIC_Value(binary_data[:2])
		mes_type = int.from_bytes(binary_data[2:3], byteorder="big")
		#Создание объекта isup
		isup_data = ISUP_Data(cic=cic, mes_type=mes_type)
		#Обработка параметров сообщения
		try:
			isup_data.mandatory_parameters, isup_data.optional_parameters = self.parameters_handlers[mes_type](binary_data[3:])
		except KeyError:
			raise ISUP_Error("unknown or unsupported message type: \"%s\"" % mes_type)
		else:
			return isup_data

class ISUP_Message_Builder:

	def __init__(self):
		self.mandatory_part_lengths = self.Define_Mandatory_Part_Lengths()
		self.parameter_builders = self.Define_Parameter_Builders()
		self.address_signals = (0,1,2,3,4,5,6,7,8,9,11,12,15)

	def Define_Parameter_Builders(self):
		builders = {
		  "nature_of_connection_indicators" : self.Build_Nature_Of_Connection_Indicators,
		  "forward_call_indicators" : self.Build_Forward_Call_Indicators,
		  "calling_party_category" : self.Build_Calling_Party_Category,
		  "transmission_medium_requirement" : self.Build_Transmission_Medium_Requirement,
		  "called_party_number" : self.Build_Called_Party_Number,
		  "backward_call_indicators" : self.Build_Backward_Call_Indicators,
		  "cause_indicators" : self.Build_Cause_Indicators,
		  "subsequent_number" : self.Build_Subsequent_Number
		}
		return builders

	def Define_Mandatory_Part_Lengths(self):
		#Код сообщения : количество обязательных параметров (фиксированных и переменных)
		lengths = {
		  1 : 5,
		  2 : 1,
		  6 : 1,
		  9 : 0,
		  12 : 1,
		  16 : 0,
		  47 : 1
		}
		return lengths

	def Build_Nature_Of_Connection_Indicators(self, value):
		if type(value) != int:
			raise ISUP_Error("nature_of_connection_indicators must be int value")
		else:
			return Nature_Of_Connection_Indicators(value)

	def Build_Forward_Call_Indicators(self, value):
		if type(value) != int:
			raise ISUP_Error("forward_call_indicators must be int value")
		else:
			return Forward_Call_Indicators(value)

	def Build_Calling_Party_Category(self, value):
		if type(value) != int:
			raise ISUP_Error("calling_party_category must be int value")
		else:
			return Calling_Party_Category(value)

	def Build_Transmission_Medium_Requirement(self, value):
		if type(value) != int:
			raise ISUP_Error("transmission_medium_requirement must be int value")
		else:
			return Transmission_Medium_Requirement(value)

	def Check_Raw_CDPN_Value(self, value):
		if type(value) != list or len(value) != 3:
			raise ISUP_Error("called_party_number value must be list by pattern: \"[byte1, byte2, (addr_sig1, addr_sigN)]\"")
		elif type(value[0]) != int or type(value[1]) != int or type(value[2]) != tuple:
			raise ISUP_Error("called_party_number value must match the pattern: \"[byte1, byte2, (addr_sig1, addr_sigN)]\"")
		else:
			for address_signal in value[2]:
				if not address_signal in self.address_signals:
					raise ISUP_Error("invalid address signals list")

	def Build_Called_Party_Number(self, value):
		self.Check_Raw_CDPN_Value(value)
		return Called_Party_Number().Build(value)

	def Build_Backward_Call_Indicators(self, value):
		if type(value) != int:
			raise ISUP_Error("backward_call_indicators must be int value")
		else:
			return Backward_Call_Indicators(value)

	def Check_Raw_Cause_Indicators_Value(self, value):
		if type(value) != list or len(value) != 3:
			raise ISUP_Error("cause_indicators value must be a list by pattern: \"[byte1, byte2, diagnostic]\"")
		elif type(value[0]) != int or type(value[1]) != int:
			raise ISUP_Error("cause_indicators value must match the pattern: \"[byte1, byte2, diagnostic]\"") 

	def Build_Cause_Indicators(self, value):
		self.Check_Raw_Cause_Indicators_Value(value)
		return Cause_Indicators().Build(value)

	def Check_Raw_Subsequent_Number_Value(self, value):
		if type(value) != list:
			raise ISUP_Error("subsequent_number value must be a list by pattern: \"[addr_sig1, addr_sigN]\"")
		else:
			for address_signal in value:
				if not address_signal in self.address_signals:
					raise ISUP_Error("invalid address signals list")

	def Build_Subsequent_Number(self, value):
		self.Check_Raw_Subsequent_Number_Value(value)
		return Subsequent_Number().Build(value)

	def Parameters_Building(self, parameters_dict):
		parameters = []
		for key, value in parameters_dict.items():
			parameter = self.parameter_builders[key](value)
			parameters.append(parameter)
		return parameters

	def Form_Parameters_Dict(self, keys_list, parameters):
		parameters_dict = {}
		for key in keys_list:
			parameters_dict[key] = parameters[key]
		return parameters_dict 

	def Form_Keys_Lists(self, keys_list, mandatory_part_length):
		mandatory_keys_list = keys_list[2 : 2 + mandatory_part_length]
		optional_keys_list = keys_list[2 + mandatory_part_length:]
		return (mandatory_keys_list, optional_keys_list)

	def Get_Parameters_Keys(self, parameters):
		keys_list = []
		for key in parameters.keys():
			keys_list.append(key)
		return keys_list

	def Split_Parameters(self, parameters):
		try:
			mandatory_part_length = self.mandatory_part_lengths[parameters["mes_type"]]
		except KeyError:
			raise ISUP_Error("unknown or unsupported message type: \"%s\"" % parameters["mes_type"])
		else:
			keys_list = self.Get_Parameters_Keys(parameters)
			mandatory_keys_list, optional_keys_list = self.Form_Keys_Lists(keys_list, mandatory_part_length)
			mandatory_part = self.Form_Parameters_Dict(mandatory_keys_list, parameters)
			optional_part = self.Form_Parameters_Dict(optional_keys_list, parameters)
			return (mandatory_part, optional_part)

	def Build_Protocol_Data(self, kwargs):
		isup_data = ISUP_Data(kwargs["cic"], kwargs["mes_type"])
		mandatory_part, optional_part = self.Split_Parameters(kwargs)
		isup_data.mandatory_parameters = self.Parameters_Building(mandatory_part)
		isup_data.optional_parameters = self.Parameters_Building(optional_part)
		#print("cic:", isup_data.cic)
		#print("mes_type:", isup_data.mes_type)
		#print("mandatory_parameters:", isup_data.mandatory_parameters)
		#print("optional_parameters:", isup_data.optional_parameters)
		return isup_data

class ISUP_Binary_Convertor:

	def __init__(self):
		self.parameter_convertors = self.Define_Parameter_Convertors()
		self.fixed_parameters_number = self.Define_Mandatory_Fixed_Parameters_Numbers()
		self.isup_header_length = 3

	def Define_Parameter_Convertors(self):
		convertors = {
		  Nature_Of_Connection_Indicators : self.Convert_Nature_Of_Connection_Indicators,
		  Forward_Call_Indicators : self.Convert_Forward_Call_Indicators,
		  Calling_Party_Category : self.Convert_Calling_Party_Category,
		  Transmission_Medium_Requirement : self.Convert_Transmission_Medium_Requirement,
		  Called_Party_Number : self.Convert_Called_Party_Number,
		  Backward_Call_Indicators : self.Convert_Backward_Call_Indicators,
		  Cause_Indicators : self.Convert_Cause_Indicators,
		  Subsequent_Number : self.Convert_Subsequent_Number
		}
		return convertors

	def Define_Mandatory_Fixed_Parameters_Numbers(self):
		#Код сообщения : количество обязательных фиксированных параметров
		lengths = {
		  1 : 4,
		  2 : 0,
		  6 : 1,
		  9 : 0,
		  12 : 0,
		  16 : 0,
		  47 : 0
		}
		return lengths

	def Convert_Nature_Of_Connection_Indicators(self, parameter):
		parameter_length = 1
		parameter_value = parameter.satellite_indicator
		parameter_value += parameter.continuity_check_indicator << 2
		parameter_value += parameter.echo_control_device_indicator << 4
		parameter_value += parameter.spare << 5
		binary_parameter = parameter_value.to_bytes(parameter_length, byteorder="big")
		return binary_parameter

	def Convert_Forward_Call_Indicators(self, parameter):
		parameter_length = 2
		parameter_value = parameter.isdn_access_indicator
		parameter_value += parameter.sccp_method_indicator << 1
		parameter_value += parameter.spare << 3
		parameter_value += parameter.for_national_use << 4
		parameter_value += parameter.national_international_call_indicator << 8
		parameter_value += parameter.end_to_end_method_indicator << 9
		parameter_value += parameter.interworking_indicator << 11
		parameter_value += parameter.end_to_end_information_indicator << 12
		parameter_value += parameter.isdn_user_part_indicator << 13
		parameter_value += parameter.isdn_user_part_preference_indicator << 14
		binary_parameter = parameter_value.to_bytes(parameter_length, byteorder="big")
		return binary_parameter

	def Convert_Calling_Party_Category(self, parameter):
		parameter_length = 1
		binary_parameter = parameter.value.to_bytes(parameter_length, byteorder="big")
		return binary_parameter

	def Convert_Transmission_Medium_Requirement(self, parameter):
		parameter_length = 1
		binary_parameter = parameter.value.to_bytes(parameter_length, byteorder="big")
		return binary_parameter

	def Convert_Address_Signals(self, digits):
		binary_address_signals = b""
		if len(digits) % 2 != 0:
			digits.append(0)
		pairs_number = len(digits) // 2
		for index in range(0, len(digits), 2):
			digit_pair = digits[index:index+2]
			digit_pair_value = digit_pair[0] + (digit_pair[1] << 4)
			binary_digit_pair = digit_pair_value.to_bytes(1, byteorder="big")
			binary_address_signals += binary_digit_pair
		return binary_address_signals

	def Convert_Called_Party_Number(self, parameter):
		byte1_value = parameter.nature_of_address_indicator
		byte1_value += parameter.odd_even_indicator << 7
		byte2_value = parameter.spare
		byte2_value += parameter.numbering_plan_indicator << 4
		byte2_value += parameter.inn_indicator << 7
		byte1 = byte1_value.to_bytes(1, byteorder="big")
		byte2 = byte2_value.to_bytes(1, byteorder="big")
		binary_indicators = byte1 + byte2
		binary_digits = self.Convert_Address_Signals(parameter.digits)
		binary_parameter = binary_indicators + binary_digits
		return binary_parameter

	def Convert_Backward_Call_Indicators(self, parameter):
		parameter_length = 2
		parameter_value = parameter.charge_indicator << 8
		parameter_value += parameter.called_party_status_indicator << 10
		parameter_value += parameter.called_party_category_indicator << 12
		parameter_value += parameter.end_to_end_method_indicator << 14
		parameter_value += parameter.interworking_indicator
		parameter_value += parameter.end_to_end_information_indicator << 1
		parameter_value += parameter.isdn_user_part_indicator << 2
		parameter_value += parameter.holding_indicator << 3
		parameter_value += parameter.isdn_access_indicator << 4
		parameter_value += parameter.echo_control_device_indicator << 5
		parameter_value += parameter.sccp_method_indicator << 6
		binary_parameter = parameter_value.to_bytes(parameter_length, byteorder="big")
		return binary_parameter

	def Convert_Cause_Indicators(self, parameter):
		byte1_value = parameter.location
		byte1_value += parameter.spare << 4
		byte1_value += parameter.coding_standard << 5
		byte1_value += 128 #extention indicator
		byte2_value = parameter.cause_value
		byte2_value += 128 #extention indicator
		byte1 = byte1_value.to_bytes(1, byteorder="big")
		byte2 = byte2_value.to_bytes(1, byteorder="big")
		diagnostic = b""
		binary_parameter = byte1 + byte2 + diagnostic
		return binary_parameter

	def Convert_Subsequent_Number(self, parameter):
		if len(parameter.digits) % 2 == 0:
			odd_even_indicator = 0
		else:
			odd_even_indicator = 1
		byte1 = (0 + (odd_even_indicator << 7)).to_bytes(1, byteorder="big")
		binary_digits = self.Convert_Address_Signals(parameter.digits)
		binary_parameter = byte1 + binary_digits
		return binary_parameter

	def Convert_Optional_Parameters(self, parameters):
		return b""

	def Get_Common_Mandatory_Variable_Parameters_Length(self, parameters_dict):
		common_length = 0
		for parameter,length in parameters_dict.items():
			common_length += length
		return common_length

	def Convert_Mandatory_Variable_Parameters(self, parameters):
		mandatory_variable_parameters = {}
		for parameter in parameters:
			binary_parameter = self.parameter_convertors[type(parameter)](parameter)
			parameter_length = len(binary_parameter)
			binary_parameter = parameter_length.to_bytes(1, byteorder="big") + binary_parameter
			mandatory_variable_parameters[binary_parameter] = parameter_length + 1
		common_parameters_length = self.Get_Common_Mandatory_Variable_Parameters_Length(mandatory_variable_parameters)
		return (mandatory_variable_parameters, common_parameters_length)

	def Get_Previous_Parameters_Length(self, index, mandatory_variable_parameters):
		parameters_keys = []
		previous_parameters_length = 0
		for parameter_key in mandatory_variable_parameters.keys():
			parameters_keys.append(parameter_key)
		parameters_keys = parameters_keys[:index-1]
		for parameter_key in parameters_keys:
			previous_parameters_length += mandatory_variable_parameters[parameter_key]
		return previous_parameters_length

	def Get_Binary_Pointers_Values(self, pointers_values):
		binary_pointers = b""
		for pointer_value in pointers_values:
			binary_pointers += pointer_value.to_bytes(1, byteorder="big")
		return binary_pointers

	def Get_Binary_Variable_Parameters(self, mandatory_variable_parameters_dict):
		binary_parameters = b""
		for parameter in mandatory_variable_parameters_dict.keys():
			binary_parameters += parameter
		return binary_parameters

	def Convert_Variable_Part(self, mandatory_parameters, optional_pointer, optional_part):
		pointers_number = len(mandatory_parameters) + 1
		pointers_values = [None] * pointers_number
		mandatory_variable_parameters, mandatory_parameters_length = self.Convert_Mandatory_Variable_Parameters(mandatory_parameters)
		for index in range(1, pointers_number + 1):
			if index == 1 and not optional_pointer:
				pass 
			elif index == 1 and not optional_part:
				pointers_values[-index] = 0
			elif index == 1:
				pointers_values[-index] = mandatory_parameters_length + index
			else:
				previous_parameters_length = self.Get_Previous_Parameters_Length(index, mandatory_variable_parameters)
				pointers_values[-index] = mandatory_parameters_length - previous_parameters_length + index
		binary_parameters = self.Get_Binary_Variable_Parameters(mandatory_variable_parameters)
		pointers = self.Get_Binary_Pointers_Values(pointers_values)
		variable_part = pointers + binary_parameters
		return variable_part

	def Convert_Mandatory_Fixed_Part(self, parameters):
		binary_parameters = b""
		for parameter in parameters:
			binary_parameter = self.parameter_convertors[type(parameter)](parameter)
			binary_parameters += binary_parameter
		return binary_parameters

	def Convert_Bin_To_Decimal(self, bin_value):
		if not bin_value:
			bin_value = "0"
		decimal_value = int(bin_value, 2)
		return decimal_value

	def Form_CIC_Bytes(self, cic_value):
		bin_cic_value = bin(cic_value)[2:]
		bin_cic_length = len(bin_cic_value)
		byte1_value = self.Convert_Bin_To_Decimal(bin_cic_value[bin_cic_length-8:])
		byte2_value = self.Convert_Bin_To_Decimal(bin_cic_value[:bin_cic_length-8])
		return (byte1_value, byte2_value)

	def Convert_CIC(self, cic_value):
		if cic_value < 0 or cic_value > 4095:
			raise ISUP_Error("cic value must be in range of 0 and 4095")
		byte1_value, byte2_value = self.Form_CIC_Bytes(cic_value) 
		byte1 = byte1_value.to_bytes(1, byteorder="big")
		byte2 = byte2_value.to_bytes(1, byteorder="big")
		binary_cic = byte1 + byte2
		return binary_cic

	def Convert_Service_Data(self, service_data):
		cic = self.Convert_CIC(service_data.cic)
		mes_type = service_data.mes_type.to_bytes(1, byteorder="big")
		isup_header = cic + mes_type
		number_of_fixed_parameters = self.fixed_parameters_number[service_data.mes_type]
		fixed_part = self.Convert_Mandatory_Fixed_Part(service_data.mandatory_parameters[:number_of_fixed_parameters])
		optional_part = self.Convert_Optional_Parameters(service_data.optional_parameters)
		if service_data.optional_parameters is None:
			variable_part = self.Convert_Variable_Part(service_data.mandatory_parameters[number_of_fixed_parameters:], optional_pointer=False, optional_part=False)
		else:
			variable_part = self.Convert_Variable_Part(service_data.mandatory_parameters[number_of_fixed_parameters:], optional_pointer=True, optional_part=bool(optional_part))
		binary_service_data = isup_header + fixed_part + variable_part + optional_part
		service_data_length = len(binary_service_data)
		return (binary_service_data, service_data_length)

class ISUP_Error(Exception):

	def __init__(self, description):
		self.description = description

class Binary_Convertor:

	def __init__(self):
		self.sccp_binary_convertor = SCCP_Binary_Convertor()
		self.isup_binary_convertor = ISUP_Binary_Convertor()
		self.common_m2ua_header_pattern = struct.Struct(">B B B B L")
		self.m2ua_parameter_header_pattern = struct.Struct(">H H")
		self.m2ua_padding_parameter_pattern = struct.Struct(">B")
		self.mtp3_routing_label_pattern = struct.Struct(">B B B B")
		self.m2ua_parameter_header_length = 4
		self.m2ua_header_length = 8
		self.mtp3_data_length = 5

	def Convert_Int_To_Bytes(self, int_value, bytes_number):
		bytes_string = int_value.to_bytes(bytes_number, byteorder="big")
		return bytes_string

	def Convert_Bytes_To_Int(self, bytes_string):
		int_value = int.from_bytes(bytes_string, byteorder="big")
		return int_value

	def Bytes_Number_Counting(self, int_value):
		hex_value = hex(int_value)[2:]
		bytes_number = math.ceil(len(hex_value) / 2)
		return bytes_number 

	def Create_M2UA_Parameter_Padding(self, padding_bytes_number):
		padding_value = (0)
		padding_byte = self.m2ua_padding_parameter_pattern.pack(padding_value)
		padding = padding_byte * padding_bytes_number
		return padding

	def Searching_For_Multiple_Length(self, parameter_length):
		initial_parameter_length = parameter_length
		for i in range(1,4):
			parameter_length = initial_parameter_length + i
			if parameter_length % 4 == 0:
				multiple_length = parameter_length
				break
		else:
			raise M2UA_Error("padding bytes counting error")
		return multiple_length

	def Forming_M2UA_Parameter_Padding(self, parameter_length):
		if parameter_length % 4 == 0:
			return b""
		else:
			multiple_length = self.Searching_For_Multiple_Length(parameter_length)
			padding_bytes_number = multiple_length - parameter_length
			padding = self.Create_M2UA_Parameter_Padding(padding_bytes_number)
			return padding

	def String_Parameter_Length_Check(self, string_parameter_value, parameter_length):
		if len(string_parameter_value) != parameter_length - self.m2ua_parameter_header_length:
			raise M2UA_Error("m2ua str parameter length \"%s\" is bigger than allowable length" % len(string_parameter_value))

	def Convert_String_Parameter_Value(self, parameter_value, parameter_length=None):
		binary_parameter_value = parameter_value.encode("utf-8")
		if parameter_length:
			binary_parameter_length = parameter_length
			self.String_Parameter_Length_Check(binary_parameter_value, parameter_length)
		else:
			binary_parameter_length = len(binary_parameter_value) + self.m2ua_parameter_header_length
		return (binary_parameter_value, binary_parameter_length)

	def Convert_Int_Parameter_Value(self, parameter_value, parameter_length=None):
		if parameter_length:
			binary_parameter_length = parameter_length
			try:
				binary_parameter_value = parameter_value.to_bytes(parameter_length - self.m2ua_parameter_header_length, byteorder="big")
			except OverflowError:
				raise M2UA_Error("m2ua int parameter value is \"%s\" is bigger than allowable value"% parameter_value)
		else:
			value_length = self.Bytes_Number_Counting(parameter_value)
			binary_parameter_value = parameter_value.to_bytes(value_length, byteorder="big")
			binary_parameter_length = value_length + self.m2ua_parameter_header_length
		return (binary_parameter_value, binary_parameter_length)

	def Convert_List_Parameter_Value(self, parameters_list):
		total_parameter_length = self.m2ua_parameter_header_length
		total_binary_parameter_value = b""
		for parameter in parameters_list:
			if type(parameter) == int:
				binary_parameter_value, dummy = self.Convert_Int_Parameter_Value(parameter, parameter_length=8)
				total_binary_parameter_value = total_binary_parameter_value + binary_parameter_value
				total_parameter_length = total_parameter_length + 4
			elif type(parameter) == M2UA_Parameter:
				binary_parameter, binary_parameter_length = self.Convert_M2UA_Parameter(parameter)
				total_binary_parameter_value = total_binary_parameter_value + binary_parameter
				total_parameter_length = total_parameter_length + binary_parameter_length
			else:
				raise M2UA_Error("unsupported element type in parameters list")
		return (total_binary_parameter_value, total_parameter_length)

	def Convert_SIO_Data(self, sio):
		sio_value = sio.service_indicator
		sio_value += sio.spare << 4 
		sio_value += sio.network_indicator << 6
		binary_sio_data = sio_value.to_bytes(1, byteorder="big")
		return binary_sio_data

	def Convert_Decimal_To_Bin(self, decimal_value, length):
		bin_value = bin(decimal_value)[2:]
		end_of_padding = False
		while not end_of_padding:
			if len(bin_value) != length:
				bin_value = "0" + bin_value
			else:
				end_of_padding = True
		return bin_value

	def Convert_Routing_Label_Data(self, routing_label):
		dpc = self.Convert_Decimal_To_Bin(routing_label.dpc, length=14)
		opc = self.Convert_Decimal_To_Bin(routing_label.opc, length=14)
		link_selector = self.Convert_Decimal_To_Bin(routing_label.link_selector, length=4)
		byte4_value = int(opc[:4], 2) + (int(link_selector,2) << 4)
		byte3_value = int(opc[4:12], 2)
		byte2_value = int(dpc[:6], 2) + (int(opc[-2:], 2) << 6)
		byte1_value = int(dpc[-8:],2)
		bytes_values = (byte1_value, byte2_value, byte3_value, byte4_value)
		binary_routing_label_data = self.mtp3_routing_label_pattern.pack(*bytes_values)
		return binary_routing_label_data

	def Convert_Service_Data(self, service_indicator, service_data):
		if service_indicator == 3:
			return self.sccp_binary_convertor.Convert_Service_Data(service_data)
		elif service_indicator == 5:
			return self.isup_binary_convertor.Convert_Service_Data(service_data)

	def Convert_MTP3_Data(self, mtp3_data):
		mtp3_binary_data = self.Convert_SIO_Data(mtp3_data.sio) + self.Convert_Routing_Label_Data(mtp3_data.routing_label)
		service_data, service_data_length = self.Convert_Service_Data(mtp3_data.sio.service_indicator, mtp3_data.service_data) 
		binary_parameter_value = mtp3_binary_data + service_data
		binary_parameter_length = self.m2ua_parameter_header_length + self.mtp3_data_length + service_data_length
		return (binary_parameter_value, binary_parameter_length)

	def M2UA_Parameter_Forming(self, parameter_value, parameter_length=None):
		if type(parameter_value) == str:
			binary_parameter_value, binary_parameter_length = self.Convert_String_Parameter_Value(parameter_value, parameter_length)
		elif type(parameter_value) == int:
			binary_parameter_value, binary_parameter_length = self.Convert_Int_Parameter_Value(parameter_value, parameter_length)
		elif type(parameter_value) == list:
			binary_parameter_value, binary_parameter_length = self.Convert_List_Parameter_Value(parameter_value)
		elif type(parameter_value) == MTP3_Data:
			binary_parameter_value, binary_parameter_length = self.Convert_MTP3_Data(parameter_value)
		else:
			raise M2UA_Error("unsupported type of m2ua parameter")
		return (binary_parameter_value, binary_parameter_length)

	def Convert_M2UA_Parameter_Value(self, object_parameter):
		if not object_parameter.length:
			binary_parameter_value, parameter_length = self.M2UA_Parameter_Forming(object_parameter.value)
		elif object_parameter.length < 4:
			raise M2UA_Error("m2ua parameter length must not be less than 4")
		elif object_parameter.length == 4:
			binary_parameter_value = b""
			parameter_length = object_parameter.length
		else:
			binary_parameter_value, parameter_length = self.M2UA_Parameter_Forming(object_parameter.value, object_parameter.length)
		return (binary_parameter_value, parameter_length)

	def Convert_M2UA_Parameter(self, object_parameter): 
		binary_parameter_value, parameter_length = self.Convert_M2UA_Parameter_Value(object_parameter)
		packet_values = (object_parameter.tag, parameter_length)
		binary_parameter_header = self.m2ua_parameter_header_pattern.pack(*packet_values)
		padding = self.Forming_M2UA_Parameter_Padding(parameter_length)
		binary_parameter = binary_parameter_header + binary_parameter_value + padding
		return (binary_parameter, parameter_length + len(padding))

	def Get_M2UA_Parameters_Info(self, object_message):
		parameters_length = 0
		binary_parameters_list = []
		for parameter in object_message.parameters:
			binary_parameter, parameter_length = self.Convert_M2UA_Parameter(parameter)
			binary_parameters_list.append(binary_parameter)
			parameters_length = parameters_length + parameter_length
		return (binary_parameters_list, parameters_length)

	def Get_M2UA_Parameters_String(self, parameters_list):
	    parameters_string = b""
	    for parameter in parameters_list:
	        parameters_string = parameters_string + parameter
	    return parameters_string 

	def Convert_M2UA_Message(self, object_message):
		binary_parameters_list, parameters_length = self.Get_M2UA_Parameters_Info(object_message)
		object_message.length = self.m2ua_header_length + parameters_length 
		packet_values = (object_message.version, object_message.spare, object_message.mes_class, object_message.mes_type, object_message.length)
		m2ua_header = self.common_m2ua_header_pattern.pack(*packet_values)
		m2ua_parameters = self.Get_M2UA_Parameters_String(binary_parameters_list)
		m2ua_message = m2ua_header + m2ua_parameters
		return m2ua_message

class Message_Builder:

	def __init__(self):
		self.mtp3 = None
		self.sccp_builder = SCCP_Message_Builder()
		self.isup_builder = ISUP_Message_Builder()
		self.convertor = Binary_Convertor()

	def Define_MTP3_Properties(self, opc, dpc, link_selector, network_indicator=2):
		self.mtp3 = MTP3_Data()
		self.mtp3.sio = self.mtp3.Service_Information_Octet(network_indicator=network_indicator)
		self.mtp3.routing_label = self.mtp3.Routing_Label(dpc=dpc, opc=opc, link_selector=link_selector)

	def Get_M2UA_Parameter_Info(self, object_parameter):
		if object_parameter.tag == 11:
			parameter_info = object_parameter.Define_Traffic_Mode_Type_Values()
			return (parameter_info, "traffic mode type")
		elif object_parameter.tag == 12:
			parameter_info = object_parameter.Define_Error_Code_Values()
			return (parameter_info, "error code")
		elif object_parameter.tag == 13:
			parameter_info = object_parameter.Define_Status_Type_Values()
			return (parameter_info, "status type")
		elif object_parameter.tag == 770:
			parameter_info = object_parameter.Define_State_Parameter_Values()
			return (parameter_info, "state")
		elif object_parameter.tag == 771:
			parameter_info = object_parameter.Define_Event_Parameter_Values()
			return (parameter_info, "event")
		elif object_parameter.tag == 772:
			parameter_info = object_parameter.Define_Congestion_And_Discard_Status_Values()
			return (parameter_info, "congestion status")
		elif object_parameter.tag == 773:
			parameter_info = object_parameter.Define_Congestion_And_Discard_Status_Values()
			return (parameter_info, "discard status")
		elif object_parameter.tag == 774:
			parameter_info = object_parameter.Define_Action_Values()
			return (parameter_info, "action")
		elif object_parameter.tag == 776:
			parameter_info = object_parameter.Define_Result_Values()
			return (parameter_info, "result")
		elif object_parameter.tag == 782:
			parameter_info = object_parameter.Define_Registration_Status_Values()
			return (parameter_info, "registration status")
		elif object_parameter.tag == 784:
			parameter_info = object_parameter.Define_Deregistration_Status_Values()
			return (parameter_info, "deregistration status")
		else:
			raise M2UA_Error("m2ua parameter tag \"%s\" does not support" % object_parameter.tag)

	def Get_Parameter_Value(self, object_parameter, parameter_definition):
		parameter_values, parameter_name = self.Get_M2UA_Parameter_Info(object_parameter)
		if type(parameter_definition) == int:
			for parameter_number in parameter_values.keys():
				if parameter_definition == parameter_number:
					break
			else:
				raise M2UA_Error("\"%s\" is unknown m2ua %s parameter value" % (parameter_definition, parameter_name))
			return parameter_definition
		elif type(parameter_definition) == str:
			for parameter_number, parameter_description in parameter_values.items():
				if parameter_definition == parameter_description:
					parameter_value = parameter_number
					break
			else:
				raise M2UA_Error("\"%s\" is unknown m2ua %s parameter value" % (parameter_definition, parameter_name))
			return parameter_value
		else:
			raise M2UA_Error("m2ua %s parameter must be int or str" % parameter_name)

	def Generate_Correlation_Id(self):
		correlation_id_value = random.randint(1,math.pow(2,32))
		return correlation_id_value

	def Build_State_Parameter(self, state_definition):
		state = M2UA_Parameter(tag=770)
		state.value = self.Get_Parameter_Value(state, state_definition)
		return state

	def Build_Event_Parameter(self, event_definition):
		event = M2UA_Parameter(tag=771)
		event.value = self.Get_Parameter_Value(event, event_definition)
		return event

	def Build_Result_Parameter(self, result_definition):
		result = M2UA_Parameter(tag=776)
		result.value = self.Get_Parameter_Value(result, result_definition)
		return result

	def Build_Action_Parameter(self, action_definition):
		action = M2UA_Parameter(tag=774)
		action.value = self.Get_Parameter_Value(action, action_definition)
		return action

	def Build_Sequence_Number_Parameter(self, sequence_number_definition):
		sequence_number = M2UA_Parameter(tag=775)
		if type(sequence_number_definition) == int:
			sequence_number.value = sequence_number_definition
			return sequence_number
		else:
			raise M2UA_Error("m2ua sequence number parameter must be int")

	def Build_Congestion_Status_Parameter(self, congestion_status_definition):
		congestion_status = M2UA_Parameter(tag=772)
		congestion_status.value = self.Get_Parameter_Value(congestion_status, congestion_status_definition)
		return congestion_status

	def Build_Discard_Status_Parameter(self, discard_status_definition):
		discard_status = M2UA_Parameter(tag=773)
		discard_status.value = self.Get_Parameter_Value(discard_status, discard_status_definition)
		return discard_status

	def Get_Status_Information_Value(self, object_parameter, status_type, status_information):
		if status_type == 1:
			status_information_values = object_parameter.Define_AS_State_Change_Status_Information_Values()
		else:
			status_information_values = object_parameter.Define_Other_Status_Information_Values()
		if type(status_information) == int:
			for parameter_number in status_information_values.keys():
				if status_information == parameter_number:
					break
			else:
				raise M2UA_Error("\"%s\" is unknown m2ua status information parameter value of status type \"%s\"" % (status_information, status_type))
			return status_information
		elif type(status_information) == str:
			for parameter_number, parameter_description in status_information_values.items():
				if status_information == parameter_description:
					parameter_value = parameter_number
					break
			else:
				raise M2UA_Error("\"%s\" is unknown m2ua status information parameter value of status type \"%s\"" % (status_information, status_type))
			return parameter_value
		else:
			raise M2UA_Error("m2ua status information parameter must be int or str")

	def Composite_Parameter_Value_Forming(self, first_value, second_value):
		binary_first_value = self.convertor.Convert_Int_To_Bytes(int_value=first_value, bytes_number=2)
		binary_second_value = self.convertor.Convert_Int_To_Bytes(int_value=second_value, bytes_number=2)
		binary_composite_value = binary_first_value + binary_second_value
		composite_value = self.convertor.Convert_Bytes_To_Int(binary_composite_value)
		return composite_value

	def Build_Status_Parameter(self, status_type_definition, status_information_definition):
		status = M2UA_Parameter(tag=13)
		status_type = self.Get_Parameter_Value(status, status_type_definition)
		status_information = self.Get_Status_Information_Value(status, status_type, status_information_definition)
		status.value = self.Composite_Parameter_Value_Forming(status_type, status_information)
		return status

	def Build_Correlation_Id_Parameter(self, cid=None):
		correlation_id = M2UA_Parameter(tag=19)
		if cid:
			correlation_id.value = cid
		else:
			correlation_id.value = self.Generate_Correlation_Id()
		return correlation_id

	def Build_Deregistration_Status_Parameter(self, deregistration_status_definition):
		deregistration_status = M2UA_Parameter(tag=784)
		deregistration_status.value = self.Get_Parameter_Value(deregistration_status, deregistration_status_definition)
		return deregistration_status

	def Build_Registration_Status_Parameter(self, registration_status_definition):
		registration_status = M2UA_Parameter(tag=782)
		registration_status.value = self.Get_Parameter_Value(registration_status, registration_status_definition)
		return registration_status

	def Build_Signalling_Data_Link_Identifier(self, link_identifier_definition):
		link_identifier = M2UA_Parameter(tag=780)
		if type(link_identifier_definition) == int:
			link_identifier.value = self.Composite_Parameter_Value_Forming(0, link_identifier_definition)
			return link_identifier
		else:
			raise M2UA_Error("m2ua sdl identifier parameter must be int")

	def Build_Signalling_Data_Terminal_Identifier_Parameter(self, terminal_identifier_definition):
		terminal_identifier = M2UA_Parameter(tag=779)
		if type(terminal_identifier_definition) == int:
			terminal_identifier.value = self.Composite_Parameter_Value_Forming(0, terminal_identifier_definition)
			return terminal_identifier
		else:
			raise M2UA_Error("m2ua sdt identifier parameter must be int")

	def Build_Local_LK_Identifier_Parameter(self, local_lk_identifier_definition):
		local_lk_identifier = M2UA_Parameter(tag=778)
		if type(local_lk_identifier_definition) == int:
			local_lk_identifier.value = local_lk_identifier_definition
			return local_lk_identifier
		else:
			raise M2UA_Error("m2ua local lk identifier parameter must be int")

	def Composite_Parameters_List_Check(self, parameters_list, argument_name, elements_number=3):
		if type(parameters_list) != list:
			raise M2UA_Error("%s argument must be list" % argument_name)
		elif len(parameters_list) == 0:
			raise M2UA_Error("%s argument must not be empty" % argument_name)
		else:
			for element in parameters_list:
				if type(element) != tuple:
					raise M2UA_Error("wrong element type in %s argument" % argument_name)
				elif len(element) != elements_number:
					raise M2UA_Error("%s must be described by %s elements in tuple" % (argument_name, elements_number))

	def Build_Link_Key_Parameters(self, link_keys_definition):
		self.Composite_Parameters_List_Check(link_keys_definition, "link_keys")
		link_keys_list = []
		for parameter in link_keys_definition:
			link_key = M2UA_Parameter(tag=777)
			link_key.length = None
			link_key_identifiers_list = []
			local_lk_identifier = self.Build_Local_LK_Identifier_Parameter(parameter[0])
			link_key_identifiers_list.append(local_lk_identifier)
			terminal_identifier = self.Build_Signalling_Data_Terminal_Identifier_Parameter(parameter[1])
			link_key_identifiers_list.append(terminal_identifier)
			link_identifier = self.Build_Signalling_Data_Link_Identifier(parameter[2])
			link_key_identifiers_list.append(link_identifier)
			link_key.value = link_key_identifiers_list
			link_keys_list.append(link_key)
		return link_keys_list

	def Build_Deregistration_Result_Parameters(self, deregistration_results_definition):
		self.Composite_Parameters_List_Check(deregistration_results_definition, "deregistration_results", elements_number=2)
		results_list = []
		for parameter in deregistration_results_definition:
			dereg_result = M2UA_Parameter(tag=783)
			dereg_result.length = None
			dereg_result_list = []
			if type(parameter[0]) == int:
				interface_identifier = self.Build_Int_Interface_Identifier_Parameter(parameter[0])
			elif type(parameter[0]) == str:
				interface_identifier = self.Build_Str_Interface_Identifier_Parameter(parameter[0])
			else:
				raise M2UA_Error("unsupported value type in interface_identifier argument")
			dereg_result_list.append(interface_identifier)
			deregistration_status = self.Build_Deregistration_Status_Parameter(parameter[1])
			dereg_result_list.append(deregistration_status)
			dereg_result.value = dereg_result_list
			results_list.append(dereg_result)
		return results_list

	def Build_Registration_Result_Parameters(self, registration_results_definition):
		self.Composite_Parameters_List_Check(registration_results_definition, "registration_results")
		results_list = []
		for parameter in registration_results_definition:
			reg_result = M2UA_Parameter(tag=781)
			reg_result.length = None
			reg_result_list = []
			local_lk_identifier = self.Build_Local_LK_Identifier_Parameter(parameter[0])
			reg_result_list.append(local_lk_identifier)
			registration_status = self.Build_Registration_Status_Parameter(parameter[1])
			reg_result_list.append(registration_status)
			if type(parameter[2]) == int:
				interface_identifier = self.Build_Int_Interface_Identifier_Parameter(parameter[2])
			elif type(parameter[2]) == str:
				interface_identifier = self.Build_Str_Interface_Identifier_Parameter(parameter[2])
			else:
				raise M2UA_Error("unsupported value type in interface_identifier argument")
			reg_result_list.append(interface_identifier)
			reg_result.value = reg_result_list
			results_list.append(reg_result)
		return results_list

	def Build_Diagnostic_Information_Parameter(self, diagnostic_information_definition):
		diagnostic_information = M2UA_Parameter(tag=7)
		diagnostic_information.length = None
		if type(diagnostic_information_definition) == int or type(diagnostic_information_definition) == str:
			diagnostic_information.value = diagnostic_information_definition
			return diagnostic_information
		else:
			raise M2UA_Error("m2ua diagnostic information parameter must be int or str")

	def Build_Info_String_Parameter(self, info_string_definition):
		info_string = M2UA_Parameter(tag=4)
		info_string.length = None
		if type(info_string_definition) == str:
			info_string.value = info_string_definition
			return info_string
		else:
			raise M2UA_Error("m2ua info string parameter must be str")

	def Build_ASP_Identifier_Parameter(self, asp_identifier_definition):
		asp_identifier = M2UA_Parameter(tag=17)
		if type(asp_identifier_definition) == int:
			asp_identifier.value = asp_identifier_definition
			return asp_identifier
		else:
			raise M2UA_Error("m2ua asp identifier parameter must be int")

	def Build_Heartbeat_Data_Parameter(self, heartbeat_data_definition):
		heartbeat_data = M2UA_Parameter(tag=9)
		heartbeat_data.length = None
		if type(heartbeat_data_definition) == str or type(heartbeat_data_definition) == int:
			heartbeat_data.value = heartbeat_data_definition
			return heartbeat_data
		else:
			raise M2UA_Error("m2ua heartbeat data parameter must be int or str")

	def Tuples_To_List_Distribution(self, tuples_list):
		array = []
		for element in tuples_list:
			for value in element:
				array.append(value)
		return array

	def Interface_Identifiers_Range_Check(self, identifiers_range):
		if len(identifiers_range) != 2:
			raise M2UA_Error("identifier range must be described only by start and stop identifiers in tuple")
		else:
			for identifier in identifiers_range:
				if type(identifier) != int:
					raise M2UA_Error("identifier range must consist only of int identifiers")

	def Interface_Identifiers_List_Check(self, interface_identifiers_list):
		if type(interface_identifiers_list) != list:
			raise M2UA_Error("interface_identifiers argument must be list")
		else:
			first_permitted_type = type(interface_identifiers_list[0])
			if first_permitted_type == int:
				second_permitted_type = tuple
			elif first_permitted_type == tuple:
				second_permitted_type = int
			elif first_permitted_type == str:
				second_permitted_type = str
			else:
				raise M2UA_Error("wrong identifier type in interface_identifiers argument")
			for identifier in interface_identifiers_list:
				if type(identifier) != first_permitted_type and type(identifier) != second_permitted_type:
					raise M2UA_Error("incorrect identifier in interface_identifiers argument")
				if type(identifier) == tuple:
					self.Interface_Identifiers_Range_Check(identifier)

	def Interface_Identifiers_List_Distribution(self, interface_identifiers_list):
		self.Interface_Identifiers_List_Check(interface_identifiers_list)
		if type(interface_identifiers_list[0]) == str:
			return (interface_identifiers_list, None, "str_identifiers")
		else:
			int_identifiers_list = []
			int_range_identifiers_list = []
			for identifier in interface_identifiers_list:
				if type(identifier) == int:
					int_identifiers_list.append(identifier)
				else:
					int_range_identifiers_list.append(identifier)
			int_range_identifiers_list = self.Tuples_To_List_Distribution(int_range_identifiers_list)
			if int_identifiers_list and not int_range_identifiers_list:
				return (int_identifiers_list, None, "int_identifiers")
			elif int_range_identifiers_list and not int_identifiers_list:
				return (int_range_identifiers_list, None, "int_range_identifiers")
			else:
				return (int_identifiers_list, int_range_identifiers_list, "complex_int_identifiers")

	def Build_Int_Interface_Identifier_Parameter(self, interface_identifier_value):
		interface_identifier = M2UA_Parameter(tag=1)
		interface_identifier.value = interface_identifier_value
		return interface_identifier

	def Build_Int_Range_Interface_Identifier_Parameter(self, interface_identifier_value):
		interface_identifier = M2UA_Parameter(tag=8)
		interface_identifier.length = None
		interface_identifier.value = interface_identifier_value
		return interface_identifier

	def Build_Str_Interface_Identifier_Parameter(self, interface_identifier_value):
		interface_identifier = M2UA_Parameter(tag=3)
		interface_identifier.length = None
		interface_identifier.value = interface_identifier_value
		return interface_identifier

	def Identifiers_List_Filtering(self, interface_identifiers_list):
		for parameter in interface_identifiers_list:
			if parameter.tag == 8:
				interface_identifiers_list.remove(parameter)
		if len(interface_identifiers_list) != 0:
			return interface_identifiers_list
		else:
			raise M2UA_Error("interface_identifiers argument elements must be int or str")

	def Build_Interface_Identifier_Parameters(self, interface_identifiers_list, without_int_range=False):
		main_list, secondary_list, info_tag = self.Interface_Identifiers_List_Distribution(interface_identifiers_list)
		interface_identifiers_list = []
		if info_tag == "str_identifiers":
			for identifier in main_list:
				str_identifier = self.Build_Str_Interface_Identifier_Parameter(identifier)
				interface_identifiers_list.append(str_identifier)
		elif info_tag == "int_identifiers":
			for identifier in main_list:
				int_identifier = self.Build_Int_Interface_Identifier_Parameter(identifier)
				interface_identifiers_list.append(int_identifier)
		elif info_tag == "int_range_identifiers":
			int_range_identifier = self.Build_Int_Range_Interface_Identifier_Parameter(main_list)
			interface_identifiers_list.append(int_range_identifier) 
		else:
			for identifier in main_list:
				int_identifier = self.Build_Int_Interface_Identifier_Parameter(identifier)
				interface_identifiers_list.append(int_identifier)
			int_range_identifier = self.Build_Int_Range_Interface_Identifier_Parameter(secondary_list)
			interface_identifiers_list.append(int_range_identifier)
		if without_int_range:
			interface_identifiers_list = self.Identifiers_List_Filtering(interface_identifiers_list)
		return interface_identifiers_list 

	def Build_Traffic_Mode_Type_Parameter(self, traffic_mode_type_definition):
		traffic_mode_type = M2UA_Parameter(tag=11)
		traffic_mode_type.value = self.Get_Parameter_Value(traffic_mode_type, traffic_mode_type_definition)
		return traffic_mode_type

	def Build_Error_Code_Parameter(self, error_code_definition):
		error_code = M2UA_Parameter(tag=12)
		error_code.value = self.Get_Parameter_Value(error_code, error_code_definition)
		return error_code

	def Build_Service_Data(self, service_indicator, kwargs):
		if service_indicator == 3:
			raise M2UA_Error("SCCP service does not supported now")
		elif service_indicator == 5:
			service_data = self.isup_builder.Build_Protocol_Data(kwargs)
			return service_data
		else:
			raise M2UA_Error("Service does not supported now")

	def Build_TTC_Protocol_Data_Parameter(self):
		ttc_protocol_data = M2UA_Parameter(tag=769)
		ttc_protocol_data.length = None
		ttc_protocol_data.value = None
		return ttc_protocol_data

	def Build_Protocol_Data_Parameter(self, service_indicator, **kwargs):
		if self.mtp3 is None:
			raise M2UA_Error("MTP3 properties not defined")
		else:
			overlay_data = self.mtp3
			overlay_data.sio.service_indicator = service_indicator
		protocol_data = M2UA_Parameter(tag=768)
		protocol_data.length = None
		overlay_data.service_data = self.Build_Service_Data(service_indicator, kwargs)
		protocol_data.value = overlay_data
		return protocol_data

	def Build_Establish_Request(self):
		object_message = M2UA_Message(message_class=6, message_type=2)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_Establish_Confirmation(self):
		object_message = M2UA_Message(message_class=6, message_type=3)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_Data_Acknowledge(self, correlation_id):
		object_message = M2UA_Message(message_class=6, message_type=15)
		correlation_id = self.Build_Correlation_Id_Parameter(cid=correlation_id)
		object_message.parameters.append(correlation_id)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_State_Request(self, state):
		object_message = M2UA_Message(message_class=6, message_type=7)
		state = self.Build_State_Parameter(state)
		object_message.parameters.append(state)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_State_Confirm(self, state):
		object_message = M2UA_Message(message_class=6, message_type=8)
		state = self.Build_State_Parameter(state)
		object_message.parameters.append(state)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_State_Indication(self, event):
		object_message = M2UA_Message(message_class=6, message_type=9)
		event = self.Build_Event_Parameter(event)
		object_message.parameters.append(event)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_Congestion_Indication(self, congestion_status, discard_status=None):
		object_message = M2UA_Message(message_class=6, message_type=14)
		congestion_status = self.Build_Congestion_Status_Parameter(congestion_status)
		object_message.parameters.append(congestion_status)
		if discard_status:
			discard_status = self.Build_Discard_Status_Parameter(discard_status)
			object_message.parameters.append(discard_status)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_Data_Retrieval_Request(self, action, sequence_number=None):
		object_message = M2UA_Message(message_class=6, message_type=10)
		action = self.Build_Action_Parameter(action)
		object_message.parameters.append(action)
		if sequence_number:
			sequence_number = self.Build_Sequence_Number_Parameter(sequence_number)
			object_message.parameters.append(sequence_number)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_Data_Retrieval_Confirm(self, action, result, sequence_number=None):
		object_message = M2UA_Message(message_class=6, message_type=11)
		action = self.Build_Action_Parameter(action)
		object_message.parameters.append(action)
		result = self.Build_Result_Parameter(result)
		object_message.parameters.append(result)
		if sequence_number:
			sequence_number = self.Build_Sequence_Number_Parameter(sequence_number)
			object_message.parameters.append(sequence_number)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_Data_Retrieval_Indication(self):
		object_message = M2UA_Message(message_class=6, message_type=12)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_Data_Retrieval_Complete_Indication(self):
		object_message = M2UA_Message(message_class=6, message_type=13)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_Release_Request(self):
		object_message = M2UA_Message(message_class=6, message_type=4)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_Release_Confirmation(self):
		object_message = M2UA_Message(message_class=6, message_type=5)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_Release_Indication(self):
		object_message = M2UA_Message(message_class=6, message_type=6)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_ASP_UP_Message(self, asp_identifier=None, info_string=None):
		object_message = M2UA_Message(message_class=3, message_type=1)
		if asp_identifier:
			asp_identifier = self.Build_ASP_Identifier_Parameter(asp_identifier)
			object_message.parameters.append(asp_identifier)
		if info_string:
			info_string = self.Build_Info_String_Parameter(info_string)
			object_message.parameters.append(info_string)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_ASP_UP_INVALID_VERSION_Message(self, asp_identifier=None, info_string=None):
		object_message = M2UA_Message(message_class=3, message_type=1, version=5)
		if asp_identifier:
			asp_identifier = self.Build_ASP_Identifier_Parameter(asp_identifier)
			object_message.parameters.append(asp_identifier)
		if info_string:
			info_string = self.Build_Info_String_Parameter(info_string)
			object_message.parameters.append(info_string)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_ASP_UP_INVALID_CLASS_Message(self, asp_identifier=None, info_string=None):
		object_message = M2UA_Message(message_class=255, message_type=1)
		if asp_identifier:
			asp_identifier = self.Build_ASP_Identifier_Parameter(asp_identifier)
			object_message.parameters.append(asp_identifier)
		if info_string:
			info_string = self.Build_Info_String_Parameter(info_string)
			object_message.parameters.append(info_string)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_ASP_UP_INVALID_TYPE_Message(self, asp_identifier=None, info_string=None):
		object_message = M2UA_Message(message_class=3, message_type=255)
		if asp_identifier:
			asp_identifier = self.Build_ASP_Identifier_Parameter(asp_identifier)
			object_message.parameters.append(asp_identifier)
		if info_string:
			info_string = self.Build_Info_String_Parameter(info_string)
			object_message.parameters.append(info_string)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_ASP_UP_ACK_Message(self, info_string=None):
		object_message = M2UA_Message(message_class=3, message_type=4)
		if info_string:
			info_string = self.Build_Info_String_Parameter(info_string)
			object_message.parameters.append(info_string)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_ASP_DOWN_Message(self, info_string=None):
		object_message = M2UA_Message(message_class=3, message_type=2)
		if info_string:
			info_string = self.Build_Info_String_Parameter(info_string)
			object_message.parameters.append(info_string)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_ASP_DOWN_ACK_Message(self, info_string=None):
		object_message = M2UA_Message(message_class=3, message_type=5)
		if info_string:
			info_string = self.Build_Info_String_Parameter(info_string)
			object_message.parameters.append(info_string)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_BEAT_Message(self, heartbeat_data=None):
		object_message = M2UA_Message(message_class=3, message_type=3)
		if heartbeat_data:
			heartbeat_data = self.Build_Heartbeat_Data_Parameter(heartbeat_data)
			object_message.parameters.append(heartbeat_data)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_BEAT_ACK_Message(self, heartbeat_data=None):
		object_message = M2UA_Message(message_class=3, message_type=6)
		if heartbeat_data:
			heartbeat_data = self.Build_Heartbeat_Data_Parameter(heartbeat_data)
			object_message.parameters.append(heartbeat_data)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_ASPAC_Message(self, traffic_mode_type=None, interface_identifiers=[], info_string=None):
		object_message = M2UA_Message(message_class=4, message_type=1)
		if interface_identifiers:
			interface_identifiers_list = self.Build_Interface_Identifier_Parameters(interface_identifiers)
			object_message.parameters = interface_identifiers_list
		if traffic_mode_type:
			traffic_mode_type = self.Build_Traffic_Mode_Type_Parameter(traffic_mode_type)
			object_message.parameters.append(traffic_mode_type)
		if info_string:
			info_string = self.Build_Info_String_Parameter(info_string)
			object_message.parameters.append(info_string)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_ASP_ACTIVE_Message(self, traffic_mode_type=None, interface_identifiers=[], info_string=None):
		object_message = M2UA_Message(message_class=4, message_type=1)
		if interface_identifiers:
			interface_identifiers_list = self.Build_Interface_Identifier_Parameters(interface_identifiers)
			object_message.parameters = interface_identifiers_list
		if traffic_mode_type:
			traffic_mode_type = self.Build_Traffic_Mode_Type_Parameter(traffic_mode_type)
			object_message.parameters.append(traffic_mode_type)
		if info_string:
			info_string = self.Build_Info_String_Parameter(info_string)
			object_message.parameters.append(info_string)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_ASPAC_ACK_Message(self, traffic_mode_type=None, interface_identifiers=[], info_string=None):
		object_message = M2UA_Message(message_class=4, message_type=3)
		if interface_identifiers:
			interface_identifiers_list = self.Build_Interface_Identifier_Parameters(interface_identifiers)
			object_message.parameters = interface_identifiers_list
		if traffic_mode_type:
			traffic_mode_type = self.Build_Traffic_Mode_Type_Parameter(traffic_mode_type)
			object_message.parameters.append(traffic_mode_type)
		if info_string:
			info_string = self.Build_Info_String_Parameter(info_string)
			object_message.parameters.append(info_string)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_ASP_ACTIVE_ACK_Message(self, traffic_mode_type=None, interface_identifiers=[], info_string=None):
		object_message = M2UA_Message(message_class=4, message_type=3)
		if interface_identifiers:
			interface_identifiers_list = self.Build_Interface_Identifier_Parameters(interface_identifiers)
			object_message.parameters = interface_identifiers_list
		if traffic_mode_type:
			traffic_mode_type = self.Build_Traffic_Mode_Type_Parameter(traffic_mode_type)
			object_message.parameters.append(traffic_mode_type)
		if info_string:
			info_string = self.Build_Info_String_Parameter(info_string)
			object_message.parameters.append(info_string)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_ASPIA_Message(self, interface_identifiers=[], info_string=None):
		object_message = M2UA_Message(message_class=4, message_type=2)
		if interface_identifiers:
			interface_identifiers_list = self.Build_Interface_Identifier_Parameters(interface_identifiers)
			object_message.parameters = interface_identifiers_list
		if info_string:
			info_string = self.Build_Info_String_Parameter(info_string)
			object_message.parameters.append(info_string)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_ASP_INACTIVE_Message(self, interface_identifiers=[], info_string=None):
		object_message = M2UA_Message(message_class=4, message_type=2)
		if interface_identifiers:
			interface_identifiers_list = self.Build_Interface_Identifier_Parameters(interface_identifiers)
			object_message.parameters = interface_identifiers_list
		if info_string:
			info_string = self.Build_Info_String_Parameter(info_string)
			object_message.parameters.append(info_string)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_ASPIA_ACK_Message(self, interface_identifiers=[], info_string=None):
		object_message = M2UA_Message(message_class=4, message_type=4)
		if interface_identifiers:
			interface_identifiers_list = self.Build_Interface_Identifier_Parameters(interface_identifiers)
			object_message.parameters = interface_identifiers_list
		if info_string:
			info_string = self.Build_Info_String_Parameter(info_string)
			object_message.parameters.append(info_string)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_ASP_INACTIVE_ACK_Message(self, interface_identifiers=[], info_string=None):
		object_message = M2UA_Message(message_class=4, message_type=4)
		if interface_identifiers:
			interface_identifiers_list = self.Build_Interface_Identifier_Parameters(interface_identifiers)
			object_message.parameters = interface_identifiers_list
		if info_string:
			info_string = self.Build_Info_String_Parameter(info_string)
			object_message.parameters.append(info_string)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_ERR_Message(self, error_code, interface_identifiers=[], diagnostic_information=None):
		object_message = M2UA_Message(message_class=0, message_type=0)
		if interface_identifiers:
			interface_identifiers_list = self.Build_Interface_Identifier_Parameters(interface_identifiers)
			object_message.parameters = interface_identifiers_list
		error_code = self.Build_Error_Code_Parameter(error_code)
		object_message.parameters.append(error_code)
		if diagnostic_information:
			diagnostic_information = self.Build_Diagnostic_Information_Parameter(diagnostic_information)
			object_message.parameters.append(diagnostic_information)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_NTFY_Message(self, status_type, status_information, asp_identifier=None, interface_identifiers=[], info_string=None):
		object_message = M2UA_Message(message_class=0, message_type=1)
		if interface_identifiers:
			interface_identifiers_list = self.Build_Interface_Identifier_Parameters(interface_identifiers)
			object_message.parameters = interface_identifiers_list
		status = self.Build_Status_Parameter(status_type, status_information)
		object_message.parameters.append(status)
		if asp_identifier:
			asp_identifier = self.Build_ASP_Identifier_Parameter(asp_identifier)
			object_message.parameters.append(asp_identifier)
		if info_string:
			info_string = self.Build_Info_String_Parameter(info_string)
			object_message.parameters.append(info_string)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_REG_REQ_Message(self, link_keys):
		object_message = M2UA_Message(message_class=10, message_type=1)
		link_keys_list = self.Build_Link_Key_Parameters(link_keys)
		object_message.parameters = link_keys_list
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_REG_RSP_Message(self, registration_results):
		object_message = M2UA_Message(message_class=10, message_type=2)
		registration_results_list = self.Build_Registration_Result_Parameters(registration_results)
		object_message.parameters = registration_results_list
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_DEREG_REQ_Message(self, interface_identifiers):
		object_message = M2UA_Message(message_class=10, message_type=3)
		interface_identifiers_list = self.Build_Interface_Identifier_Parameters(interface_identifiers, without_int_range=True)
		object_message.parameters = interface_identifiers_list
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_DEREG_RSP_Message(self, deregistration_results):
		object_message = M2UA_Message(message_class=10, message_type=4)
		deregistration_results_list = self.Build_Deregistration_Result_Parameters(deregistration_results)
		object_message.parameters = deregistration_results_list
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_IAM_Message(self, cic, nature_of_connection_indicators, forward_call_indicators, calling_party_category, 
		                  transmission_medium_requirement, called_party_number):
		object_message = M2UA_Message(message_class=6, message_type=1)
		self.Define_MTP3_Properties(opc=19, dpc=20, link_selector=0)
		protocol_data = self.Build_Protocol_Data_Parameter(service_indicator=5, cic=cic, mes_type=1, nature_of_connection_indicators=nature_of_connection_indicators,
			                                               forward_call_indicators=forward_call_indicators, calling_party_category=calling_party_category, 
			                                               transmission_medium_requirement=transmission_medium_requirement, called_party_number=called_party_number)
		object_message.parameters.append(protocol_data)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_ACM_Message(self, cic, backward_call_indicators):
		object_message = M2UA_Message(message_class=6, message_type=1)
		protocol_data = self.Build_Protocol_Data_Parameter(service_indicator=5, cic=cic, mes_type=6, backward_call_indicators=backward_call_indicators)
		object_message.parameters.append(protocol_data)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_ANM_Message(self, cic):
		object_message = M2UA_Message(message_class=6, message_type=1)
		protocol_data = self.Build_Protocol_Data_Parameter(service_indicator=5, cic=cic, mes_type=9)
		object_message.parameters.append(protocol_data)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_REL_Message(self, cic, cause_indicators):
		object_message = M2UA_Message(message_class=6, message_type=1)
		protocol_data = self.Build_Protocol_Data_Parameter(service_indicator=5, cic=cic, mes_type=12, cause_indicators=cause_indicators)
		object_message.parameters.append(protocol_data)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_RLC_Message(self, cic):
		object_message = M2UA_Message(message_class=6, message_type=1)
		protocol_data = self.Build_Protocol_Data_Parameter(service_indicator=5, cic=cic, mes_type=16)
		object_message.parameters.append(protocol_data)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_CFN_Message(self, cic, cause_indicators):
		object_message = M2UA_Message(message_class=6, message_type=1)
		protocol_data = self.Build_Protocol_Data_Parameter(service_indicator=5, cic=cic, mes_type=47, cause_indicators=cause_indicators)
		object_message.parameters.append(protocol_data)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

	def Build_SAM_Message(self, cic, subsequent_number):
		object_message = M2UA_Message(message_class=6, message_type=1)
		protocol_data = self.Build_Protocol_Data_Parameter(service_indicator=5, cic=cic, mes_type=2, subsequent_number=subsequent_number)
		object_message.parameters.append(protocol_data)
		binary_message = self.convertor.Convert_M2UA_Message(object_message)
		return binary_message

class Message_Parser:

	def __init__(self):
		self.sccp_parser = SCCP_Message_Parser()
		self.isup_parser = ISUP_Message_Parser()
		self.common_m2ua_header_pattern = struct.Struct(">B B B B L")
		self.m2ua_parameter_header_pattern = struct.Struct(">H H")
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
		sio_data = mtp3_object.Service_Information_Octet(network_indicator=network_indicator, spare=spare, service_indicator=service_indicator)
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
		dpc = self.DPC_Value_Forming(binary_routing_label_data)
		opc = self.OPC_Value_Forming(binary_routing_label_data)
		link_selector = self.Link_Selector_Value_Forming(binary_routing_label_data)
		routing_label = mtp3_object.Routing_Label(dpc=dpc, opc=opc, link_selector=link_selector)
		return routing_label

	def M2UA_Protocol_Data_Handling(self, binary_protocol_data):
		#MTP3 object building
		mtp3_data = MTP3_Data()
		print(mtp3_data)
		print(mtp3_data)
		#Building SIO data
		mtp3_data.sio = self.MTP3_Service_Information_Octet_Forming(mtp3_object=mtp3_data, binary_sio_data=binary_protocol_data[:1])
		#Building routing label
		mtp3_data.routing_label = self.MTP3_Routing_Label_Forming(mtp3_object=mtp3_data, binary_routing_label_data=binary_protocol_data[1:5])
		#Service data
		mtp3_data.service_data = self.Service_Data_Forming(service_indicator=mtp3_data.sio.service_indicator, binary_data=binary_protocol_data[5:])
		return mtp3_data

	def M2UA_Composite_Parameters_Handling(self, binary_parameter_value):
		parameter_value = self.M2UA_Parameters_Forming(binary_parameter_value)
		return parameter_value

	def Polymorphic_M2UA_Parameter_Value_Handling(self, binary_parameter_value):
		parameter_value = binascii.hexlify(binary_parameter_value)
		return parameter_value

	def Int_Range_M2UA_Parameter_Value_Handling(self, binary_parameter_value):
		int_range_parameter_values = []
		end_of_ranges = False
		while not end_of_ranges:
			start_identifier = int.from_bytes(binary_parameter_value[:4], byteorder="big")
			stop_identifier = int.from_bytes(binary_parameter_value[4:8], byteorder="big")
			int_range_parameter_values.append((start_identifier, stop_identifier))
			binary_parameter_value = binary_parameter_value[8:]
			if not binary_parameter_value:
				end_of_ranges = True
		return int_range_parameter_values

	def Str_M2UA_Parameter_Value_Handling(self, binary_parameter_value):
		parameter_value = binary_parameter_value.decode("utf-8")
		return parameter_value

	def Int_M2UA_Parameter_Value_Handling(self, binary_parameter_value):
		parameter_value = int.from_bytes(binary_parameter_value, byteorder="big")
		return parameter_value

	def M2UA_Parameter_Value_Forming(self, parameter_tag, binary_parameter_value):
		#Empty parameter has None value
		if not binary_parameter_value:
			return None
		parameter_handlers = self.Define_M2UA_Parameter_Handlers()
		parameter_value = None
		for parameter_tags, handler in parameter_handlers.items():
			for tag in parameter_tags:
				if parameter_tag == tag:
					parameter_value = handler(binary_parameter_value)
		if parameter_value == None:
			raise M2UA_Error("unsupported parameter tag: %s" % parameter_tag)
		else:
			return parameter_value

	def M2UA_Parameters_Forming(self, m2ua_data):
		#Empty list for parameter collecting
		m2ua_parameters = []
		#Сycle stop сondition
		end_of_parameters = False
		while not end_of_parameters:
			#Extracting tag and length atributes from parameter
			parameter_tag = m2ua_data[:2]
			parameter_length = m2ua_data[2:4]
			parameter_header = parameter_tag + parameter_length
			unpacked_data = self.m2ua_parameter_header_pattern.unpack(parameter_header)
			#Building parameter by tag
			m2ua_parameter = M2UA_Parameter(unpacked_data[0])
			#Checking tag for existence 
			self.M2UA_Parameter_Tag_Check(m2ua_parameter)
			#Parameter length determining
			m2ua_parameter.length = unpacked_data[1]
			#Removing padding bytes if parameter length is not multiple of 4
			if m2ua_parameter.length % 4 != 0:
				m2ua_data = self.M2UA_Parameter_Padding_Removing(m2ua_data, m2ua_parameter.length)
			#Parameter value extracting 
			binary_parameter_value = m2ua_data[4:m2ua_parameter.length]
			#Parameter value assignment
			m2ua_parameter.value = self.M2UA_Parameter_Value_Forming(m2ua_parameter.tag, binary_parameter_value)
			#Append formed parameter to list
			m2ua_parameters.append(m2ua_parameter)
			#Byte string shifting along parameter length
			m2ua_data = self.M2UA_Parameters_Shifting(m2ua_data, m2ua_parameter.length)
			#Stop condition checking
			if not m2ua_data:
				end_of_parameters = True
		return m2ua_parameters 

	def Parse_Message(self, binary_message):
		#Retrieving the M2UA header bytes from the binary message
		binary_m2ua_header = binary_message[:8]
		#Building M2UA header object
		m2ua_data = self.M2UA_Header_Forming(binary_m2ua_header)
		#Building M2UA parameters if they exist
		if m2ua_data.length > 8:
			m2ua_parameters = self.M2UA_Parameters_Forming(binary_message[8:])
			m2ua_data.parameters = m2ua_parameters
		return m2ua_data

class M2UA_Error(Exception):

	def __init__(self, description):
		self.description = description

class Argument:

        def __init__(self):
                self.remote_address = None
                self.remote_port = 2904
                self.remote_address2 = None
                self.remote_port2 = 2906
                self.login = None
                self.password = None
                self.local_address = None
                self.local_port = 2904
                self.local_address2 = None
                self.local_port2 = 2906
                self.asp = None
                self.iid = None

class Config_Parser:

        def __init__(self):
                self.asp = None
                self.iid = None

        def File_Existence_Check(self, file_path):
                if type(file_path) != str:
                        raise argparse.ArgumentTypeError("argument must be string")
                else:
                        if not os.path.exists(file_path):
                                raise argparse.ArgumentTypeError("file \"%s\" does not exist" % file_path)
                        else:
                                return file_path

        def Define_Args(self):
                args = argparse.ArgumentParser(description="List of possible command line arguments")
                args.add_argument("-c", "--config", action="store", type=self.File_Existence_Check, required=True, dest="config", help="set script config")
                return args

        def Load_Config_File(self, config_path):
                file = open(config_path, "r", encoding="utf-8")
                try:
                        config = json.loads(file.read())
                except json.decoder.JSONDecodeError:
                        file.close()
                        print("Validation error: wrong JSON format: %s" % sys.exc_info()[1])
                        sys.exit(107)
                else:
                        file.close()
                return config

        def Define_Config_Schema(self):
                schema = {
                    '$schema': 'http://json-schema.org/draft-04/schema#', 
                    'title': 'Config schema',
                    'type': 'object',
                    'properties':
                        {
                         'EXTER_IP': {'type': 'string', 'minLength': 7, 'maxLength': 15},
                         'EXTER_PORT': {'type': 'integer', 'minimum': 1024, 'maximum': 65536, 'exclusiveMinimum': False, 'exclusiveMaximum': False},
                         'EXTER_IP2': {'type': 'string', 'minLength': 7, 'maxLength': 15},
                         'EXTER_PORT2': {'type': 'integer', 'minimum': 1024, 'maximum': 65536, 'exclusiveMinimum': False, 'exclusiveMaximum': False},
                         'DEV_USER': {'type': 'string', 'minLength': 1},
                         'DEV_PASS': {'type': 'string', 'minLength': 1},
                         'IP': {'type': 'string', 'minLength': 7, 'maxLength': 15},
                         'PORT': {'type': 'integer', 'minimum': 1024, 'maximum': 65536, 'exclusiveMinimum': False, 'exclusiveMaximum': False},
                         'IP2': {'type': 'string', 'minLength': 7, 'maxLength': 15},
                         'PORT2': {'type': 'integer', 'minimum': 1024, 'maximum': 65536, 'exclusiveMinimum': False, 'exclusiveMaximum': False},
                         'ASP_LIST': {'type': 'array', 'items': {'type': 'integer', 'minLength': 1}},
                         'IID_LIST': {'type': 'array', 'items': {'type': 'integer', 'minLength': 1}}
                        },
                        "required" : ["EXTER_IP", "IP"]
                }
                return schema

        def Errors_Output(self, errors):
                for e in errors:
                        if len(e.path) == 0:
                                print("Validation error: %s" % e.message)
                                sys.exit(107)
                        else:
                                print("Validation error: %s (property \"%s\")" % (e.message, e.path.pop()))
                                sys.exit(107)

        def Validate_Config(self, config):
                schema = self.Define_Config_Schema()
                errors = sorted(Draft4Validator(schema).iter_errors(config), key=lambda e: e.path)
                if errors:
                        self.Errors_Output(errors)

        def Arguments_Forming(self, config):
                arguments = Argument()
                arguments.remote_address = config["EXTER_IP"]
                try:
                        arguments.remote_port = config["EXTER_PORT"]
                except KeyError:
                        pass
                arguments.remote_address2 = config["EXTER_IP2"]
                try:
                        arguments.remote_port2 = config["EXTER_PORT2"]
                except KeyError:
                        pass
                arguments.login = config["DEV_USER"]
                arguments.password = config["DEV_PASS"]
                arguments.local_address = config["IP"]
                try:
                        arguments.local_port = config["PORT"]
                except KeyError:
                        pass
                arguments.local_address2 = config["IP2"]
                try:
                        arguments.local_port2 = config["PORT2"]
                except KeyError:
                        pass
                try:
                        arguments.asp = config["ASP_LIST"]
                except KeyError:
                        pass
                try:
                        arguments.iid = config["IID_LIST"]
                except KeyError:
                        pass
                return arguments

        def Parse_Config(self):
                args = self.Define_Args()
                arguments = args.parse_args()
                config = self.Load_Config_File(arguments.config)
                self.Validate_Config(config)
                arguments = self.Arguments_Forming(config)
                return arguments

class Parameters_Validator:

	def Message_Class_Check(self, message, message_class):
		# Message Class check
		description = Message_Parser().Get_M2UA_Class_Description(message)
		try:
			mc = int(message_class)
			if 0 <= mc <= 10:
				if mc == message.mes_class:
					return True, "Message class match"
				else:
					return False, "Message class don't match. Need: {0}, Received: {1}".format(message_class, message.mes_class)
			else:
				return False, "Invalid message class value in configuration"
		except ValueError:
			message_class = "(" + message_class + ")"
			if message_class.lower() in description.lower():
				return True, "Message class match"
			else:
				return False, "Message class don't match. Need: {0}, Received: {1}".format(message_class, description)

	def Message_Type_Check(self, message, message_type):
		#Проверка типа сообщения 
		description = Message_Parser().Get_M2UA_Type_Description(message)
		message_type = "(" + message_type + ")"
		if message_type.lower() in description.lower():
			return True, "Message type match"
		else:
			return False, "Message type don't match. Need: {0}, Received: {1}".format(message_type, message.mes_type)

	#def Param_Value_Check(param, param_tag, param_value):
	def Param_Value_Check(self, message, params):
		#Parameter value check
		resultvalue = []
		if len(message.parameters) > 0:
			for key in params:
				print ("conf par", key)
				for tag in message.parameters:
					print("recv_par", tag.tag, tag.value)
					if key[0] == tag.tag:
						if key[1] == tag.value:
							resultvalue.append(True)
							continue
						else:
							pass
					else:
						pass
				resultvalue.append(False)
			for value in resultvalue:
				if value == False:
					return False, "Tag/s or TagValue/s don't match"
				else:
					return True, "Tags & values are match"
		else:
			return False, "No parameters in message"

	def Validate_Message(self, message, message_class, message_type):
			result = self.Message_Class_Check(message, message_class)
			if not result[0]:
				print (result[1])
				return False, result[1]
			result = self.Message_Type_Check(message, message_type)
			if not result[0]:
				print (result[1])
				return False, result[1]
			print ("OK!")
			return True, "OK"			

	def Validate_Message_W_Params(self, message, message_class, message_type, params):				
			result = self.Message_Class_Check(message, message_class)
			if not result[0]:
				print (result[1])
				return False, result[1]
			result = self.Message_Type_Check(message, message_type)
			if not result[0]:
				print (result[1])
				return False, result[1]
			result = self.Param_Value_Check(message, params)
			if not result[0]:
				print (result[1])
				return False, result[1]
			print ("OK!")
			return True, "OK"	

class Config_Executor:

	def Config_Define_M2UA_Parameter_Handlers(self):
		handlers = {
		  (1,) : self.Config_IID_Int_M2UA_Parameter_Value_Handling,
		  (11,12,17,19,770,771,772,773,774,775,776,778,779,780,782,784) : self.Config_Int_M2UA_Parameter_Value_Handling,
		  (13,) : self.Config_Int_Twopar_M2UA_Parameter_Value_Handling,
		  (3,4) : self.Config_Str_M2UA_Parameter_Value_Handling,
		  (8,) : self.Config_Int_Range_M2UA_Parameter_Value_Handling,
		  (7,9) : self.Config_Polymorphic_M2UA_Parameter_Value_Handling,
		  (768,) : self.Config_M2UA_Protocol_Data_Handling,
		  (769,) : self.Config_M2UA_TTC_Protocol_Data_Handling,
		  (777,781,783) : self.Config_M2UA_Composite_Parameters_Handling
		}
		return handlers

# Not realized
	def Config_M2UA_Protocol_Data_Handling(self, binary_protocol_data):
		#MTP3 object building
		mtp3_data = MTP3_Data()
		#Building SIO data
		mtp3_data.sio = self.MTP3_Service_Information_Octet_Forming(mtp3_object=mtp3_data, binary_sio_data=binary_protocol_data[:1])
		#Building routing label
		mtp3_data.routing_label = self.MTP3_Routing_Label_Forming(mtp3_object=mtp3_data, binary_routing_label_data=binary_protocol_data[1:5])
		#Service data
		mtp3_data.service_data = self.Service_Data_Forming(service_indicator=mtp3_data.sio.service_indicator, binary_data=binary_protocol_data[5:])
		return mtp3_data

#Not realized
	def Config_M2UA_Composite_Parameters_Handling(self, binary_parameter_value):
		parameter_value = self.M2UA_Parameters_Forming(binary_parameter_value)
		return parameter_value

#Not realized
	def Config_Polymorphic_M2UA_Parameter_Value_Handling(self, binary_parameter_value):
		parameter_value = binascii.hexlify(binary_parameter_value)
		return parameter_value

#Not realized
	def Config_M2UA_TTC_Protocol_Data_Handling(self, binary_protocol_data):
		raise M2UA_Error("mtp3 ttc data parsing not supported now")

	def Config_Int_Range_M2UA_Parameter_Value_Handling(self, parameter_value):
		int_range_parameter_values = "" 
		values = parameter_value.split("/")
		if len(values) == 1:
			raise M2UA_Error("invalid parameter value: %s" % parameter_value)
		elif (len(values) % 2):
			raise M2UA_Error("invalid parameter value: %s" % parameter_value)
		elif len(values) > 6:
			raise M2UA_Error("maximum range count = 6")
		else:
			i = 0
			while i < len(values): 
				int_range_parameter_values+="(" + str(values[i]) + ", " + str(values[i+1]) + "), "
				i += 2
			int_range_parameter_values= int_range_parameter_values[:-2] 
		return int_range_parameter_values

	def Config_Str_M2UA_Parameter_Value_Handling(self, parameter_value):
		#par_value = parameter_value.lstrip("'").lstrip('"').rstrip("'").rstrip('"')
		par_value = parameter_value.replace('"', "'")
		return par_value

	def Config_Int_M2UA_Parameter_Value_Handling(self, parameter_value):
		par_value = int(parameter_value)
		return par_value

	def Config_Int_Twopar_M2UA_Parameter_Value_Handling(self, parameter_value):
		temp = parameter_value.partition("/")
		par_value = (int(temp[0]) << 16) + int(temp[2])
		return par_value

	def Config_IID_Int_M2UA_Parameter_Value_Handling(self, parameter_value):
		temp = parameter_value.split("/")
		if len(temp) == 1:
			par_value = temp[0]
		else:
			par_value = "["
			for value in temp:
				par_value+=str(value) + ", "
			par_value=par_value[:-2] + "]"
		return par_value

	def Config_M2UA_Parameter_Value_Forming(self, parameter_tag, parameter_value):
		#Empty parameter has None value
		if not parameter_value:
			return None
		parameter_handlers = self.Config_Define_M2UA_Parameter_Handlers()
		par_value = None
		for parameter_tags, handler in parameter_handlers.items():
			for tag in parameter_tags:
				if parameter_tag == tag:
					par_value = handler(parameter_value)
		if par_value == None:
			raise M2UA_Error("unsupported parameter tag: %s" % parameter_tag)
		else:
			return par_value

	def Get_M2UA_Tag_Description(self, message_tag):
		tags = M2UA_Parameter(message_tag).Define_Parameter_Tags()
		for tag,description in tags.items():    
			if int(message_tag) == tag:
				tag_description = description
				break
		else:
			raise M2UA_Error("m2ua tag \"%s\" does not supported" % message_tag)
		return tag_description

	def Get_M2UA_Tag_Number(self, message_tag):
		tags = M2UA_Parameter(message_tag).Define_Parameter_Tags()
		for tag,description in tags.items():    
			if message_tag.lower() == description.lower():
				tag_number = tag
				break
		else:
			raise M2UA_Error("m2ua tag \"%s\" does not supported" % message_tag)
		return tag_number

	def Multi_Tag_Forming(self, input_description, params, Tags):
		description = input_description.replace(" ", "_")
		compl = 0
		iid = "interface_identifiers=["
		if description == "interface_identifier_(integer)":
			for _ in Tags:
				if _ == 1 or _ == 3:
					raise M2UA_Error("invalid iid parameters combination in message")
				elif _ == 8:
					compl = 1
			params_list = params.split("/")
			i=1
			if compl:
				iid = ""
				for value in params_list:
					if i == len(params_list):
						iid+=", " + value + "]"  
					else:
						iid+=", " + value   
					i+=1
				return iid, None, compl
			else:
				for value in params_list:
					if i == len(params_list):
						iid+=value   
						iid+="]"
					else:
						iid+=value   
						iid+=", "
					i+=1
				return iid, None, None
		elif description == "interface_identifier_(text)":
			for _ in Tags:
				if _ == 1 or _ == 3 or _ == 8:
					raise M2UA_Error("invalid iid parameters combination in message")
			iid+=value #.lstrip("[").rstrip("]")
			iid+="]"
			return iid, None, None
		elif description == "interface_identifier_(integer_range)":
			for _ in Tags:
				if _ == 8 or _ == 3:
					raise M2UA_Error("invalid iid parameters combination in message")
				elif _ == 1:
					compl = 1
			params_list = params.split("/")
			if (len(params_list) % 2):
				raise M2UA_Error("invalid parameter value: %s" % params)
			else:
				i = 0
				if compl:
					iid = ""
					while i < len(params_list):
						if i+2 == len(params_list):
							iid+=", (" + params_list[i] + ", " + params_list[i+1] + ")]"
						else:
							iid+=", (" + params_list[i] + ", " + params_list[i+1] + ")"
						i+=2
					return iid, None, compl
				else:
					while i < len(params_list):
						if i+2 == len(params_list):
							iid+="(" + params_list[i] + ", " + params_list[i+1] + ")]"
						else:
							iid+="(" + params_list[i] + ", " + params_list[i+1] + ")" + ", "
						i+=2
					return iid, None, None
		elif description == "status_type/information":
			params_list = params.split("/")
			return "status_type={0}, information={1}".format(params_list[0], params_list[1]), None, None
		elif description == "link_key":
			params_list = params.split("/")
			link_key = "link_keys=["
			i=1
			for value in params_list:
					if i == len(params_list):
						link_key+=value + "]" 
					else:
						link_key+=value + ", "
					i+=1
			return link_key, None, None
		elif description == "registration_result":
			params_list = params.split("/")
			reg_stat = "registration_results=["
			i=1
			for value in params_list:
					if i == len(params_list):
						reg_stat+=value + "]" 
					else:
						reg_stat+=value + ", "
					i+=1
			return reg_stat, None, None
		elif description == "de-registration_result":
			params_list = params.split("/")
			reg_stat = "deregistration_results=["
			i=1
			for value in params_list:
					if i == len(params_list):
						reg_stat+=value + "]" 
					else:
						reg_stat+=value + ", "
					i+=1
			return reg_stat, None, None
		else:
			return description, params, None

	def Values_Exec(self, message_row, flag):
		# Ecexute message type and paarmeters from CDATA
		message_row_type = None
		#params = []
		params = "["
		if message_row:
			row_comp = message_row.partition("(")
			row_comp2 = row_comp[2].rstrip(")").split(";")
			if flag == "recv":
				message_row_type = row_comp[0].upper()
				if message_row_type == "NO MESSAGE":
					return True, message_row_type, False
			else:
				message_row_type = row_comp[0].upper().replace(" ", "_")
			if row_comp[2] and row_comp[2] != ")":
				if flag == "recv":
					i=1
					for val in row_comp2:
						temp = val.strip().partition("=")
						tempt = temp[2].partition(":")
						try:
							tag = int(tempt[0])
						except ValueError:
							tag = self.Get_M2UA_Tag_Number(tempt[0].lstrip("'").lstrip('"').rstrip("'").rstrip('"'))
						param_mdfy = tempt[2].replace('"',"'").replace("[","").replace("]","")
						value = self.Config_M2UA_Parameter_Value_Forming(tag, param_mdfy)
						if str(value).startswith("[") and str(value).endswith("]"):
							temp_str = str(value).replace("[","").replace("]","")
							params+="(" + str(tag) + ", "
							for _ in temp_str:
								if _ == ",":
									params+="), (" + str(tag) + ", "
								elif _ == " ":
									pass
								else:
									params+=_
							if i == len(row_comp2):
								params+=")]"
							else:
								params+="), "
						else:
							if str(value).startswith("("):
								value = "[" + value + "]" 
							if i == len(row_comp2):
								params+= "(" + str(tag) + ", " + str(value) + ")]"
							else:
								params+= "(" + str(tag) + ", " + str(value) + "), "
						i+=1
					return True, message_row_type, True, params
				else:
					param_string = ""
					first = True
					Tags = [] # for checking to iids
					for val in row_comp2:
						tagpar = False
						temp = val.strip().partition("=")
						tempt = temp[2].partition(":")
						par_val = tempt[2].replace('"',"'").replace("[","").replace("]","")
						if temp[0] == "tag":
							try:
								def_tag = int(tempt[0])
								descr = self.Get_M2UA_Tag_Description(tempt[0]).replace(" ", "_").lower()
							except ValueError:
								descr = tempt[0].lstrip("'").lstrip('"').rstrip("'").rstrip('"').lower()
								def_tag = self.Get_M2UA_Tag_Number(descr.lstrip("'").lstrip('"').rstrip("'").rstrip('"'))
							description, real_params, iidcompl =self.Multi_Tag_Forming(descr, par_val, Tags)
							Tags.append(def_tag)
						elif temp[0] == "par":
							description = tempt[0].lstrip("'").lstrip('"').rstrip("'").rstrip('"').replace(" ", "_").lower()
							tagpar = True
						if first:
							if tagpar:
								param_string += description + "=" + tempt[2]
							elif real_params:
								param_string += description + "=" + tempt[2].lstrip("[").rstrip("]") 
							else:
								param_string += description  
							first = False
						else:
							if tagpar:
								param_string += ", " + description + "=" + tempt[2]
							elif iidcompl: # if we have iid with tags 1 and 8
								pos = param_string.find("interface_identifiers")
								pos_sq = param_string.find("]", pos)
								param_string = param_string[:pos_sq-1] + description + param_string[pos_sq+1:]
							elif real_params:
								param_string += ", " + description + "=" + tempt[2].lstrip("[").rstrip("]") 
							else:
								param_string += ", " + description  								 						
					return True, message_row_type, True, param_string
			else:
				return True, message_row_type, False
		else:
			sys.exit(1)
		



a = Message_Parser()
b = a.M2UA_Protocol_Data_Handling(bytes.fromhex('0111d8040211201112'))
