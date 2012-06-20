#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of Androwarn.
#
# Copyright (C) 2012, Thomas Debize <tdebize at mail.com>
# All rights reserved.
#
# Androwarn is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Androwarn is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Androwarn.  If not, see <http://www.gnu.org/licenses/>.

# Global imports
import os, re, logging

# Androguard imports
from androguard.core.analysis import analysis
from androguard.core.bytecodes.apk import *

# Androwarn modules import
from androwarn.core.core import *
from androwarn.util.util import *

# Logguer
log = logging.getLogger('log')

# -- SMS Abuse -- #
def detect_Telephony_SMS_abuse(x) :
	"""
		@param x : a VMAnalysis instance
		
		@rtype : a list of formatted strings
	"""
	formatted_str = []
	
	b = x.tainted_packages.search_methods("Landroid/telephony/SmsManager","sendTextMessage", ".")
	
	for result in xrange(len(b)) :
		method = b[result].get_method()
		#method_call_index_to_find = b[result].get_offset()
		method_call_index_to_find = b[result].get_idx()

		registers = backtrace_registers_before_call(x, method, method_call_index_to_find)
		log.info("Class '%s' - Method '%s' - register state before call %s" % (b[result].get_class_name(),b[result].get_name(), registers))
		#print "[+] Registers state before call " + str(registers)
				
		if len(registers) > 0 :
			target_phone_number = get_register_value(1, registers)
			sms_message 		= get_register_value(3, registers)
			
			local_formatted_str = "This application sends an SMS message '%s' to the '%s' phone number" % (sms_message, target_phone_number)
			if not(local_formatted_str in formatted_str) :
				formatted_str.append(local_formatted_str)
	return formatted_str

def detect_Telephony_Phone_Call_abuse(x) :
	"""
		@param x : a VMAnalysis instance
		
		@rtype : a list of formatted strings
	"""
	formatted_str = []
	
	detector_1 = search_string(x, "android.intent.action.CALL")
	detector_2 = search_string(x, "android.intent.action.DIAL")
		
	detectors = [detector_1, detector_2]
	
	if detectors :
		local_formatted_str = 'This application makes phone calls'
		formatted_str.append(local_formatted_str)
		
		for res in detectors :
			if res :
				try :
					log_result_path_information(res, "Call Intent", "string")
				except :
					log.warn("Detector result '%s' is not a Path instance" % res) 
		
	return formatted_str
