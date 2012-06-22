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

def detect_Telephony_Operator_lookup(x) :
	"""
		@param x : a VMAnalysis instance
		
		@rtype : a list of formatted strings
	"""
	formatted_str = []
	
	structural_analysis_results = x.tainted_packages.search_methods("Landroid/telephony/TelephonyManager","getNetworkOperatorName", ".")
	for result in xrange(len(structural_analysis_results)) :
		registers = data_flow_analysis(structural_analysis_results, result, x)	
		
		local_formatted_str = "This application reads the operator name" 
		
		# we want only one occurence
		if not(local_formatted_str in formatted_str) :
			formatted_str.append(local_formatted_str)

		
	return formatted_str	

def detect_Telephony_CellID_lookup(x) :
	"""
		@param x : a VMAnalysis instance
		
		@rtype : a list of formatted strings
	"""
	formatted_str = []
	
	structural_analysis_results = x.tainted_packages.search_methods("Landroid/telephony/gsm/GsmCellLocation","getCid", ".")
	for result in xrange(len(structural_analysis_results)) :
		registers = data_flow_analysis(structural_analysis_results, result, x)		
		
		local_formatted_str = "This application reads the Cell ID value" 
		
		# we want only one occurence
		if not(local_formatted_str in formatted_str) :
			formatted_str.append(local_formatted_str)

		
	return formatted_str

def detect_Telephony_LAC_lookup(x) :
	"""
		@param x : a VMAnalysis instance
		
		@rtype : a list of formatted strings
	"""
	formatted_str = []
	
	structural_analysis_results = x.tainted_packages.search_methods("Landroid/telephony/gsm/GsmCellLocation","getLac", ".")
	for result in xrange(len(structural_analysis_results)) :
		registers = data_flow_analysis(structural_analysis_results, result, x)	
		
		local_formatted_str = "This application reads the Location Area Code value" 
		
		# we want only one occurence
		if not(local_formatted_str in formatted_str) :
			formatted_str.append(local_formatted_str)

		
	return formatted_str

def detect_Telephony_MCCMNC_lookup(x) :
	"""
		@param x : a VMAnalysis instance
		
		@rtype : a list of formatted strings
	"""
	formatted_str = []
	
	structural_analysis_results = x.tainted_packages.search_methods("Landroid/telephony/TelephonyManager","getNetworkOperator", ".")
	
	for result in xrange(len(structural_analysis_results)) :
		registers = data_flow_analysis(structural_analysis_results, result, x)	
		
		local_formatted_str = "This application reads the numeric name (MCC+MNC) of current registered operator." 
		
		# we want only one occurence
		if not(local_formatted_str in formatted_str) :
			formatted_str.append(local_formatted_str)

		
	return formatted_str
	
def detect_Telephony_DeviceID_lookup(x) :
	"""
		@param x : a VMAnalysis instance
		
		@rtype : a list of formatted strings
	"""
	formatted_str = []
	
	structural_analysis_results = x.tainted_packages.search_methods("Landroid/telephony/TelephonyManager","getDeviceId", ".")
	
	for result in xrange(len(structural_analysis_results)) :
		registers = data_flow_analysis(structural_analysis_results, result, x)	
		
		local_formatted_str = "This application reads the unique device ID for example, the IMEI for GSM and the MEID or ESN for CDMA phones" 
		
		# we want only one occurence
		if not(local_formatted_str in formatted_str) :
			formatted_str.append(local_formatted_str)

		
	return formatted_str

def detect_Telephony_IMSI_lookup(x) :
	"""
		@param x : a VMAnalysis instance
		
		@rtype : a list of formatted strings
	"""
	formatted_str = []
	
	structural_analysis_results = x.tainted_packages.search_methods("Landroid/telephony/TelephonyManager","getSubscriberId", ".")
	
	for result in xrange(len(structural_analysis_results)) :
		registers = data_flow_analysis(structural_analysis_results, result, x)	
		
		local_formatted_str = "This application reads the unique subscriber ID for example, the IMSI for a GSM phone" 
		
		# we want only one occurence
		if not(local_formatted_str in formatted_str) :
			formatted_str.append(local_formatted_str)

		
	return formatted_str

def detect_Telephony_SimSerialNumber_lookup(x) :
	"""
		@param x : a VMAnalysis instance
		
		@rtype : a list of formatted strings
	"""
	formatted_str = []
	
	structural_analysis_results = x.tainted_packages.search_methods("Landroid/telephony/TelephonyManager","getSimSerialNumber", ".")
	
	for result in xrange(len(structural_analysis_results)) :
		registers = data_flow_analysis(structural_analysis_results, result, x)	
		
		local_formatted_str = "This application reads the SIM's serial number" 
		
		# we want only one occurence
		if not(local_formatted_str in formatted_str) :
			formatted_str.append(local_formatted_str)

		
	return formatted_str
