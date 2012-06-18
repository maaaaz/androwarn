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
import re, logging

# Androwarn modules import
from androwarn.core.core import *
from androwarn.search.search import *
from androwarn.util.util import *

# Logguer
log = logging.getLogger('log')


def perform_analysis(apk_file, a, d, x, no_connection) :
	"""
	@param apk_file : apk file path
	@param a 		: an APK instance, DalvikVMFormat, and VMAnalysis objects
	@param d 		: a DalvikVMFormat instance
	@param x 		: a VMAnalysis instance
	
	@rtype : a dictionary of strings lists { "apk_files" : ["1", "2", "3"...], "application_name" : ['example'], ...}
	"""
	data = {}
	
	# Application
	data['application_package_name'] 			= [grab_application_package_name(a)]
	app_name, app_description, app_icon			= grab_application_name_description_icon(data['application_package_name'][0], no_connection)
	data['application_name']					= [app_name]
	data['application_description']				= [app_description]
	data['application_icon'] 					= [app_icon]
	
	
	# APK 
	data['apk_file_SHA1_hash'] 					= [grab_apk_file_sha1_hash(apk_file)]
	data['apk_file_name'] 						= [grab_filename(a)]
	data['file_list']							=  grab_file_list(a)
	
	
	# Manifest
	data['androidversion_code']					= [grab_androidversion_code(a)]
	data['androidversion_name']					= [grab_androidversion_name(a)]
	data['main_activity']						= [grab_main_activity(a)]
	data['activities']							=  grab_activities(a)
	data['services']							=  grab_services(a)
	data['receivers']							=  grab_receivers(a)
	data['providers']							=  grab_providers(a)
	data['permissions']							=  grab_permissions(a)
	data['features']							=  grab_features(a)
	data['libraries']							=  grab_libraries(a)
	data['certificate_information']				=  grab_certificate_information(a)
	
	
	# Code
	# -- Classes
	data['classes_list']						=  grab_classes_list(x)
	data['internal_new_classes_list']			=  grab_internal_new_classes_list(x)
	data['external_classes_list']				=  grab_external_classes_list(x)
	# -- Packages
	data['internal_packages_list']				=  grab_internal_packages_list(x)
	data['internal_new_packages_list']			=  grab_internal_new_packages_list(x)
	data['external_packages_list']				=  grab_external_packages_list(x)
	
	
	# Malicious Behaviours Detection
	# -- Telephony identifiers leakage
	data['telephony_identifiers_leakage']		= detect_Telephony_Operator_lookup(x)
	data['telephony_identifiers_leakage'].extend( detect_Telephony_CellID_lookup(x) )
	data['telephony_identifiers_leakage'].extend( detect_Telephony_LAC_lookup(x) )
	data['telephony_identifiers_leakage'].extend( detect_Telephony_MCCMNC_lookup(x) )
	data['telephony_identifiers_leakage'].extend( detect_Telephony_phone_state_lookup(x) )
	data['telephony_identifiers_leakage'].extend( detect_Telephony_DeviceID_lookup(x) )
	data['telephony_identifiers_leakage'].extend( detect_Telephony_IMSI_lookup(x) )
	data['telephony_identifiers_leakage'].extend( detect_Telephony_SimSerialNumber_lookup(x) )
	data['telephony_identifiers_leakage'].extend( detect_Telephony_DeviceSoftwareVersion_lookup(x) )
	
	
	# -- Telephony services abuse
	data['telephony_services_abuse']			= detect_Telephony_Phone_Call_abuse(x)
	data['telephony_services_abuse']	 .extend( detect_Telephony_SMS_read(x) )
	data['telephony_services_abuse']	 .extend( detect_Telephony_SMS_abuse(x) )
	
	
	# -- Physical location lookup
	data['location_lookup']						= detect_Location_lookup(x)
	
	# -- Contact list lookup
	data['contact_lookup']						= detect_ContactAccess_lookup(x)
	
	# -- Native code execution
	data['native_code_execution']				= detect_Library_loading(x)
	
	# -- UNIX command execution
	data['unix_command_execution']				= detect_UNIX_command_execution(x)
	
	# -- WIFI credentials leakage
	data['wifi_credentials_leakage']			= detect_WiFi_Credentials_lookup(x)
	
	# -- Suspicious connection establishment
	data['suspicious_connection_establishment']	= detect_Socket_use(x)
	
	# -- Audio/Video eavesdropping
	data['media_recorder_abuse']				= detect_MediaRecorder_Voice_record(x)
	data['media_recorder_abuse']		 .extend (detect_MediaRecorder_Video_capture(x) )
	
	return data
