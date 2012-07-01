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
import logging

# Logguer
log = logging.getLogger('log')

# Androguard import
from androguard.core.bytecode import *
from androguard.core.bytecodes.dvm import *
from androguard.core.bytecodes.apk import *
try :
	from androguard.core.analysis.ganalysis import *
except ImportError :
	print "The networkx module is not installed, please install it and try again"

# Androwarn modules import
from androwarn.core.core import *
from androwarn.search.search import *
from androwarn.util.util import *

def AnalyzeAPK(filename, raw=False, decompiler=None) :
    """
        Analyze an android application and setup all stuff for a more quickly analysis !

        @param filename : the filename of the android application or a buffer which represents the application
        @param raw : True is you would like to use a buffer
        @param decompiler : ded, dex2jad, dad
        
        @rtype : return the APK, DalvikVMFormat, and VMAnalysis objects
    """
    androconf.debug("APK ...")
    a = APK(filename, raw)

    d, dx = AnalyzeDex( a.get_dex(), raw=True )

    if decompiler != None :
      androconf.debug("Decompiler ...")
      decompiler = decompiler.lower()
      if decompiler == "dex2jad" :
        d.set_decompiler( DecompilerDex2Jad( d, androconf.CONF["PATH_DEX2JAR"], androconf.CONF["BIN_DEX2JAR"], androconf.CONF["PATH_JAD"], androconf.CONF["BIN_JAD"] ) )
      elif decompiler == "ded" :
        d.set_decompiler( DecompilerDed( d, androconf.CONF["PATH_DED"], androconf.CONF["BIN_DED"] ) )
      elif decompiler == "dad" :
        d.set_decompiler( DecompilerDAD( d, dx ) )
      else :
        print "Unknown decompiler, use default", decompiler
        d.set_decompiler( DecompilerDAD( d, dx ) )

    return a, d, dx

def AnalyzeDex(filename, raw=False) :
    """
        Analyze an android dex file and setup all stuff for a more quickly analysis !

        @param filename : the filename of the android dex file or a buffer which represents the dex file
        @param raw : True is you would like to use a buffe

        @rtype : return the DalvikVMFormat, and VMAnalysis objects
    """
    androconf.debug("DalvikVMFormat ...")
    d = None
    if raw == False :
        d = DalvikVMFormat( open(filename, "rb").read() )
    else :
        d = DalvikVMFormat( filename )

    androconf.debug("EXPORT VM to python namespace")
    ExportVMToPython( d )

    androconf.debug("VMAnalysis ...")
    dx = uVMAnalysis( d )
    #dx = VMAnalysis( d )

    androconf.debug("GVMAnalysis ...")
    gx = GVMAnalysis( dx, None )

    d.set_vmanalysis( dx )
    d.set_gvmanalysis( gx )

    androconf.debug("XREF ...")
    d.create_xref()
    androconf.debug("DREF ...")
    d.create_dref()

    return d, dx

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
	data['application_version']					= [grab_androidversion_name(a)]
	
	# APK 
	data['apk_file_SHA1_hash'] 					= [grab_apk_file_sha1_hash(apk_file)]
	data['apk_file_name'] 						= [grab_filename(a)]
	data['file_list']							=  grab_file_list(a)
	
	
	# Manifest
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
	data['telephony_identifiers_leakage'].extend( detect_Telephony_DeviceID_lookup(x) )
	data['telephony_identifiers_leakage'].extend( detect_Telephony_IMSI_lookup(x) )
	data['telephony_identifiers_leakage'].extend( detect_Telephony_SimSerialNumber_lookup(x) )
	
	
	# -- Device settings harvesting
	data['device_settings_harvesting']			= detect_Telephony_DeviceSoftwareVersion_lookup(x)
	data['device_settings_harvesting']	.extend(  detect_Telephony_phone_state_lookup(x)  )
	
	
	# -- Physical location lookup
	data['location_lookup']						= detect_Location_lookup(x)
	
	
	# -- Connection interfaces information exfiltration
	data['connection_interfaces_exfiltration']	= detect_WiFi_Credentials_lookup(x)
	
	
	# -- Telephony services abuse
	data['telephony_services_abuse']			= detect_Telephony_Phone_Call_abuse(x)
	data['telephony_services_abuse']	 .extend( detect_Telephony_SMS_abuse(x) )
	
	
	# -- Audio/Video eavesdropping
	data['media_recorder_abuse']				= detect_MediaRecorder_Voice_record(x)
	data['media_recorder_abuse']		 .extend (detect_MediaRecorder_Video_capture(x) )
	
	# -- Suspicious connection establishment
	data['suspicious_connection_establishment']	= detect_Socket_use(x)
	
	
	# -- PIM data leakage
	data['PIM_data_leakage']					= detect_ContactAccess_lookup(x)
	data['PIM_data_leakage']	 		 .extend( detect_Telephony_SMS_read(x) )
	
	
	# -- Native code execution
	data['code_execution']						= detect_Library_loading(x)
	data['code_execution']				 .extend( detect_UNIX_command_execution(x) )
	

	

	
	return data
