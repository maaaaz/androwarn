#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Global imports
import os, re, logging, urllib2, hashlib
from urllib2 import urlopen, HTTPError

# Androguard imports
from androguard.core.analysis import analysis
from androguard.core.bytecodes.apk import *
from xml.dom import minidom

# Androwarn modules import
from androwarn.core.core import *
from androwarn.constants.api_constants import *
from androwarn.util.util import *

# Constants 
ERROR_INDEX_NOT_FOUND = -2

REQUEST_TIMEOUT = 4
ERROR_APP_DESC_NOT_FOUND = 'N/A'

CONNECTION_DISABLED = 0
CONNECTION_ENABLED = 1

# Logguer
log = logging.getLogger('log')


# Some aliases to the original functions

# APK and Manifest related functions #
def grab_apk_file_sha1_hash(apk_file) :
	"""
	@param apk_file : apk file path (not an apk instance)
	
	@rtype : the hexified string SHA1 hash
	"""	
	block_size=2**20
	sha1 = hashlib.sha1()
	
	f = open(apk_file,'rb')
	
	while True:
		data = f.read(block_size)
		if not data:
			break
		sha1.update(data)
	f.close()
	return sha1.hexdigest()
	
def grab_filename(apk) :
	"""
	Return the filename of the APK
	"""
	# Grab only the name.apk, not the full path provided
	#return apk.filename
	return apk.filename.split('/')[-1]
	

def grab_application_package_name(apk) :
	"""
	Return the name of the package
	"""
	return apk.package

def grab_application_name_description_icon(package_name, no_connection) :
	"""
	@param package_name : package name
	
	@rtype : (name, description, icon) string tuple
	"""
	if no_connection == CONNECTION_DISABLED :
		return ERROR_APP_DESC_NOT_FOUND, ERROR_APP_DESC_NOT_FOUND, ERROR_APP_DESC_NOT_FOUND		
	try :
		# Content in English
		url = "http://play.google.com/store/apps/details?id=%s&hl=en" % str(package_name)
		
		req = urllib2.Request(url)
		response = urllib2.urlopen(req, timeout=REQUEST_TIMEOUT)
		the_page = response.read()
		
		p_name = re.compile(ur'''<h1 class="doc-banner-title">(.*)</h1>''')
		p_desc = re.compile(ur'''(?:\<div id=\"doc-original-text\" \>)(.*)(?:\<\/div\>\<\/div\>\<div class\=\"doc-description-overflow\"\>)''')
		p_icon = re.compile(ur'''(?:\<div class\=\"doc-banner-icon\"\>)(.*)(?:\<\/div\>\<\/td\><td class="doc-details-ratings-price")''')
		
		if p_name.findall(the_page) and p_desc.findall(the_page) and p_icon.findall(the_page) :
			name = strip_HTML_tags(p_name.findall(the_page)[0].decode("utf-8"))
			desc = strip_HTML_tags(p_desc.findall(the_page)[0].decode("utf-8"))
			#icon_link = strip_HTML_tags(p_icon.findall(the_page)[0])
			icon_link = p_icon.findall(the_page)[0]

			#return (p_name.findall(the_page)[0].decode("utf-8"), p_desc.findall(the_page)[0].decode("utf-8"), p_icon.findall(the_page)[0])
			return (name, desc, icon_link)

		else :
			log.warn("'%s' application's description and icon could not be found in the page" % str(package_name))
			return ERROR_APP_DESC_NOT_FOUND, ERROR_APP_DESC_NOT_FOUND, ERROR_APP_DESC_NOT_FOUND
	
	except HTTPError :
		log.warn("'%s' application name does not exist on Google Play" % str(package_name))
		return ERROR_APP_DESC_NOT_FOUND, ERROR_APP_DESC_NOT_FOUND, ERROR_APP_DESC_NOT_FOUND

def grab_androidversion_code(apk) :
	"""
	Return the android version code
	"""
	return apk.androidversion["Code"]

def grab_androidversion_name(apk) :
	"""
	Return the android version name 
	"""
	return apk.androidversion["Name"]

def grab_main_activity(apk) :
	"""
	Return the name of the main activity
	"""
	for i in apk.xml :
		x = set()
		y = set()
		for item in apk.xml[i].getElementsByTagName("activity") :
			for sitem in item.getElementsByTagName( "action" ) :
				val = sitem.getAttribute( "android:name" )
				if val == "android.intent.action.MAIN" :
					x.add( item.getAttribute( "android:name" ) )
					for sitem in item.getElementsByTagName( "category" ) :
						val = sitem.getAttribute( "android:name" )
						if val == "android.intent.category.LAUNCHER" :
							y.add( item.getAttribute( "android:name" ) )
		z = x.intersection(y)
		if len(z) > 0 :
			return apk.format_value(z.pop())
		return None

def grab_activities(apk) :
	"""
	Return the android:name attribute of all activities
	"""
	return apk.get_elements("activity", "android:name")

def grab_services(apk) :
	"""
	Return the android:name attribute of all services
	"""
	return apk.get_elements("service", "android:name")

def grab_receivers(apk) :
	"""
	Return the android:name attribute of all receivers
	"""
	return apk.get_elements("receiver", "android:name")

def grab_providers(apk) :
	"""
	Return the android:name attribute of all providers
	"""
	return apk.get_elements("provider", "android:name")

def grab_permissions(apk) :
	"""
	Return a list of permissions
	"""
	return apk.get_permissions()

def grab_features(apk) :
	"""
	Return a list of features
	"""
	features = []
	xml = {}
	for i in apk.zip.namelist() :
		if i == "AndroidManifest.xml" :
			xml[i] = minidom.parseString( AXMLPrinter( apk.zip.read( i ) ).getBuff() )
			for item in xml[i].getElementsByTagName('uses-feature') :
				features.append( str( item.getAttribute("android:name") ) )
	return features

def grab_libraries(apk) :
	"""
	Return the android:name attributes for libraries
	"""
	return apk.get_elements( "uses-library", "android:name" )

def grab_file_list(apk) :
	"""
	Return the files inside the AP
	"""
	return apk.zip.namelist()

def grab_certificate(apk, filename) :
	"""
	Return a certificate object by giving the name in the apk file
	"""
	import chilkat
	cert = chilkat.CkCert()
	f = apk.get_file( filename )
	success = cert.LoadFromBinary(f, len(f))
	return success, cert

def grab_certificate_information(apk) :

	file_list = grab_file_list(apk)
	p_find_cert = re.compile('^(META-INF\/(.*).RSA)$')
	cert_found = ''
	
	for i in file_list :
		if p_find_cert.match(i):
			cert_found = p_find_cert.match(i).groups()[0]
			log.info("Certificate found : %s", p_find_cert.match(i).groups()[0])

	
	success, cert = grab_certificate(apk, cert_found)
	
	if success != True :
		log.error("Can not get the certificate %s from the APK" % cert_found)

	cert_info = []
	cert_info.append("Issuer:\n\tC=%s, ST=%s, L=%s, O=%s,\n\tOU=%s, CN=%s" % (cert.issuerC(), cert.issuerS(), cert.issuerL(), cert.issuerO(), cert.issuerOU(), cert.issuerCN()))
	cert_info.append("Subject:\n\tC=%s, ST=%s, L=%s, O=%s,\n\tOU=%s, CN=%s" % (cert.subjectC(), cert.subjectS(), cert.subjectL(), cert.subjectO(), cert.subjectOU(), cert.subjectCN()))
	cert_info.append("Serial number: %s" % cert.serialNumber())
	cert_info.append("SHA1 thumbprint: %s" % cert.sha1Thumbprint())
	
	return cert_info
	
####################################

# Classes and Packages related functions #
# -- Classes -- #
def grab_classes_list(x) :
	"""
	Return a list of the canonical name (ex "android.widget.GridView") of all the classes used
	"""
	tainted_list = x.get_tainted_packages().get_packages()
	list = []
	for item in tainted_list:
		instance, name = item
		if re.match( '^L[a-zA-Z]+(?:\/[a-zA-Z]+)*(.)*;$', name) :
			global_part = name[1:-1].split('/')
			
			final_part = global_part[:-1]
			last_part = global_part[-1].split('$')[0]
			final_part.append(str(last_part))
			
			final_name = '.'.join(str(i) for i in final_part)
			
			# Do not include one-char classes name and check if the name is already in the list
			if(len(final_name) > 1 and not(final_name in list)) : 
				list.append(final_name)
	list.sort()		
	return list

def grab_internal_classes_list(x) :
	"""
	Return a list of the canonical name (ex "android.widget.GridView") of the internal classes used
	"""
	tainted_list = x.get_tainted_packages().get_internal_packages()
	list = []
	for item in tainted_list:
		name = item.get_method().get_class_name()
		if re.match( '^L[a-zA-Z]+(?:\/[a-zA-Z]+)*(.)*;$', name) :
			global_part = name[1:-1].split('/')
			final_part = global_part[:-1]
			last_part = global_part[-1].split('$')[0]
			final_part.append(str(last_part))
			final_name = '.'.join(str(i) for i in final_part)
			
			# Do not include one-char classes name and check if the name is already in the list
			if(len(final_name) > 1 and not(final_name in list)) : 
				list.append(final_name)
			
	list.sort()		
	return list

def grab_internal_new_classes_list(x) :
	"""
	Return a list of the canonical name (ex "android.widget.GridView") of the internal new classes used
	"""
	tainted_list = x.get_tainted_packages().get_internal_new_packages()
	list = []
	for item in tainted_list:
		name = item.get_method().get_class_name()
		if re.match( '^L[a-zA-Z]+(?:\/[a-zA-Z]+)*(.)*;$', name) :
			global_part = name[1:-1].split('/')
			final_part = global_part[:-1]
			last_part = global_part[-1].split('$')[0]
			final_part.append(str(last_part))
			final_name = '.'.join(str(i) for i in final_part)
			
			# Do not include one-char classes name and check if the name is already in the list
			if(len(final_name) > 1 and not(final_name in list)) : 
				list.append(final_name)
			
	list.sort()		
	return list

def grab_external_classes_list(x) :
	"""
	Return a list of the canonical name (ex "android.widget.GridView") of the external packages used
	"""
	tainted_list = x.get_tainted_packages().get_external_packages()
	list = []
	for item in tainted_list:
		name = item.get_method().get_class_name()
		if re.match( '^L[a-zA-Z]+(?:\/[a-zA-Z]+)*(.)*;$', name) :
			global_part = name[1:-1].split('/')
			final_part = global_part[:-1]
			last_part = global_part[-1].split('$')[0]
			final_part.append(str(last_part))
			final_name = '.'.join(str(i) for i in final_part)
			
			# Do not include one-char classes name and check if the name is already in the list
			if(len(final_name) > 1 and not(final_name in list)) : 
				list.append(final_name)
			
	list.sort()		
	return list

def search_class(x, package_name) :
	"""
	@param x : a VMAnalysis instance
	@param package_name : a regexp for the name of the package
	
	@rtype : a list of classes' paths
	"""
	return x.tainted_packages.search_packages( package_name )

def search_field(x, field_name) :
	"""
	@param x : a VMAnalysis instance
	@param field_name : a regexp for the field name
	
	@rtype : a list of classes' paths
	"""
	for f, _ in x.tainted_variables.get_fields() :
		field_info = f.get_info()
		if field_name in field_info :
			return f
	return []

def search_string(x, string_name) :
	"""
	@param x : a VMAnalysis instance
	@param string_name : a regexp for the string name
	
	@rtype : a list of classes' paths
	"""
	for s, _ in x.tainted_variables.get_strings() :
		string_info = s.get_info()
		if string_name in string_info :
			return s
	return []

def search_class_in_the_list(canonical_class_list,canonical_class_name):
        """
			@param canonical_class_list : a canonical list of classes
            @param canonical_class_name : a regexp for the name of the class
        
            @rtype : a list of class names
        """
        l = []
        ex = re.compile( canonical_class_name )   
        l = filter(ex.search, canonical_class_list)
        
        return l


# -- Packages -- #
def grab_packages_list(x) :
	"""
	Return a list of the canonical name (ex "android.widget.GridView") of all the packages used
	"""
	tainted_list = x.get_tainted_packages().get_packages()
	list = []
	for item in tainted_list:
		instance, name = item
		if re.match( '^L[a-zA-Z]+(?:\/[a-zA-Z]+)*(.)*;$', name) :
			global_part = name[1:-1].split('/')
			final_part = global_part[:-1]
			final_name = '.'.join(str(i) for i in final_part)

			# Do not include one-char classes name and check if the name is already in the list
			if(len(final_name) > 1 and not(final_name in list)) : 
				list.append(final_name)
			
	list.sort()		
	return list


def grab_internal_packages_list(x) :
	"""
	Return a list of the canonical name (ex "android.widget.GridView") of the internal classes used
	"""
	tainted_list = x.get_tainted_packages().get_internal_packages()
	list = []
	for item in tainted_list:
		name = item.get_method().get_class_name()
		if re.match( '^L[a-zA-Z]+(?:\/[a-zA-Z]+)*(.)*;$', name) :
			global_part = name[1:-1].split('/')
			final_part = global_part[:-1]
			final_name = '.'.join(str(i) for i in final_part)
			
			# Do not include one-char classes name and check if the name is already in the list
			if(len(final_name) > 1 and not(final_name in list)) : 
				list.append(final_name)
			
	list.sort()		
	return list


def grab_internal_new_packages_list(x) :
	"""
	Return a list of the canonical name (ex "android.widget.GridView") of the internal new classes used
	"""
	tainted_list = x.get_tainted_packages().get_internal_new_packages()
	list = []
	for item in tainted_list:
		name = item.get_method().get_class_name()
		if re.match( '^L[a-zA-Z]+(?:\/[a-zA-Z]+)*(.)*;$', name) :
			global_part = name[1:-1].split('/')
			final_part = global_part[:-1]
			final_name = '.'.join(str(i) for i in final_part)
			
			# Do not include one-char classes name and check if the name is already in the list
			if(len(final_name) > 1 and not(final_name in list)) : 
				list.append(final_name)
			
	list.sort()		
	return list


def grab_external_packages_list(x) :
	"""
	Return a list of the canonical name (ex "android.widget.GridView") of the external packages used
	"""
	tainted_list = x.get_tainted_packages().get_external_packages()
	list = []
	for item in tainted_list:
		name = item.get_method().get_class_name()
		if re.match( '^L[a-zA-Z]+(?:\/[a-zA-Z]+)*(.)*;$', name) :
			global_part = name[1:-1].split('/')
			final_part = global_part[:-1]
			final_name = '.'.join(str(i) for i in final_part)
			
			# Do not include one-char classes name and check if the name is already in the list
			if(len(final_name) > 1 and not(final_name in list)) : 
				list.append(final_name)
			
	list.sort()		
	return list


def search_package_in_the_list(canonical_package_list,canonical_package_name):
	"""
		@param canonical_package_list : a canonical list of package
		@param canonical_package_name : a regexp for the name of the package

	
		@rtype : a list of package names
	"""
	l = []
	ex = re.compile( canonical_package_name )   
	l = filter(ex.search, canonical_package_list)
	
	return l
##########################################

# 	Method calls  #
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
		method_call_index_to_find = b[result].get_offset()
		
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


# -- Socket -- #			
def detect_Socket_use(x) :
	"""
		@param x : a VMAnalysis instance
		
		@rtype : a list of formatted strings
	"""
	formatted_str = []
	
	b = x.tainted_packages.search_methods("Ljava/net/Socket","<init>", ".")
	
	for result in xrange(len(b)) :
		method = b[result].get_method()
		method_call_index_to_find = b[result].get_offset()
		
		registers = backtrace_registers_before_call(x, method, method_call_index_to_find)
		log.info("Class '%s' - Method '%s' - register state before call %s" % (b[result].get_class_name(),b[result].get_name(), registers))

		#print "[+] Registers state before call " + str(registers)
				
		if len(registers) > 0 :
			remote_address 	= get_register_value(1, registers) # 1 is the index of the PARAMETER called in the method
			remote_port		= get_register_value(2, registers)
			
			local_formatted_str = "This application opens a Socket and connects it to the remote address '%s' on the '%s' port " % (remote_address, remote_port)
			if not(local_formatted_str in formatted_str) :
				formatted_str.append(local_formatted_str)		
	
	return formatted_str

# -- Voice Record -- #
def detect_MediaRecorder_Voice_record(x) :
	"""
		@param x : a VMAnalysis instance
		
		@rtype : a list of formatted strings
	"""	
	formatted_str = []
	
	b = x.tainted_packages.search_methods("Landroid/media/MediaRecorder","setAudioSource", ".")	
	
	for result in xrange(len(b)) :
		method = b[result].get_method()
		method_call_index_to_find = b[result].get_offset()
		
		registers = backtrace_registers_before_call(x, method, method_call_index_to_find)
		log.info("Class '%s' - Method '%s' - register state before call %s" % (b[result].get_class_name(),b[result].get_name(), registers))

		#print "[+] Registers state before call " + str(registers)
				
		if len(registers) > 0 :
			audio_source_int 	= int(get_register_value(1, registers)) # 1 is the index of the PARAMETER called in the method
			audio_source_name 	= get_constants_name_from_value(MediaRecorder_AudioSource, audio_source_int)
			
			local_formatted_str = "This application records audio from the '%s' source " % audio_source_name
			if not(local_formatted_str in formatted_str) :
				formatted_str.append(local_formatted_str)
		
	return formatted_str

# -- Video Record -- #
def detect_MediaRecorder_Video_capture(x) :
	"""
		@param x : a VMAnalysis instance
		
		@rtype : a list of formatted strings
	"""	
	formatted_str = []
	
	# Retrieve the Source #
	b = x.tainted_packages.search_methods("Landroid/media/MediaRecorder","setVideoSource", ".")	
	for result in xrange(len(b)) :
		method = b[result].get_method()
		method_call_index_to_find = b[result].get_offset()
		
		registers = backtrace_registers_before_call(x, method, method_call_index_to_find)
		log.info("Class '%s' - Method '%s' - register state before call %s" % (b[result].get_class_name(),b[result].get_name(), registers))
		#print "[+] Registers state before call " + str(registers)
				
		if len(registers) > 0 :
			video_source_int 	= int(get_register_value(1, registers)) # 1 is the index of the PARAMETER called in the method
			video_source_name 	= get_constants_name_from_value(MediaRecorder_VideoSource, video_source_int)
			
			local_formatted_str = "This application captures video from the '%s' source" % video_source_name
			if not(local_formatted_str in formatted_str) :
				formatted_str.append(local_formatted_str)
	
	
	# Retrieve the recorded file path #
	'''
	b = x.tainted_packages.search_methods("Landroid/media/MediaRecorder","setOutputFile", ".")	
	for result in xrange(len(b)) :
		method = b[result].get_method()
		method_call_index_to_find = b[result].get_offset()
		
		registers = backtrace_registers_before_call(x, method, method_call_index_to_find)
		log.info("Class '%s' - Method '%s' - register state before call %s" % (b[result].get_class_name(),b[result].get_name(), registers))
		#print "[+] Registers state before call " + str(registers)
				
		if len(registers) > 0 :
			file_path 	= get_register_value(1, registers) # 1 is the index of the PARAMETER called in the method
			
			# Avoid false-positives #
			if len(file_path) > 1 :
				formatted_str += " and write the recorded file to '%s'" % file_path
	'''	
	return formatted_str


def detect_Telephony_Operator_lookup(x) :
	"""
		@param x : a VMAnalysis instance
		
		@rtype : a list of formatted strings
	"""
	formatted_str = []
	
	b = x.tainted_packages.search_methods("Landroid/telephony/TelephonyManager","getNetworkOperatorName", ".")
	for result in xrange(len(b)) :
		method = b[result].get_method()
		method_call_index_to_find = b[result].get_offset()
		registers = backtrace_registers_before_call(x, method, method_call_index_to_find)
		log.info("Class '%s' - Method '%s' - register state before call %s" % (b[result].get_class_name(),b[result].get_name(), registers))
				
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
	
	b = x.tainted_packages.search_methods("Landroid/telephony/gsm/GsmCellLocation","getCid", ".")
	for result in xrange(len(b)) :
		method = b[result].get_method()
		method_call_index_to_find = b[result].get_offset()
		registers = backtrace_registers_before_call(x, method, method_call_index_to_find)
		log.info("Class '%s' - Method '%s' - register state before call %s" % (b[result].get_class_name(),b[result].get_name(), registers))
				
		local_formatted_str = "This application reads the CellID value" 
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
	
	b = x.tainted_packages.search_methods("Landroid/telephony/gsm/GsmCellLocation","getLac", ".")
	for result in xrange(len(b)) :
		method = b[result].get_method()
		method_call_index_to_find = b[result].get_offset()
		registers = backtrace_registers_before_call(x, method, method_call_index_to_find)
		log.info("Class '%s' - Method '%s' - register state before call %s" % (b[result].get_class_name(),b[result].get_name(), registers))
				
		local_formatted_str = "This application reads the Location Area value" 
		
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
	
	b = x.tainted_packages.search_methods("Landroid/telephony/TelephonyManager","getNetworkOperator", ".")
	for result in xrange(len(b)) :
		method = b[result].get_method()
		method_call_index_to_find = b[result].get_offset()
		registers = backtrace_registers_before_call(x, method, method_call_index_to_find)
		log.info("Class '%s' - Method '%s' - register state before call %s" % (b[result].get_class_name(),b[result].get_name(), registers))
				
		local_formatted_str = "This application reads the numeric name (MCC+MNC) of current registered operator." 
		
		# we want only one occurence
		if not(local_formatted_str in formatted_str) :
			formatted_str.append(local_formatted_str)

		
	return formatted_str

def detect_Telephony_phone_state_lookup(x) :
	"""
		@param x : a VMAnalysis instance
		
		@rtype : a list of formatted strings
	"""
	formatted_str = []
	
	b = x.tainted_packages.search_methods("Landroid/telephony/TelephonyManager","getCallState", ".")
	for result in xrange(len(b)) :
		method = b[result].get_method()
		method_call_index_to_find = b[result].get_offset()
		registers = backtrace_registers_before_call(x, method, method_call_index_to_find)
		log.info("Class '%s' - Method '%s' - register state before call %s" % (b[result].get_class_name(),b[result].get_name(), registers))
				
		local_formatted_str = "This application reads the phone's current state" 
		
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
	
	b = x.tainted_packages.search_methods("Landroid/telephony/TelephonyManager","getDeviceId", ".")
	for result in xrange(len(b)) :
		method = b[result].get_method()
		method_call_index_to_find = b[result].get_offset()
		registers = backtrace_registers_before_call(x, method, method_call_index_to_find)
		log.info("Class '%s' - Method '%s' - register state before call %s" % (b[result].get_class_name(),b[result].get_name(), registers))
				
		local_formatted_str = "This application reads the unique device ID, for example, the IMEI for GSM and the MEID or ESN for CDMA phones" 
		
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
	
	b = x.tainted_packages.search_methods("Landroid/telephony/TelephonyManager","getSubscriberId", ".")
	for result in xrange(len(b)) :
		method = b[result].get_method()
		method_call_index_to_find = b[result].get_offset()
		registers = backtrace_registers_before_call(x, method, method_call_index_to_find)
		log.info("Class '%s' - Method '%s' - register state before call %s" % (b[result].get_class_name(),b[result].get_name(), registers))
				
		local_formatted_str = "This application reads the unique subscriber ID, for example, the IMSI for a GSM phone" 
		
		# we want only one occurence
		if not(local_formatted_str in formatted_str) :
			formatted_str.append(local_formatted_str)

		
	return formatted_str

def detect_Telephony_DeviceSoftwareVersion_lookup(x) :
	"""
		@param x : a VMAnalysis instance
		
		@rtype : a list of formatted strings
	"""
	formatted_str = []
	
	b = x.tainted_packages.search_methods("Landroid/telephony/TelephonyManager","getDeviceSoftwareVersion", ".")
	for result in xrange(len(b)) :
		method = b[result].get_method()
		method_call_index_to_find = b[result].get_offset()
		registers = backtrace_registers_before_call(x, method, method_call_index_to_find)
		log.info("Class '%s' - Method '%s' - register state before call %s" % (b[result].get_class_name(),b[result].get_name(), registers))
				
		local_formatted_str = "This application reads the software version number for the device, for example, the IMEI/SV for GSM phones" 
		
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
	
	b = x.tainted_packages.search_methods("Landroid/telephony/TelephonyManager","getSimSerialNumber", ".")
	for result in xrange(len(b)) :
		method = b[result].get_method()
		method_call_index_to_find = b[result].get_offset()
		registers = backtrace_registers_before_call(x, method, method_call_index_to_find)
		log.info("Class '%s' - Method '%s' - register state before call %s" % (b[result].get_class_name(),b[result].get_name(), registers))
				
		local_formatted_str = "This application reads the serial number of the SIM" 
		
		# we want only one occurence
		if not(local_formatted_str in formatted_str) :
			formatted_str.append(local_formatted_str)

		
	return formatted_str

def detect_ContactAccess_lookup(x) :
	"""
		@param x : a VMAnalysis instance
		
		@rtype : a list of formatted strings
	"""
	formatted_str = []
	
	detector_1 = search_field(x, "Landroid/provider/ContactsContract$CommonDataKinds$Phone;")
		
	detectors = [detector_1]
	
	if detectors :
		local_formatted_str = 'This application reads/edits contact data'
		formatted_str.append(local_formatted_str)
		
		for res in detectors :
			if res :
				try :
					log_result_path_information(res, "Contact access", "field")
				except :
					log.warn("Detector result '%s' is not a Path instance" % res)
					
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
	


def detect_Telephony_SMS_read(x) :
	"""
		@param x : a VMAnalysis instance
		
		@rtype : a list of formatted strings
	"""
	formatted_str = []
	
	detector_1 = search_string(x, "content://sms/inbox")
		
	detectors = [detector_1]
	
	if detectors :
		local_formatted_str = 'This application reads the SMS inbox'
		formatted_str.append(local_formatted_str)
		
		for res in detectors :
			if res :
				try :
					log_result_path_information(res, "SMS Inbox", "string")
				except :
					log.warn("Detector result '%s' is not a Path instance" % res) 
		
	return formatted_str


def detect_WiFi_Credentials_lookup(x) :
	"""
		@param x : a VMAnalysis instance
		
		@rtype : a list of formatted strings
	"""
	# Several HTC devices suffered from a bug allowing to dump wpa_supplicant.conf file containing clear text credentials
	formatted_str = []
	
	b = x.tainted_packages.search_methods("Landroid/net/wifi/WifiConfiguration","toString", ".")
	for result in xrange(len(b)) :
		method = b[result].get_method()
		method_call_index_to_find = b[result].get_offset()
		registers = backtrace_registers_before_call(x, method, method_call_index_to_find)
		log.info("Class '%s' - Method '%s' - register state before call %s" % (b[result].get_class_name(),b[result].get_name(), registers))
				
		local_formatted_str = "This application reads the WiFi credentials" 
		
		# we want only one occurence
		if not(local_formatted_str in formatted_str) :
			formatted_str.append(local_formatted_str)

		
	return formatted_str	

def detect_UNIX_command_execution(x) :
	"""
		@param x : a VMAnalysis instance
		
		@rtype : a list of formatted strings
	"""
	# Several HTC devices suffered from a bug allowing to dump wpa_supplicant.conf file containing clear text credentials
	formatted_str = []
	
	b = x.tainted_packages.search_methods("Ljava/lang/Runtime","exec", ".")
	for result in xrange(len(b)) :
		method = b[result].get_method()
		method_call_index_to_find = b[result].get_offset()
		registers = backtrace_registers_before_call(x, method, method_call_index_to_find)
		log.info("Class '%s' - Method '%s' - register state before call %s" % (b[result].get_class_name(),b[result].get_name(), registers))
				
		local_formatted_str = "This application executes that UNIX command" 
		
		# we want only one occurence
		if not(local_formatted_str in formatted_str) :
			formatted_str.append(local_formatted_str)

		
	return formatted_str

def detect_Location_lookup(x) :
	"""
		@param x : a VMAnalysis instance
		
		@rtype : a list of formatted strings
	"""
	# Several HTC devices suffered from a bug allowing to dump wpa_supplicant.conf file containing clear text credentials
	formatted_str = []
	
	b = x.tainted_packages.search_methods("Landroid/location/LocationManager","getProviders", ".")
	for result in xrange(len(b)) :
		method = b[result].get_method()
		method_call_index_to_find = b[result].get_offset()
		registers = backtrace_registers_before_call(x, method, method_call_index_to_find)
		log.info("Class '%s' - Method '%s' - register state before call %s" % (b[result].get_class_name(),b[result].get_name(), registers))
				
		local_formatted_str = "This application reads location information from available providers" 
		
		# we want only one occurence
		if not(local_formatted_str in formatted_str) :
			formatted_str.append(local_formatted_str)
		
	return formatted_str

def detect_Library_loading(x) :
	"""
		@param x : a VMAnalysis instance
		
		@rtype : a list of formatted strings
	"""
	# Several HTC devices suffered from a bug allowing to dump wpa_supplicant.conf file containing clear text credentials
	formatted_str = []
	
	b = x.tainted_packages.search_methods("Ljava/lang/System","loadLibrary", ".")
	for result in xrange(len(b)) :
		method = b[result].get_method()
		method_call_index_to_find = b[result].get_offset()
		registers = backtrace_registers_before_call(x, method, method_call_index_to_find)
		log.info("Class '%s' - Method '%s' - register state before call %s" % (b[result].get_class_name(),b[result].get_name(), registers))
		
		
					
		local_formatted_str = "This application loads a native library" 
		
		# If we're lucky enough to directly have the library's name
		if len(registers) == 1 :
			local_formatted_str = "%s : '%s'" % (local_formatted_str, get_register_value(0, registers))
		
		# we want only one occurence
		if not(local_formatted_str in formatted_str) :
			formatted_str.append(local_formatted_str)

		
	return formatted_str
