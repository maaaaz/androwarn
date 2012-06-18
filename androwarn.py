#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Global imports
import sys, os, re, logging

# OptionParser imports
from optparse import OptionParser

# Androguard imports
PATH_INSTALL = "/home/android/tools/androguard/"
sys.path.append(PATH_INSTALL)

from androlyze import *
from androguard.core import *
from androguard.core.androgen import *
from androguard.core.androconf import *
from androguard.core.bytecode import *
from androguard.core.bytecodes.jvm import *
from androguard.core.bytecodes.dvm import *
from androguard.core.bytecodes.apk import *
from androguard.core.analysis.analysis import *
from androguard.core.analysis.ganalysis import *
from androguard.decompiler.decompiler import *
#from androguard.core.analysis.risk import *

# Androwarn modules import
PATH_INSTALL = "./"
sys.path.append(PATH_INSTALL)
from androwarn.core.core import *
from androwarn.search.search import *
from androwarn.util.util import *
from androwarn.report.report import *
from androwarn.analysis.analysis import *

# Logger definition
log = logging.getLogger('log')
log.setLevel(logging.DEBUG)
formatter = logging.Formatter('[%(levelname)s] %(message)s')
handler = logging.StreamHandler()
handler.setFormatter(formatter)
log.addHandler(handler)

# Options definition
option_0 = { 'name' : ('-i', '--input'), 'help' : 'APK file to analyze', 'nargs' : 1 }
option_1 = { 'name' : ('-v', '--verbose'), 'help' : 'Verbosity level { 1-4 }  ( ESSENTIAL, MODERATE, ADVANCED, EXPERT )', 'nargs' : 1 }
option_2 = { 'name' : ('-r', '--report'), 'help' : 'Report type { txt, html, pdf }', 'nargs' : 1 }
option_3 = { 'name' : ('-o', '--output'), 'help' : 'Output filename (default name: "application_package_name" in the current directory', 'nargs' : 1 }
option_4 = { 'name' : ('-L', '--log-level'), 'help' : 'Log level { DEBUG, INFO, WARN, ERROR, CRITICAL }', 'nargs' : 1 }
option_5 = { 'name' : ('-n', '--no-connection'), 'help' : 'Disable lookups on Google Play ', 'nargs' : 0 }

options = [option_0, option_1, option_2, option_3, option_4, option_5]


def main(options, arguments) :

			
	if (options.input != None) :
		
		# Log_Level
		if options.log_level != None :
			try :
				log.setLevel(options.log_level)
			except :
				parser.error("Please specify a valid log level")
		
		# Verbose
		if (options.verbose != None) and (options.verbose in VERBOSE_LEVEL) :
			verbosity = options.verbose
		else :
			parser.error("Please specify a valid verbose level")
		
		# Report Type	
		if (options.report != None) and (options.report in REPORT_TYPE) :
			report = options.report
		else :
			parser.error("Please specify a valid report type")

		# Online Lookups enabled	
		no_connection = {True : CONNECTION_DISABLED, False : CONNECTION_ENABLED}[options.no_connection != None] 

		# Input	
		APK_FILE = options.input
		
		# Output
		output = {True : options.output, False : ''}[options.output != None]
		
		
		a, d, x = AnalyzeAPK(APK_FILE)

		'''
		print detect_Telephony_SMS_abuse(x)
		print detect_Socket_use(x)

		print detect_Telephony_Operator_lookup(x)
		print detect_Telephony_CellID_lookup(x)
		print detect_Telephony_LAC_lookup(x)
		print detect_Telephony_MCCMNC_lookup(x)
		print detect_Telephony_phone_state_lookup(x)
		print detect_Telephony_DeviceID_lookup(x)
		print detect_Telephony_SimSerialNumber_lookup(x) 
		print detect_ContactAccess_lookup(x)
		print detect_Telephony_Phone_Call_abuse(x)
		print detect_Telephony_SMS_abuse(x)
		print detect_Telephony_SMS_read(x)
		print detect_WiFi_Credentials_lookup(x)
		print detect_UNIX_command_execution(x)
		print detect_Location_lookup(x)
		print detect_Library_loading(x)
		
		print detect_MediaRecorder_Video_capture(x)
		print detect_MediaRecorder_Voice_record(x)
		'''
		data = perform_analysis(APK_FILE, a, d, x, no_connection)
		dump_analysis_results(data)
		
		generate_report(data, verbosity, report, output)
		'''
		name, desc, icon = grab_application_name_description_icon("com.facebook.katana")
		print name, desc, icon
		'''
		#generate_report(icon,desc)
		
		# Machine to human transcription according to several category of information
		# Global_Evaluation, Manifest_info, Confidential_data, Leaked_data, Third-party_libs, Suspicious_functions = transcript_to_sentences ( database )
		# This allow the reading of the sqlite files, instead of storing the original APK
		
		# Filter on verbosity (user technical level)
		# HTML_info = Sentences_to_HTML_Report(Global_Evaluation, Manifest_info, Confidential_data, Leaked_data, Third-party_libs, Suspicious_functions)


if __name__ == "__main__" :
	parser = OptionParser()
	for option in options :
		param = option['name']
		del option['name']
		parser.add_option(*param, **option)

	options, arguments = parser.parse_args()
	#sys.argv[:] = arguments
	main(options, arguments)
