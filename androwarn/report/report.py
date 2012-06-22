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
from jinja2 import Environment, PackageLoader, FileSystemLoader, Template

# Androwarn modules import
from androwarn.search.search import *
from androwarn.util.util import *

# Constants 
HTML_TEMPLATE_FILE = 'template.html'
OUTPUT_DIR = './Report/'

# Logguer
log = logging.getLogger('log')

# Constants
REPORT_TXT = 'txt'
REPORT_HTML = 'html'
REPORT_PDF = 'pdf'
REPORT_TYPE = [REPORT_TXT, REPORT_HTML, REPORT_PDF]

VERBOSE_ESSENTIAL = '1'
VERBOSE_ADVANCED = '2'
VERBOSE_EXPERT = '3'
VERBOSE_LEVEL = [VERBOSE_ESSENTIAL, VERBOSE_ADVANCED, VERBOSE_EXPERT]

# Analysis data levels (must match with the analysis module)
data_level  = [
				# Application
				{ 'application_package_name'				: 1 },
				{ 'application_name'						: 1 } ,
				{ 'application_description'					: 1 } ,
				
				# APK 
				{ 'apk_file_SHA1_hash'						: 1 },
				{ 'apk_file_name'							: 1 },
				{ 'file_list'								: 2 },
				
				# Manifest
				{ 'androidversion_code'						: 3 },
				{ 'androidversion_name'						: 2 },
				{ 'main_activity'							: 3 },
				{ 'activities'								: 3 },
				{ 'services'								: 3 },
				{ 'receivers'								: 3 },
				{ 'providers'								: 3 },
				{ 'permissions'								: 1 },
				{ 'features'								: 2 },
				{ 'libraries'								: 2 },
				{ 'certificate_information'					: 2 },
				
				# Malicious Behaviours Detection
				# -- Telephony identifiers leakage				
				{ 'telephony_identifiers_leakage'			: 1 },
				
				# -- Device settings harvesting				
				{ 'device_settings_harvesting'				: 1 },
				
				# -- Physical location lookup
				{ 'location_lookup'							: 1 },

				# -- Connection interfaces information exfiltration
				{ 'connection_interfaces_exfiltration'		: 1 },

				# -- Telephony services abuse
				{ 'telephony_services_abuse'				: 1 },
				
				# -- Audio/Video eavesdropping
				{ 'media_recorder_abuse'					: 1 },
				
				# -- Suspicious connection establishment
				{ 'suspicious_connection_establishment'		: 1 },

				# -- PIM dataleakage
				{ 'PIM_data_leakage'						: 1 },
				
				# -- Native code execution
				{ 'code_execution'							: 1 },

					
				# Code
				# -- Classes
				{ 'classes_list'							: 3 },
				{ 'internal_new_classes_list'				: 3 },
				{ 'external_classes_list'					: 3 },
				{ 'internal_packages_list'					: 3 },
				{ 'internal_new_packages_list'				: 3 },
				{ 'external_packages_list'					: 3 }

			  ]
			  
def w_list(list, file) :
	if list :
		for i in list :
			file.write("- %s\n" % i)

def w_title(string, file) :
	# Title it and replace underscores with spaces
	string = string.replace('_', ' ')
	string = ' '.join(word.capitalize() for word in string.split())
	file.write("[+] %s:\n" % string)

def w_simple_string(string, file) :
	file.write("%s\n" % string)
	
def generate_report_txt(data,verbosity, report, output_file) :
	with open(output_file, 'w') as f_out :
		w_simple_string("===== Androwarn Report =====", f_out)
		for item in data_level :
			key =  item.keys()[0]
			if (item[key] <= int(verbosity)) and (key in data) and (len(data[key]) > 0):
				w_title(key,f_out)
				w_list(data[key], f_out)
				w_simple_string('', f_out)
			
	f_out.close()


def generate_report_html(data, verbosity, report, output_file) :
	env = Environment( loader = FileSystemLoader(OUTPUT_DIR), trim_blocks=True, newline_sequence='\n')
	template = env.get_template(HTML_TEMPLATE_FILE)
	
	# In this case we are forced to dump the html into the Report folder as it contains css/img/ico
	output_file = "%s%s.html" % (OUTPUT_DIR, output_file.split('/')[-1])
	template.stream(data).dump(output_file, encoding='utf-8')

def generate_report(data, verbosity, report, output) :
	output_file = {True: data['application_package_name'][0] , False: output }[cmp(output, '') == 0]
	
	if cmp(report, REPORT_TXT) == 0 :
		generate_report_txt(data,verbosity, report, output_file)
	
	if cmp(report, REPORT_HTML) == 0 :
		generate_report_html(data,verbosity, report, output_file)
	
	if cmp(report, REPORT_PDF) == 0 :
		print "PDF Generation not implemented yet"
			

	
