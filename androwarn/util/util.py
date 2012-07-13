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

# Androguard imports
from androguard.core.analysis import analysis
from androguard.core.bytecodes.apk import *

# Global imports
import re, logging
from HTMLParser import HTMLParser

# Logguer
log = logging.getLogger('log')

def convert_dex_to_canonical(dex_name) :
	"""
		@param dex_name : a dex name, for instance "Lcom/name/test"
	
		@rtype : a dotted string, for instance "com.name.test"
	"""
	final_name = ''
	if re.match( '^L[a-zA-Z]+(?:\/[a-zA-Z]+)*(.)*;$', dex_name) :
		global_part = dex_name[1:-1].split('/')
		final_part = global_part[:-1]
		last_part = global_part[-1].split('$')[0]
		final_part.append(str(last_part))
		final_name = '.'.join(str(i) for i in final_part)
	else :
		return "[!] Conversion to canonical name failed : \"" + dex_name + "\" is not a valid library dex name"
	return final_name

def detector_tab_is_not_empty(list) :
	"""
		@param list : a list of result
	
		@rtype : False if all the items in the list are empty, True otherwise
	"""
	for item in list :
		if not(not(item)) :
			return True
	return False

# Log extra information
def log_result_path_information(res, res_prefix, res_type) :
	"""
		@param res : a result from the detector's result list
		@param res_prefix : result's category name
		@param res_type : result's type
	
		@rtype : void - it only logs extra information about the analysis result
	"""
	res_info = res.get_info()
	if len(res_info) > 0:
		paths = res.get_paths()
		
		for path in res.get_paths() :
			access, idx = path[0]
			m_idx = path[1]
			log.info("%s %s found '%s'\n\t=> access_flag %s, index %s, method_index %s" % (res_prefix, res_type, res_info, access, idx, m_idx ) )

# HTML Sanitizer
class MLStripper(HTMLParser):
    def __init__(self):
        self.reset()
        self.fed = []
    def handle_data(self, d):
        self.fed.append(d)
    def get_data(self):
        return ''.join(self.fed)

def strip_HTML_tags(html):
	"""
		@param html : a string to be cleaned up
	
		@rtype : a HTML-tag sanitized string
	"""
	# Keep the indentation
	html = html.replace('<br>', '\n')
	
	# Remove HTML tags
	s = MLStripper()
	s.feed(html)
	
	return s.get_data()

# Dump
def flush_simple_string(string, file) :
	"""
		@param string : a unique string
		@param file : output file descriptor
	"""
	file.write("%s\n" % string)

def dump_analysis_results(data, file_descriptor) :
	"""
		@param data : analysis results list
		@param file_descriptor : dump output, file or sys.stdout
	
		@rtype : void - it only prints out the list
	"""
	# Watch out for encoding error while priting
	flush_simple_string("===== Androwarn Report =====", file_descriptor)
	if data :
		for item in data :
			for category, element_tuple in item.iteritems() :
				if isinstance(category,str) :
					flush_simple_string("[+] %s" % category.encode('ascii','ignore').replace('_',' ').title(), file_descriptor)
				for name,content in element_tuple :
					if content and isinstance(name,str) :
						flush_simple_string("\t[.] %s" % (name.encode('ascii','ignore').replace('_',' ').title().ljust(40)), file_descriptor)
						for element in content :
							if isinstance(element,str) :
								flush_simple_string("\t\t- %s" % element.encode('ascii','ignore').replace('_',' ').title(), file_descriptor)
						flush_simple_string("", file_descriptor)
				flush_simple_string("", file_descriptor)

# Classes harvesting
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
