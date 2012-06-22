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


def log_result_path_information(res, res_prefix, res_type) :
	res_info = res.get_info()
	if len(res_info) > 0:
		for path in res.get_paths() :
			log.info("%s %s found '%s'\n\t=> %s %s %s %s " % (res_prefix, res_type, res_info, path.get_access_flag(), path.get_method().get_class_name(), path.get_method().get_name(), path.get_method().get_descriptor() ) )

class MLStripper(HTMLParser):
    def __init__(self):
        self.reset()
        self.fed = []
    def handle_data(self, d):
        self.fed.append(d)
    def get_data(self):
        return ''.join(self.fed)

def strip_HTML_tags(html):
	# Keep the indentation
	html = html.replace('<br>', '\n')
	
	# Remove HTML tags
	s = MLStripper()
	s.feed(html)
	
	return s.get_data()

def dump_analysis_results(data) :
	for i in data :
		print "[+] Item\t: '%s'" % i
		print "[+] Data\t: %s" % data[i]
		print "[+] Data type\t: %s" % type(data[i])
		print

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
