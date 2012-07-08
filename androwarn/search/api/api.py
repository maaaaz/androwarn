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

# Androguard imports
from androguard.core.analysis import analysis
from androguard.core.bytecodes.apk import *

# Androwarn modules import
from androwarn.core.core import *
from androwarn.util.util import *


# Logguer
log = logging.getLogger('log')


# Some aliases to the original functions

# Classes and Packages related functions #
# -- Classes -- #
def grab_classes_list(x) :
	"""
		@param x : a VMAnalysis instance
		
		@rtype : a list of the canonical name (ex "android.widget.GridView") of all the classes used
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
		@param x : a VMAnalysis instance
		
		@rtype : a list of the canonical name (ex "android.widget.GridView") of the internal classes used
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
		@param x : a VMAnalysis instance
		
		@rtype : a list of the canonical name (ex "android.widget.GridView") of the internal new classes used
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
		@param x : a VMAnalysis instance
		
		@rtype : a list of the canonical name (ex "android.widget.GridView") of the external packages used
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

# -- Packages -- #
def grab_packages_list(x) :
	"""
		@param x : a VMAnalysis instance
		
		@rtype : a list of the canonical name (ex "android.widget.GridView") of all the packages used
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
		@param x : a VMAnalysis instance
		
		@rtype : a list of the canonical name (ex "android.widget.GridView") of the internal classes used
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
		@param x : a VMAnalysis instance
		
		@rtype : a list of the canonical name (ex "android.widget.GridView") of the internal new classes used
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
		@param x : a VMAnalysis instance
	
		@rtype : a list of the canonical name (ex "android.widget.GridView") of the external packages used
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

	
		@rtype : a list of packages names
	"""
	l = []
	ex = re.compile( canonical_package_name )   
	l = filter(ex.search, canonical_package_list)
	
	return l
##########################################
