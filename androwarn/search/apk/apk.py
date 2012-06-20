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
import os, re, logging, hashlib

# Androguard imports
from androguard.core.analysis import analysis
from androguard.core.bytecodes.apk import *

# Androwarn modules import
from androwarn.core.core import *
from androwarn.util.util import *

# Logguer
log = logging.getLogger('log')

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
	
def grab_file_list(apk) :
	"""
	Return the files inside the AP
	"""
	return apk.zip.namelist()
