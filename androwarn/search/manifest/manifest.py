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
from xml.dom import minidom

# Androwarn modules import
from androwarn.core.core import *
from androwarn.constants.api_constants import *
from androwarn.util.util import *

# Logguer
log = logging.getLogger('log')

def grab_main_activity(apk) :
	"""
	Return the name of the main activity
	"""
	return apk.get_main_activity()

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
	cert_info.append("SHA-1 thumbprint: %s" % cert.sha1Thumbprint())
	
	return cert_info
	
####################################
