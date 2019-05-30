#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of Androwarn.
#
# Copyright (C) 2012, 2019, Thomas Debize <tdebize at mail.com>
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
import codecs
import pprint

# Logguer
log = logging.getLogger('log')

def grab_main_activity(apk) :
    """
        @param apk : an APK instance
        
        @rtype : the name of the main activity
    """
    return apk.get_main_activity()

def grab_activities(apk) :
    """
        @param apk : an APK instance
    
        @rtype : the android:name attribute of all activities
    """
    return apk.get_activities()

def grab_services(apk) :
    """
        @param apk : an APK instance
        
        @rtype : the android:name attribute of all services
    """
    return apk.get_services()

def grab_receivers(apk) :
    """
        @param apk : an APK instance
    
        @rtype : the android:name attribute of all receivers
    """
    return apk.get_receivers()

def grab_providers(apk) :
    """
        @param apk : an APK instance
    
        @rtype : the android:name attribute of all providers
    """
    return apk.get_providers()

def grab_permissions(apk) :
    """
        @param apk : an APK instance
        
        @rtype : a list of permissions
    """
    '''
    result = ["Asked: %s" % "\n".join(sorted(apk.get_permissions())),
              "Implied: %s" % apk.get_uses_implied_permission_list(),
              "Declared: %s" % apk.get_declared_permissions()]
    '''
    result = ["Asked: %s" % pprint.pformat(sorted(apk.get_permissions())),
              "Implied: %s" % pprint.pformat(sorted(apk.get_uses_implied_permission_list())),
              "Declared: %s" % pprint.pformat(sorted(apk.get_declared_permissions()))]
              
    return result

def grab_features(apk) :
    """
        @param apk : an APK instance
    
        @rtype : a list of features
    """
    return list(apk.get_features())

def grab_libraries(apk) :
    """
        @param apk : an APK instance
    
        @rtype : the libraries' names
    """
    return list(apk.get_libraries())

def grab_file_list(apk) :
    """
        @param apk : an APK instance
        
        @rtype : the file list inside the AP
    """
    return apk.get_files()

def grab_certificate_information(apk) :
    """
        @param apk : an APK instance
        
        @rtype : a certificate object by giving the name in the apk file
    """
    
    cert_info = []
    
    cert_info.append("APK is signed: %s\n" % apk.is_signed())
    
    for index,cert in enumerate(apk.get_certificates()):
        cert_info.append("Certificate #%s" % index)
        cert_info_issuer = ["Issuer:", cert.issuer.human_friendly]
        cert_info_subject = ["Subject:", cert.subject.human_friendly]
        
        cert_info.extend(cert_info_issuer)
        cert_info.extend(cert_info_subject)
        
        cert_info.append("Serial number: %s" % cert.serial_number)
        cert_info.append("Hash algorithm: %s" % cert.hash_algo)
        cert_info.append("Signature algorithm: %s" % cert.signature_algo)
        cert_info.append("SHA-1 thumbprint: %s" % codecs.encode(cert.sha1, 'hex').decode())
        cert_info.append("SHA-256 thumbprint: %s" % codecs.encode(cert.sha256, 'hex').decode())
        cert_info.append("")
    
    return cert_info

def grab_sdk_versions(apk) :
    
    result = ["Declared target SDK: %s" % apk.get_target_sdk_version(),
              "Effective target SDK: %s" % apk.get_effective_target_sdk_version(),
              "Min SDK: %s" % apk.get_min_sdk_version(),
              "Max SDK: %s" % apk.get_max_sdk_version()]
    return result