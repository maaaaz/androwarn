#!/usr/bin/env python
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

# Androwarn modules import
from warn.util.util import *

# Logguer
log = logging.getLogger('log')

def detect_ContactAccess_lookup(x) :
    """
        @param x : a Analysis instance
        
        @rtype : a list of formatted strings
    """
    formatted_str = []
    
    detectors = structural_analysis_search_field("Landroid/provider/ContactsContract$CommonDataKinds$Phone;", x)
    
    if detectors:
        formatted_str.append('This application reads or edits contact data')
        log_result_path_information(detectors)
        
    return formatted_str


def detect_Telephony_SMS_read(x) :
    """
        @param x : a Analysis instance
        
        @rtype : a list of formatted strings
    """
    formatted_str = []
    
    detectors = structural_analysis_search_string("content://sms/inbox", x)
    
    if detectors:
        formatted_str.append('This application reads the SMS inbox')
        log_result_path_information(detectors)
        
    return formatted_str


def gather_PIM_data_leakage(x) :
    """
        @param x : a Analysis instance
    
        @rtype : a list strings for the concerned category, for exemple [ 'This application makes phone calls', "This application sends an SMS message 'Premium SMS' to the '12345' phone number" ]
    """
    result = []
    
    result.extend( detect_ContactAccess_lookup(x) )
    result.extend( detect_Telephony_SMS_read(x) )
        
    return result
