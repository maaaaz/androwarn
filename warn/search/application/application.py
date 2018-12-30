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
import re, logging, urllib2, hashlib
from urllib2 import urlopen, HTTPError

# Androguard imports
from guard.core.analysis import analysis
from guard.core.bytecodes.apk import *

# Androwarn modules import
from warn.core.core import *
from warn.util.util import *

# Play-scraper import
try :
    import play_scraper
except ImportError :
    sys.exit("[!] The play-scraper module is not installed, please install it and try again")

# Constants 
ERROR_APP_DESC_NOT_FOUND = 'N/A'

# Logguer
log = logging.getLogger('log')


# Some aliases to the original functions
def grab_application_package_name(apk) :
    """
        @param apk : an APK instance
        
        @rtype : the package name
    """
    return apk.package

def grab_application_name_description_icon(package_name, online_lookup) :
    """
        @param package_name : package name
    
        @rtype : (name, description, icon) string tuple
    """
    if not(online_lookup):
        return ERROR_APP_DESC_NOT_FOUND, ERROR_APP_DESC_NOT_FOUND, ERROR_APP_DESC_NOT_FOUND     
    try :
        
        app_details = play_scraper.details(package_name)
        if app_details:
            name = app_details['title'] if 'title' in app_details else ERROR_APP_DESC_NOT_FOUND
            desc = app_details['description'] if 'description' in app_details else ERROR_APP_DESC_NOT_FOUND
            icon_link = app_details['icon'] if 'icon' in app_details else ERROR_APP_DESC_NOT_FOUND
            
            return (name, desc, ERROR_APP_DESC_NOT_FOUND)
        
        else:
            log.warn("'%s' application's description and icon could not be found in the page" % str(package_name))
            return ERROR_APP_DESC_NOT_FOUND, ERROR_APP_DESC_NOT_FOUND, ERROR_APP_DESC_NOT_FOUND
    
    except ValueError:
        log.warn("'%s' application name does not exist on Google Play" % str(package_name))
        return ERROR_APP_DESC_NOT_FOUND, ERROR_APP_DESC_NOT_FOUND, ERROR_APP_DESC_NOT_FOUND

def grab_androidversion_code(apk) :
    """
        @param apk : an APK instance
        
        @rtype : the android version code
    """
    return apk.androidversion["Code"]

def grab_androidversion_name(apk) :
    """
        @param apk : an APK instance
        
        @rtype : the android version name 
    """
    return apk.androidversion["Name"]
