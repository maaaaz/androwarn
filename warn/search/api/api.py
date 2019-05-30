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
import re
import logging

# Androwarn modules import
from warn.core.core import *
from warn.util.util import *

# Logguer
log = logging.getLogger('log')

# Classes related functions #
def grab_classes_list(d, x) :
    """
        @param x : a Analysis instance
        
        @rtype : a list of the canonical name (ex "android.widget.GridView") of all the classes used
    """
    result = sorted(map(lambda i: convert_dex_to_canonical(i.get_vm_class().get_name()), x.get_classes()))
    #result.sort()
    return result

def grab_internal_classes_list(d, x) :
    """
        @param x : a Analysis instance
        
        @rtype : a list of the canonical name (ex "android.widget.GridView") of the internal classes used
    """
    
    result = sorted(map(lambda i: convert_dex_to_canonical(i.get_vm_class().get_name()), x.get_internal_classes()))
    #result.sort()
    return result

def grab_external_classes_list(d, x) :
    """
        @param x : a Analysis instance
        
        @rtype : a list of the canonical name (ex "android.widget.GridView") of the external packages used
    """
    result = sorted(map(lambda i: convert_dex_to_canonical(i.get_vm_class().get_name()), x.get_external_classes()))
    #result.sort()
    return result

def grab_classes_hierarchy(d, x):
    result = []
    for i in d:
        result = result + i.print_classes_hierarchy()
    
    return result

def grab_intents_sent(x) :
    """
        @param x : a Analysis instance
        
        @rtype : a list of formatted strings
    """
    formatted_str = []
    
    structural_analysis_results = structural_analysis_search_method("Landroid/content/Intent","<init>", x)
    
    for registers in data_flow_analysis(structural_analysis_results, x):
        if len(registers) >= 2 :
            intent_name = get_register_value(1, registers)

            local_formatted_str = "%s" % (intent_name)
            if not(local_formatted_str in formatted_str) :
                formatted_str.append(local_formatted_str)
    
    return sorted(formatted_str)