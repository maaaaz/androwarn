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
import sys
import logging
import os
import time
import textwrap
import json
import codecs

# Jinja2 module import
try :
    from jinja2 import Environment, PackageLoader, FileSystemLoader, Template
except ImportError :
    sys.exit("[!] The Jinja2 module is not installed, please install it and try again")

# Logguer
log = logging.getLogger('log')

# Constants 
HTML_TEMPLATE_FILE = './template.html'
TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'report_template/')

# Constants
REPORT_TXT = 'txt'
REPORT_HTML = 'html'
REPORT_JSON = 'json'

# Data tab cleaner
def clean_list(list_to_clean,purge_list) :
    """
        @param list_to_clean : a list to be cleaned up
        @param purge_list : the list of elements to remove in the list
    
        @rtype : a cleaned list
    """
    if list_to_clean and purge_list :
        for i in reversed(purge_list) :
            del list_to_clean[i]

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
    if data:
        for item in data:
            for category, element_tuple in item.items():
                
                if isinstance(category, str):
                    flush_simple_string("[+] %s" % category.replace('_',' ').title(), file_descriptor)
                
                for name,content in element_tuple :
                    if content and isinstance(name, str):
                        flush_simple_string("\t[.] %s" % name.replace('_',' ').title().ljust(40), file_descriptor)
                        
                        for element in content:
                            if isinstance(element,str) or isinstance(element,unicode):
                                prefix = "\t\t - "
                                wrapper = textwrap.TextWrapper(initial_indent=prefix, width=200, subsequent_indent="\t\t   ")
                                flush_simple_string(wrapper.fill(element), file_descriptor)
                        
                        flush_simple_string("", file_descriptor)
                flush_simple_string("", file_descriptor)


def filter_analysis_results(data, verbosity) :
    
    # Analysis data levels (must match with the analysis module)
    data_level  = {
                    # Application
                     'application_name'                     : 1 ,
                     'application_version'                  : 1 ,
                     'package_name'                         : 1 ,
                     'description'                          : 1 ,
                    
                    
                    # Malicious Behaviours Detection
                    # -- Telephony identifiers leakage              
                     'telephony_identifiers_leakage'        : 1 ,
                    
                    # -- Device settings harvesting             
                     'device_settings_harvesting'           : 1 ,
                    
                    # -- Physical location lookup
                     'location_lookup'                      : 1 ,

                    # -- Connection interfaces information exfiltration
                     'connection_interfaces_exfiltration'   : 1 ,

                    # -- Telephony services abuse
                     'telephony_services_abuse'             : 1 ,
                    
                    # -- Audio/Video eavesdropping
                     'audio_video_eavesdropping'            : 1 ,
                    
                    # -- Suspicious connection establishment
                     'suspicious_connection_establishment'  : 1 ,

                    # -- PIM dataleakage
                     'PIM_data_leakage'                     : 1 ,
                    
                    # -- Native code execution
                     'code_execution'                       : 1 ,
                    
                    # APK 
                     'file_name'                            : 1 ,
                     'fingerprint'                          : 1 ,
                     'file_list'                            : 2 ,
                     'certificate_information'              : 2 ,
                    
                    
                    # Manifest
                     'main_activity'                        : 3 ,
                     'sdk_versions'                         : 3 ,
                     'activities'                           : 3 ,
                     'services'                             : 3 ,
                     'receivers'                            : 3 ,
                     'providers'                            : 3 ,
                     'permissions'                          : 1 ,
                     'features'                             : 2 ,
                     'libraries'                            : 2 ,
                    
                    
                    # APIs
                     'classes_list'                         : 3 ,
                     'internal_classes_list'                : 3 ,
                     'external_classes_list'                : 3 ,
                     'classes_hierarchy'                    : 3 ,
                     'intents_sent'                         : 3 
    }

    if data :
        purge_category = []
        
        for category_index, item in enumerate(data) :
            for category, element_tuple in item.items() :
                purge_tuple = []
                
                for tuple_index, tuple in enumerate(element_tuple) :
                    name, content = tuple
                    
                    # if the defined level for an item is above the user's chosen verbosity, remove it
                    if (name in data_level) and (int(data_level[name]) > int(verbosity)) :
                        purge_tuple.append(tuple_index)
                    
                    elif not(name in data_level) :
                        log.error("'%s' item has no defined level of verbosity", name)
                
                clean_list(element_tuple,purge_tuple)

            # if there's no item for a category, remove the entire category
            if not(element_tuple) :
                purge_category.append(category_index)
        
        clean_list(data,purge_category)
        
    return data

def generate_report_txt(data,verbosity, report, output_file) :
    """
        @param data : analysis result list
        @param verbosity : desired verbosity
        @param report : report type
        @param output_file : output file name
    """
    output, extension = os.path.splitext(output_file)
    output_file = output_file + ".txt" if ".txt" not in extension.lower() else output_file
    
    with open(output_file, 'w') as f_out:
        dump_analysis_results(data, f_out)
    f_out.close()
    
    print("[+] Analysis successfully completed and TXT file report available '%s'" % output_file)

def generate_report_json(data,verbosity, report, output_file) :
    """
        @param data : analysis result list
        @param verbosity : desired verbosity
        @param report : report type
        @param output_file : output file name
    """
    output, extension = os.path.splitext(output_file)
    output_file = output_file + ".json" if ".json" not in extension.lower() else output_file
    
    with open(output_file, 'w') as f_out:
        json.dump(data, f_out)
    f_out.close()
    
    print("[+] Analysis successfully completed and JSON file report available '%s'" % output_file)

def generate_report_html(data, verbosity, report, output_file) :
    """
        @param data : analysis result list
        @param verbosity : desired verbosity
        @param report : report type
        @param output_file : output file name
    """
    global HTML_TEMPLATE_FILE
    env = Environment(loader = FileSystemLoader(TEMPLATE_DIR), trim_blocks=False, newline_sequence='\n')
    template = env.get_template(HTML_TEMPLATE_FILE)
    
    output, extension = os.path.splitext(output_file)
    output_file = output_file + ".html" if ".html" not in extension.lower() else output_file
    
    template.stream(data=data).dump(output_file, encoding='utf-8')
    
    print("[+] Analysis successfully completed and HTML file report available '%s'" % output_file)

def generate_report(package_name, data, verbosity, report, output) :
    """
        @param data : analysis result list
        @param verbosity : desired verbosity
        @param report : report type
    """
    if (sys.version_info < (3, 0)):
        os_getcwd = os.getcwdu
    
    else:
        os_getcwd = os.getcwd
    
    output_file = os.path.join(os_getcwd(), package_name + "_%s" % str(int(time.time()))) if not(output) else output
    
    filter_analysis_results(data,verbosity)
    
    if report == REPORT_TXT:
        generate_report_txt(data,verbosity, report, output_file)
    
    if report == REPORT_HTML:
        generate_report_html(data,verbosity, report, output_file)
    
    if report == REPORT_JSON:
        generate_report_json(data,verbosity, report, output_file)