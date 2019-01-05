#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of Androwarn.
#
# Copyright (C) 2012, 2019 Thomas Debize <tdebize at mail.com>
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
import os
import re
import logging
import argparse

# Androwarn modules import
from androguard.misc import AnalyzeAPK
from warn.search.search import grab_application_package_name
from warn.analysis.analysis import perform_analysis
from warn.report.report import generate_report

# Logger definition
log = logging.getLogger('log')
log.setLevel(logging.ERROR)
formatter = logging.Formatter('[%(levelname)s] %(message)s')
handler = logging.StreamHandler()
handler.setFormatter(formatter)
log.addHandler(handler)

# Script version
VERSION = '1.5'
print '[+] Androwarn version %s\n' % VERSION

# Options definition
parser = argparse.ArgumentParser(description="version: " + VERSION)

# Options definition
parser.add_argument('-i', '--input', help='APK file to analyze', required=True, type=str)
parser.add_argument('-o', '--output', help='Output report file (default "./<apk_package_name>_<timestamp>.<report_type>")', type=str)
parser.add_argument('-v', '--verbose', help='Verbosity level (ESSENTIAL 1, ADVANCED 2, EXPERT 3) (default 1)', type=int, choices=[1,2,3], default=1)
parser.add_argument('-r', '--report', help='Report type (default "html")', choices=['txt', 'html', 'json'], type=str, default='html')
parser.add_argument('-d', '--display-report', help='Display analysis results to stdout', action='store_true', default=False)
parser.add_argument('-L', '--log-level', help='Log level (default "ERROR")', type=str, choices=['debug','info','warn','error','critical','DEBUG', 'INFO','WARN','ERROR','CRITICAL'], default="ERROR")
parser.add_argument('-w', '--with-playstore-lookup', help='Enable online lookups on Google Play', action='store_true', default=False)

def main():
    global parser
    options = parser.parse_args()
    log.debug("[+] options: %s'" % options)
    
    # Log_Level
    try :
        log.setLevel(options.log_level.upper())
    except :
        parser.error("Please specify a valid log level")

    # Input
    print "[+] Loading the APK file..."
    a, d, x = AnalyzeAPK(options.input)
    package_name = grab_application_package_name(a)
    
    # Analysis
    data = perform_analysis(options.input, a, d, x, options.with_playstore_lookup)
    
    # Synthesis
    if options.display_report:
        # Brace yourself, a massive dump is coming
        dump_analysis_results(data,sys.stdout) 
    
    generate_report(package_name, data, options.verbose, options.report, options.output)

if __name__ == "__main__":
    main()