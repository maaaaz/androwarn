#!/usr/bin/env python
# -*- coding: utf-8 -*-

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
