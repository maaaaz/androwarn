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

# Androwarn modules import
from warn.core.core import *
from warn.util.util import *
from warn.constants.api_constants import *

# Logguer
log = logging.getLogger('log')

# -- Voice Record -- #
def detect_MediaRecorder_Voice_record(x) :
    """
        @param x : a Analysis instance
        
        @rtype : a list of formatted strings
    """ 
    formatted_str = []
    
    structural_analysis_results = structural_analysis_search_method("Landroid/media/MediaRecorder","setAudioSource", x)
    
    for registers in data_flow_analysis(structural_analysis_results, x):
        if registers:
            local_formatted_str = "This application records audio"
            try:
                audio_source_int    = int(get_register_value(1, registers))
                audio_source_name   = get_constants_name_from_value(MediaRecorder_AudioSource, audio_source_int)
                local_formatted_str = local_formatted_str + " from the '%s' source " % audio_source_name    
            except:
                pass
            
            if not(local_formatted_str in formatted_str) :
                    formatted_str.append(local_formatted_str)
                
    return sorted(formatted_str)

# -- Video Record -- #
def detect_MediaRecorder_Video_capture(x) :
    """
        @param x : a Analysis instance
        
        @rtype : a list of formatted strings
    """ 
    formatted_str = []
    
    structural_analysis_results = structural_analysis_search_method("Landroid/media/MediaRecorder","setVideoSource", x)
    
    for registers in data_flow_analysis(structural_analysis_results, x):
        if registers:
            local_formatted_str = "This application captures video"
            try:
                video_source_int    = int(get_register_value(1, registers)) # 1 is the index of the PARAMETER called in the method
                video_source_name   = get_constants_name_from_value(MediaRecorder_VideoSource, video_source_int)
            
                local_formatted_str = local_formatted_str + " from the '%s' source" % video_source_name
                
            except:
                pass
            
            if not(local_formatted_str in formatted_str) :
                    formatted_str.append(local_formatted_str)

    return sorted(formatted_str)

def gather_audio_video_eavesdropping(x) :
    """
        @param x : a Analysis instance
    
        @rtype : a list strings for the concerned category, for exemple [ 'This application makes phone calls', "This application sends an SMS message 'Premium SMS' to the '12345' phone number" ]
    """
    result = []
    
    result.extend ( detect_MediaRecorder_Voice_record(x) )
    result.extend ( detect_MediaRecorder_Video_capture(x) )
    
    return result
