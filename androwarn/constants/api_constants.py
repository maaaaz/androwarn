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

# This file maps the integer values with the constant names for several android classes

MediaRecorder_AudioSource = {
								0x0: 'DEFAULT',
								0x1: 'MIC',
								0x2: 'VOICE_UPLINK',
								0x3: 'VOICE_DOWNLINK',
								0x4: 'VOICE_CALL',
								0x5: 'CAMCORDER',
								0x6: 'VOICE_RECOGNITION',
								0x7: 'VOICE_COMMUNICATION'
							}

MediaRecorder_VideoSource = {
								0x0: 'DEFAULT',
								0x1: 'CAMERA'
							}
