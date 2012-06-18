Androwarn : yet another static analyzer for Android applications
================================================================

Description
-----------
Androwarn is a tool whose main aim is to detect and warn the user about potential malicious behaviours developped by an Android application.

The detection is performed with the static analysis of the application's Dalvik bytecode, represented as Smali.

This analysis leads to the generation of a report, according to a technical detail level chosen from the user.


Features
--------
* Structural and data flow analysis of the bytecode aiming at different malicious behaviours categories
	- Telephony identifiers exfiltration : IMEI, IMSI, MCC, MNC, LAC, CID, operator's name...
	- Device settings exfiltration : software version, usage statistics, system settings, logs...
	- Geolocation information leakage : GPS/WiFi geolocation...
	- Connection interfaces information exfiltration: WiFi credentials, Bluetooth MAC adress...
	- Telephony services abyse : premium SMS sending, phone call composition...
	- Audio/video flow interception: call recording, video capture...
	- Remote connection establishment : socket open call, Bluetooth pairing, APN settings edit...
	- PIM data leakage : contacts, calendar, SMS, mails...
	- External memory operations : file access on SD card...
	- PIM data modification : add/delete contacts, calendar events...
	- Arbitrary code execution : native code using JNI, UNIX command, privilege escalation...
	- Denial of Service : event notification deactivation, file deletion, process killing, virtual keyboard disable, terminal shutdown/reboot...


* Report generation according to several detail levels
	- Essential (-v 1) for newbies
	- Intermediate (-v 2)
	- Expert (-v 3)

* Report generation according to several formats
	- plaintext (TXT)
	- formatted text (HTML) with a Bootstrap template


Usage
-----
python androwarn.py -i my_application_to_be_analyzed.apk -r html -v 3

(python androwarn.py -h to see full options)


Installation
------------
1. Take a look at the Dependencies chapter and setup what's needed
2. Open the androwarn.py file
3. Locate the `PATH_INSTALL = "/home/android/tools/androguard/"` instruction at line 11
4. Edit that line with the root path of your androguard environnement
5. Profit


Dependencies
------------
* Androguard : https://code.google.com/p/androguard/


Contributing
-------------
You're welcome, any help is appreciated :)


Author
------
* Thomas Debize <tdebize at mail.com>


Copyright and license
---------------------
Androwarn is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

Androwarn is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 

See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License along with Androwarn.  
If not, see http://www.gnu.org/licenses/.

Greetings
-------------
* Anthony Desnos, for his amazing Androguard project and his help through my entire Final-Year project
