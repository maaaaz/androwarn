Androwarn
=========
Yet another static code analyzer for malicious Android applications
====================================================

Description
-----------
Androwarn is a tool whose main aim is to detect and warn the user about potential malicious behaviours developped by an Android application.

The detection is performed with the static analysis of the application's Dalvik bytecode, represented as Smali, with the [`androguard`](https://github.com/androguard/androguard) library.

This analysis leads to the generation of a report, according to a technical detail level chosen from the user.


Features
--------
* Structural and data flow analysis of the bytecode targeting different malicious behaviours categories
    + **Telephony identifiers exfiltration**: IMEI, IMSI, MCC, MNC, LAC, CID, operator's name...
    + **Device settings exfiltration**: software version, usage statistics, system settings, logs...
    + **Geolocation information leakage**: GPS/WiFi geolocation...
    + **Connection interfaces information exfiltration**: WiFi credentials, Bluetooth MAC adress...
    + **Telephony services abuse**: premium SMS sending, phone call composition...
    + **Audio/video flow interception**: call recording, video capture...
    + **Remote connection establishment**: socket open call, Bluetooth pairing, APN settings edit...
    + **PIM data leakage**: contacts, calendar, SMS, mails, clipboard...
    + **External memory operations**: file access on SD card...
    + **PIM data modification**: add/delete contacts, calendar events...
    + **Arbitrary code execution**: native code using JNI, UNIX command, privilege escalation...
    + **Denial of Service**: event notification deactivation, file deletion, process killing, virtual keyboard disable, terminal shutdown/reboot...


* Report generation according to several detail levels
    - Essential (`-v 1`) for newbies
    - Advanced (`-v 2`)
    - Expert (`-v 3`)

* Report generation according to several formats
    - Plaintext `txt`
    - Formatted `html` from a Bootstrap template
    - JSON


Usage
-----
### Options
```
usage: androwarn [-h] -i INPUT [-o OUTPUT] [-v {1,2,3}] [-r {txt,html,json}]
                 [-d]
                 [-L {debug,info,warn,error,critical,DEBUG,INFO,WARN,ERROR,CRITICAL}]
                 [-w]

version: 1.4

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        APK file to analyze
  -o OUTPUT, --output OUTPUT
                        Output report file (default
                        "./<apk_package_name>_<timestamp>.<report_type>")
  -v {1,2,3}, --verbose {1,2,3}
                        Verbosity level (ESSENTIAL 1, ADVANCED 2, EXPERT 3)
                        (default 1)
  -r {txt,html,json}, --report {txt,html,json}
                        Report type (default "html")
  -d, --display-report  Display analysis results to stdout
  -L {debug,info,warn,error,critical,DEBUG,INFO,WARN,ERROR,CRITICAL}, --log-level {debug,info,warn,error,critical,DEBUG,INFO,WARN,ERROR,CRITICAL}
                        Log level (default "ERROR")
  -w, --with-playstore-lookup
                        Enable online lookups on Google Play
```
  
### Common usage
```
$ python androwarn.py -i my_application_to_be_analyzed.apk -r html -v 3
```

By default, the report is generated in the current folder.  
An HTML report is now contained in a standalone file, CSS/JS resources are inlined.


Sample application
------------------
A sample application has been built, concentrating several malicious behaviours.

The APK is available in the `_SampleApplication/bin/` folder and the HTML report is available in the `_SampleReports` folder.


Dependencies and installation
-----------------------------
* Python 3 or Python 2.7 + androguard + jinja2 + play_scraper + argparse
* The **easiest way** to setup everything: `pip install androwarn` and then directly use `$ androwarn`
* Or git clone that repository and `pip install -r requirements.txt`


Changelog
---------
* version 1.6 - 2019/05/30: Python 3 support and few fixes
* version 1.5 - 2019/01/05: few fixes
* version 1.4 - 2019/01/04: code cleanup and use of the latest androguard version
* version 1.3 - 2018/12/30: few fixes
* version 1.2 - 2018/12/30: few fixes
* version 1.1 - 2018/12/29: fixing few bugs, removing Chilkat dependencies and pip packaging
* version 1.0 - from 2012 to 2013


Contributing
-------------
You're welcome, any help is appreciated :)


Contact
------
* Thomas Debize < tdebize at mail d0t com >
* Join #androwarn on Freenode

Copyright and license
---------------------
Androwarn is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

Androwarn is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 

See the GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License along with Androwarn.  
If not, see http://www.gnu.org/licenses/.


Greetings
-------------
* [Stéphane Coulondre](http://stephane.coulondre.info), for supervising my Final Year project
* [Anthony Desnos](https://sites.google.com/site/anthonydesnos/home), for his amazing [Androguard](https://github.com/androguard/androguard) project and his help through my Final Year project