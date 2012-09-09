Initial testing.

Requires:
  Nothing!

Tested on Debian 6
  cmake 2.8.2+dfsg.1-0+squeeze1

Building.
   mkdir ettercap-script-build
   cd ettercap-script-build/
   cmake -DENABLE_LUA=on -DCMAKE_INSTALL_PREFIX=/opt/ettercap -DCMAKE_BUILD_TYPE=Release -DENABLE_GTK=off ../ettercap-script 
   make
   sudo make install

Running
   sudo /opt/ettercap/bin/ettercap -i eth0 -T "/10.211.55.8//" 
   
   (I then run "curl http://icanhazip.com" on the targeted system)

---------

ettercap 0.7.5 copyright 2001-2012 Ettercap Development Team

Listening on:
  eth0 -> 00:1C:42:10:CD:45
          10.211.55.6/255.255.255.0
          fe80::21c:42ff:fe10:cd45/64
          fdb2:2c26:f4e4:0:21c:42ff:fe10:cd45/64

SSL dissection needs a valid 'redir_command_on' script in the etter.conf file
Privileges dropped to UID 65534 GID 65534...

plugin ec_sslstrip.so cannot be loaded...
  30 plugins
  40 protocol dissectors
  55 ports monitored
13861 mac vendor fingerprint
1766 tcp OS fingerprint
2183 known services

Randomizing 255 hosts for scanning...
Scanning the whole netmask for 255 hosts...
* |==================================================>| 100.00 %

3 hosts added to the hosts list...
Starting Unified sniffing...


Text only Interface activated...
Hit 'h' for inline help

Closing text interface...


Terminating ettercap...
Unified sniffing was stopped.

_mcleanup: gmon.out: Permission denied
mike@debian-6-x86-64:~$ sudo /opt/ettercap/bin/ettercap -i eth0 -T ///80

ettercap 0.7.5 copyright 2001-2012 Ettercap Development Team

Listening on:
  eth0 -> 00:1C:42:10:CD:45
          10.211.55.6/255.255.255.0
          fe80::21c:42ff:fe10:cd45/64
          fdb2:2c26:f4e4:0:21c:42ff:fe10:cd45/64

SSL dissection needs a valid 'redir_command_on' script in the etter.conf file
Privileges dropped to UID 65534 GID 65534...

plugin ec_sslstrip.so cannot be loaded...
  30 plugins
  40 protocol dissectors
  55 ports monitored
13861 mac vendor fingerprint
1766 tcp OS fingerprint
2183 known services
EC_LUA: plugin running...
LUA: We are inside ec_helpers.lua!
LUA: Defining a TCP packet hook...
1234LUA: hooked!
LUA: We are at the end of ec_helpers.lua. Though the script will now exit, ettercap will be able to callback into Lua through FFI!
EC_LUA: loaded ec_helpers.lua

Randomizing 255 hosts for scanning...
Scanning the whole netmask for 255 hosts...
* |==================================================>| 100.00 %

3 hosts added to the hosts list...
Starting Unified sniffing...


Text only Interface activated...
Hit 'h' for inline help


Packet visualization stopped...
I got the tcp!!!!!
I got the tcp!!!!!
I got the tcp!!!!!
I got the tcp!!!!!
I got the tcp!!!!!
I got the tcp!!!!!
LUA: Orig body length: 15
I got the tcp!!!!!
I got the tcp!!!!!
I got the tcp!!!!!
I got the tcp!!!!!
I got the tcp!!!!!
Closing text interface...


Terminating ettercap...
Unified sniffing was stopped.


------

And that's it.
