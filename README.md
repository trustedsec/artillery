Project Artillery - A project by Binary Defense Systems (https://www.binarydefense.com).

Binary Defense Systems (BDS) is a sister company of TrustedSec, LLC
=======
Artillery is a combination of a honeypot, monitoring tool, and alerting system. Eventually this will evolve into a hardening monitoring platform as well to detect insecure configurations from nix and windows systems. It's relatively simple, run ```./setup.py``` and hit yes, this will install Artillery in ```/var/artillery``` and edit your ```/etc/init.d/rc.local``` on linux to start artillery on boot up. On windows it will be installed to ```\Program Files (x86)\Artillery``` and a batch file is included for startup

### Features

1. It sets up multiple common ports that are attacked. If someone connects to these ports, it blacklists them forever (to remove blacklisted ip's, On Linux remove them from ```/var/artillery/banlist.txt```. On Windows remove them from```\Program Files (x86)\Artillery\banlist.txt```)

2. It monitors what folders you specify, by default it checks ```/var/www``` and ```/etc``` for modifications.(linux only)

3. It monitors the SSH logs and looks for brute force attempts.(linux only)

4. It will email you when attacks occur and let you know what the attack was.

Be sure to edit the ```/var/artillery/config```on Linux or ```\Program Files (x86)\Artillery\config``` on Windows to turn on mail delivery, brute force attempt customizations, and what folders to monitor.


### Bugs and enhancements

For bug reports or enhancements, please open an issue here https://github.com/BinaryDefense/artillery/issues

### Project structure

For those technical folks you can find all of the code in the following structure:

- ```Artillery.py``` - main program file
- ```restart_server.py``` - handles restarting software
- ```remove_ban.py``` - removes ips from banlist
- ```src/anti_dos.py``` - main monitoring module for Dos attacks
- ```src/apache_monitor.py`` - main monitoring module for Apache web service
- ```src/config.py``` - main module for configuration settings
- ```src/email_handler.py``` - main module for handling email
- ```src/events.py``` - main module for trigering events on windows systems
- ```src/ftp_monitor.py``` - main monitoring module for FTP bruteforcing
- ```src/globals.py``` - main module for holding global variables for use in artillery
- ```src/pyuac.py``` - main module for windows uac prompt
- ```src/core.py``` - main central code reuse for things shared between each module
- ```src/monitor.py``` - main monitoring module for changes to the filesystem
- ```src/ssh_monitor.py``` - main monitoring module for SSH brute forcing
- ```src/honeypot.py``` - main module for honeypot detection
- ```src/harden.py``` - check for basic hardening to the OS
- ```database/integrity.data``` - main database for maintaining sha512 hashes of filesystem
- ```setup.py``` - on linux copies files to ```/var/artillery/``` then edits ```/etc/init.d/artillery``` to ensure artillery                     starts per each reboot
                 - on windows copies files to ```\Program Files (x86)\Artillery\``` you have option to launch on install.(see below)

### Supported platforms

- Linux
- Windows

On windows to install pywin32 is needed.Install version that matches the version of python installed ex: 32/64 bit. Download files to location of your choice.open a cmd prompt browse to directory that files are located. To run type "python setup.py". You will be prompted for credentials if you are not an admin.  Artillery will be installed in ```"Program Files (x86)\Artillery```. After setup you have option to launch program. included is a batch file to launch once it is installed it is located in install directory.Console logging must be enabled in config.

Project Artillery - A project by Binary Defense Systems (https://www.binarydefense.com).

Binary Defense Systems (BDS) is a sister company of TrustedSec, LLC
