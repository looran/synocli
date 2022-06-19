## Synology NAS file management from command-line

synocli is a command-line tool and Python API than interacts with a DSM7 based Synology device using the Web API:
* **download files with multiple threads** and automatic resume
* list files
* provide interactive python shell to query the APIs
* connection in direct using https://ip|fqdn:port of your device
* connection through **QuickConnect** using your QuickConnect ID
* does not require any service in addition to web interface access

![synocli demo: downloading files](doc/synocli_demo.gif)<br/>
_synocli demo: downloading files_

![Synology DSM7 Architecture and infrastructure](https://docs.google.com/drawings/d/e/2PACX-1vQd_4mqoAAbHgl8BaJM8FkwPZ9omRaxk7lN3ynpjuWvGZVb3FaJxl6km-R5Le4Pi9ejWBQhJqWUIzIs/pub?w=1900&h=1200)<br/>
_Synology DSM7 Architecture and infrastructure: DSM7 components mainly related to FileStation and QuickConnect infrastructure overview_

<ins>Use case for synocli</ins>: you have access to a Synology device as a simple user and no services like webdav / sftp are available

### synocli usage

```
usage: synocli.py [-h] [-k] [-l LOGIN] [-L] [-p PASSWORD] [-v]
                  [-z TEMPORISATION]
                  url_or_qcid {ls,get,interact} ...

Synology NAS file management from command-line
v0.1 - 2022, Laurent Ghigonis <ooookiwi@gmail.com>

positional arguments:
  url_or_qcid           DSM url as http[s]://ip|fqdn:port or QuickConnect ID
  {ls,get,interact}     action
    ls                  [-R] [<directory>] list directory or root
    get                 [-R] <path> [<out>] download file
    interact            interactive shell

optional arguments:
  -h, --help            show this help message and exit
  -k, --insecure        skip SSL certificate verification in all HTTPS connections
  -l LOGIN, --login LOGIN
  -L, --lan             enable connection to LAN IPs
  -p PASSWORD, --password PASSWORD
  -v, --verbose         verbose display, 2 for debug, 3 for debug http requests
  -z TEMPORISATION, --temporisation TEMPORISATION
                        temporisation, default=2

# list files through QuickConnect
synocli <quickconnect_id> list
# list files through QuickConnect, specifying login and password on the command-line
synocli -l admin -p 'MyPassword' <quickconnect_id> list
# list files through direct connection
synocli https://192.168.1.19:5001 list
# get file through QuickConnect
synocli <quickconnect_id> get /share1/document.pdf
# get all files recursively in a directory through QuickConnect
synocli <quickconnect_id> get -R /share1/my_directory
# start interactive mode
synocli <quickconnect_id> interact
```

### interactive mode

```
Interactive mode
^^^^^^^^^^^^^^^^
show this help
   synohelp
available functions
   syno.ls([path], recursive=False)
   syno.get(path, [outpath|-], recursive=False)
   syno.api_desktop_defs()
   syno.api_security()
   syno.api_info()
   syno.api_desktop_initdata_user_service()
   syno.api_package_status()
   syno.api_desktop_ui_configuration()
   syno.api_systeminfo_storage()
available objects
   syno.infos
change debug level
   logging.getLogger().setLevel(logging.DEBUG)
```

### synocli architecture

#### downloader (action 'get')

The downloader is multi-threaded and starts downloading files as soon as they are found by the recursive file listing.

You can specify the number of threads (-t), but the default of 2 should be good for all usages. Increasing the thread number will put higher pressure on disk IOs, potentialy decreasing performance.

When doing a recursive download (-R), synocli skip files that have same size and older or same modification time that the local files.

### Requirements

python3
```
requests
beautifulsoup4
tqdm
```

Install requirements using pip:
```
pip install -r requirements.txt
```

optional:
* ipython, if you you interactive mode (action 'interact')

### Similar projects and ressources

* synology-api - A Python wrapper around Synology API

from Renato (N4S4), allows to query many APIs of a Synology device from python

it does not support QuickConnect

https://github.com/N4S4/synology-api/

* qcon - Go library implementing the Synology QuickConnect protocol

https://github.com/jamesbo13/qcon

https://github.com/jamesbo13/qcon/blob/master/protocol.md

Found after creating synocli, maybe some of James analysis can help improve it.

* synoadm - customize Synology DSM devices

allows you to push custom SSL certificate for your Synology device, and set an htaccess on the web interface

https://github.com/looran/synoadm

* nas-download-manager - An open source browser extension for adding/managing download tasks to your Synology DiskStation.

https://github.com/seansfkelley/nas-download-manager

does not support quickconnect as per https://github.com/seansfkelley/nas-download-manager/issues/5


* vuln CVE-2020-27652, CVE-2020-27653 Synology SRM QuickConnect HTTP connection Information Disclosure Vulnerability (OCTOBER 29, 2020)

An exploitable information disclosure vulnerability exists in the QuickConnect HTTP connection functionality of Synology SRM 1.2.3 RT2600ac 8017-5. An attacker can impersonate the remote VPN endpoint in order to downgrade the HTTPS connection to HTTP, allowing an attacker to capture the web interface communication and in turn steal the session cookies. An attacker can perform a man-in-the-middle attack to trigger this vulnerability.

https://talosintelligence.com/vulnerability_reports/TALOS-2020-1061

* THURSDAY, OCTOBER 29, 2020 Vulnerability Spotlight: Multiple vulnerabilities in Synology SRM (Synology Router Manager)

https://blog.talosintelligence.com/2020/10/vulnerability-spotlight-multiple.html


