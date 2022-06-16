#!/usr/bin/env python3

DESCRIPTION = """Synology NAS file management from command-line
v0.1 - 2022 Laurent Ghigonis <ooookiwi@gmail.com>"""

EXAMPLE_COMMANDLINE = """# list files through QuickConnect
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
"""

INTERACTIVE_MODE_HELP = """
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

running ipython..."""

README_MD = """
synocli is a command-line tool and Python API than interacts with a DSM7 based Synology device using the Web API:
* **download files with multiple threads** and automatic resume
* list files
* provide interactive python shell to query the APIs
* connection in direct using https://ip|fqdn:port of your device
* connection through **QuickConnect** using your QuickConnect ID
* does not require any service in addition to web interface access

![synocli demo: downloading files](doc/synocli_demo.gif)

![Synology DSM7 Architecture and infrastructure](doc/synology_dsm7_architecture_and_infrastructure.png)

### synocli usage

```
{USAGE}```

### interactive mode

```
{INTERACTIVE_MODE_HELP}
```

### synocli architecture

#### downloader (action 'get')

The downloader is multi-threaded and starts downloading files as soon as they are found by the recursive file listing.

You can specify the number of threads (-t), but the default of 2 should be good for all usages. Increasing the thread number will put higher pressure on disk IOs, potentialy decreasing performance.

When doing a recursive download (-R), synocli skip files that have same size and older or same modification time that the local files.

### Requirements

python3
```
{REQUIREMENTS}```

Install requirements using pip:
```
pip install -r requirements.txt
```

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
"""

SYNO_LOG = "synocli_%s_%s.log"

import re
import sys
import time
import json
import math
import atexit
import urllib
import random
import getpass
import logging
import binascii
import argparse
import threading
import concurrent.futures
from pathlib import Path
from pprint import pformat
from collections import defaultdict
from logging import debug, info, warning, error

import tqdm
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from bs4 import BeautifulSoup

def convert_size(size_bytes):
   if size_bytes == 0:
       return "0B"
   size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
   i = int(math.floor(math.log(size_bytes, 1024)))
   p = math.pow(1024, i)
   s = round(size_bytes / p, 2)
   return "%s %s" % (s, size_name[i])

class Syno_session(object):
    def __init__(self, sid, insecure):
        self.sid = sid
        self.insecure = insecure
        req = requests.Session()
        req.headers.update({
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36',
        })
        self.req = req
        self.synotoken = None

    def get(self, url, **kwargs):
        r = self.req.get(url, verify=not self.insecure, **kwargs)
        return self._req_debug(r)

    def post(self, url, **kwargs):
        r = self.req.post(url, verify=not self.insecure, **kwargs)
        return self._req_debug(r)

    def _req_debug(self, r):
        if logging.getLogger().getEffectiveLevel() == logging.DEBUG_HTTP:
            debug("""session %d: request
       url: %s
       method: %s
       headers: %s
       body: %s""" % (self.sid, r.request.url, r.request.method, r.request.headers, r.request.body))
            debug("""session %d: response
       headers: %s
       content len: %d""" % (self.sid, r.headers, len(r.content)))
        return r

class Syno(object):
    SITE_DEFAULTS = [ "global.quickconnect.to" ]
    PINGPONG_WORKERS = 10
    PINGPONG_TIMEOUT = 10
    TEMPORISATION_DEFAULT = 2
    DOWNLOAD_THREADS_DEFAULT = 2
    DOWNLOAD_QUEUE_LOW = 200
    DOWNLOAD_QUEUE_HIGH = 1500
    ERR_COUNT_LIMIT_DEFAULT = 10
    PATH_NAME_DISPLAY_MAX = 30

    def __init__(self, url_or_qcid, login, password, insecure=False, lan=False, temporisation=TEMPORISATION_DEFAULT, err_count_limit=ERR_COUNT_LIMIT_DEFAULT):
        self.login = login
        self.password = password
        self.insecure = insecure
        self.lan = lan
        self.temporisation = temporisation
        self.err_count_limit = err_count_limit
        self.infos = defaultdict(set)
        self.session = dict()
        session = Syno_session(0, self.insecure)
        self.session[0] = session
        if any(pattern in url_or_qcid for pattern in ["http://", "https://"]):
            self.dsmurl = url_or_qcid
            if url_or_qcid.find("quickconnect.to") > 0:
                self.qcid = re.match(r"http[s]?://(?P<qcid>[\w_-]+)\..*", url_or_qcid).group('qcid')
            else:
                self.qcid = ""
        else:
            self.qcid = url_or_qcid
            self.dsmurl = self._qc_get_dsmurl(session, self.qcid)
        self.dsmurl_entry = "%s/webapi/entry.cgi" % self.dsmurl
        self.dsmurl_query = "%s/webapi/query.cgi" % self.dsmurl
        self._login(session)
        info("gathered informations:\n%s" % '\n'.join([ "   %s: %s" % (k, ','.join([str(z) for z in v])) for k, v in self.infos.items() ]))

    def ls(self, directory=None, recursive=False):
        session = self.session[0]
        if directory[-1] == '/':
            # remove trailing slash, invalid for DSM
            directory = directory[:-1]
        s = ""
        dirs = list()
        if directory and directory != '/':
            ls = session.post(self.dsmurl_entry, data={
                'offset': 0,
                'limit': 1000,
                'sort_by': "name",
                'sort_direction': "ASC",
                'action': "list",
                'check_dir': True,
                'additional': '["real_path","size","owner","time","perm","type","mount_point_type","description","indexed"]',
                'filetype': "all",
                'folder_path': directory,
                'api': "SYNO.FileStation.List",
                'method': "list",
                'version': "2",
            })
            items = "files"
            s += "%s\n" % directory
        else:
            ls = session.post(self.dsmurl_entry, data={
                'filetype': "dir",
                'sort_by': "name",
                'check_dir': True,
                'additional': '["real_path","owner","time","perm","mount_point_type","sync_share","volume_status","indexed","hybrid_share"]',
                'enum_cluster': True,
                'node': "fm_root",
                'api': "SYNO.FileStation.List",
                'method': "list_share",
                'version': 2,
            })
            items = "shares"
            s += "shares\n"
        lsjson = ls.json()
        debug(pformat(lsjson))
        if not lsjson["success"]:
            warning("could not list files\nanswer json: %s" % pformat(lsjson))
            return
        for d in lsjson["data"][items]:
            a = d["additional"]
            t = "d" if d["isdir"] else " "
            t += "r" if a["perm"]["acl"]["read"] else "-"
            t += "w" if a["perm"]["acl"]["write"] else "-"
            t += "x" if a["perm"]["acl"]["exec"] else "-"
            t += "a" if a["perm"]["acl"]["append"] else "-"
            t += "d " if a["perm"]["acl"]["del"] else "- "
            t += "%-10s " % a["owner"]["user"]
            t += "%-10s " % a["owner"]["group"]
            if items == "files":
                t += "%-10d " % a["size"]
            t += "%-10d" % a["time"]["mtime"]
            s += "%s %s%s\n" % (t, d["name"], "/" if d["isdir"] else "")
            if d["isdir"]:
                dirs.append(d["path"])
        print(s)
        if recursive and len(dirs) > 0:
            for d in dirs:
                self.ls(d, recursive=True)
        return s

    def get(self, basepath, outpath=None, recursive=False, progress=True, download_threads=DOWNLOAD_THREADS_DEFAULT):
        session = self.session[0]
        # ensure path is a Path
        if type(basepath) is str:
            basepath = Path(basepath)
        # ensure outpath is a Path, except if stdout
        if outpath is None:
            outpath = Path('.').absolute()
        elif type(outpath) is str and outpath != '-':
            outpath = Path(outpath).absolute()
            if not outpath.exists():
                outpath.mkdir()

        downloader = concurrent.futures.ThreadPoolExecutor(max_workers=download_threads, thread_name_prefix='downloader')
        downloads = list()
        pending = list()
        try:
            for worker_id in range(1, download_threads+1):
                if worker_id not in self.session.keys():
                    info("[+] creating session for download thread %d" % worker_id)
                    s = Syno_session(worker_id, self.insecure)
                    self._login(s)
                    self.session[worker_id] = s
            if progress:
                # create progress bars
                ptotal = tqdm.tqdm(total=0, position=0, unit_scale=True, bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} err={postfix[0]} warn={postfix[1]} files={postfix[2]}/{postfix[3]}", postfix=[0, 0, 0, 0])
                self.progress_file = list()
                for worker_id in range(1, download_threads+1):
                    pfile = tqdm.tqdm(total=0, position=worker_id, unit_scale=True, bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}", desc="")
                    self.progress_file.append(pfile)
            stats = {
                'err_count': 0,
                'relogin_count': 0,
                'files_count': 0,
                'files_done': 0,
                'files_skip': 0,
                'dir_count': 0,
                'size_done': 0,
                'size_count': 0,
                'size_skip': 0,
            }
            tolist = [ basepath ]

            self._log_progress(progress, "[+] listing files and starting download")
            while len(downloads) > 0 or len(pending) > 0 or len(tolist) > 0:
                update_progress = False

                # list path in tolist queue if any
                if len(tolist) > 0:
                    update_progress = True
                    todo_path = tolist.pop(0)
                    ls = session.post(self.dsmurl_entry, data={
                        'offset': 0,
                        'limit': 1000,
                        'sort_by': "name",
                        'sort_direction': "ASC",
                        'action': "list",
                        'check_dir': True,
                        'additional': '["size","time"]',
                        'filetype': "all",
                        'folder_path': str(todo_path),
                        'api': "SYNO.FileStation.List",
                        'method': "list",
                        'version': "2",
                    })
                    lsjson = ls.json()

                    # building list of new files to download
                    todo_dl = list()
                    if lsjson["success"]:
                        # 'todo_path' is a directory
                        if todo_path == basepath:
                            # if initial target entry is a directory, create it localy and put all subfile/subdir in it
                            outpath = outpath / basepath.name
                            if not outpath.exists():
                                outpath.mkdir()
                        for d in lsjson["data"]["files"]:
                            path = Path(d["path"])
                            if d["isdir"]:
                                stats['dir_count'] += 1
                                relativepath = path.relative_to(basepath)
                                outdir = outpath / relativepath
                                if not outdir.exists():
                                    outdir.mkdir()
                                if recursive:
                                    tolist.append(path)
                                continue
                            todo_dl.append((path, d["additional"]["size"], d["additional"]["time"]["mtime"]))
                    else:
                        # 'todo_path' is file, only happens when we download a single file
                        todo_dl.append((todo_path, -1, -1))

                    # add files to the pending list
                    for todo_path, size, mtime in todo_dl:
                        stats['files_count'] += 1
                        stats['size_count'] += size
                        if outpath != '-':
                            relativepath = todo_path.parent.relative_to(basepath)
                            outdir = outpath / relativepath
                            if outdir.exists():
                                outfile = outdir / todo_path.name
                                if outfile.exists():
                                    debug("file already exists: %s" % todo_path)
                                    stat = outfile.stat()
                                    debug("size %d localsize %d" % (size, stat.st_size))
                                    debug("mtime %d localmtime %d" % (mtime, stat.st_mtime))
                                    if stat.st_size == size and stat.st_mtime >= mtime:
                                        debug("skipping file")
                                        stats['files_skip'] += 1
                                        stats['size_skip'] += size
                                        continue
                            outfile = outdir / todo_path.name
                        pending.append((self._dl_thread, todo_path, outfile, size, progress))

                    if len(tolist) == 0:
                        # no more path in ls queue
                        self._log_progress(progress, "done listing files, found %d files and %d directories" % (stats["files_count"], stats["dir_count"]))

                # look for finished downloads
                remaining_downloads = list()
                for dl in downloads:
                    if not dl.done():
                        remaining_downloads.append(dl)
                        continue
                    update_progress = True
                    path, outfile, size, worker_id, error = dl.result()
                    if error:
                        # XXX we are not detecting properly exceptions from downloader
                        # XXX "short read: 38" is detected properly
                        if ( (type(error) is requests.exceptions.HTTPError and error.response.status_code == 502)
                                or (error == "short read: 38") ):
                            warning("HTTP error 502 while downloading or short read with size 38, performing log-in again for downloader %d path %s:\n%s" % (worker_id, path, error))
                            stats['relogin_count'] += 1
                            time.sleep(self.temporisation)
                            s = self.session[worker_id]
                            self._logout(s)
                            self._login(s)
                            downloads.append(downloader.submit(self._dl_thread, path, outfile, size, progress))
                        else:
                            warning("unknown error reported by downloader %d while downloading %s:\n%s" % (worker_id, path, error))
                            stats['err_count'] += 1
                        if self.err_count_limit > 0 and stats['err_count'] >= self.err_count_limit:
                            self.err("too many errors encountered while downloading (%d), exiting" % stats['err_count'])
                    else:
                        stats['size_done'] += size
                        stats['files_done'] += 1
                downloads = remaining_downloads

                # start downloads
                if len(pending) > 0 and len(downloads) < self.DOWNLOAD_QUEUE_LOW:
                    # fill 'downloads' by taking up-to DOWNLOAD_QUEUE_HIGH items from 'pending'
                    item_count = min(self.DOWNLOAD_QUEUE_HIGH - len(downloads), len(pending))
                    debug("queuing %d new downloads" % item_count)
                    item_start = len(pending) - item_count
                    for item in pending[item_start:]:
                        downloads.append(downloader.submit(*item))
                    pending = pending[:item_start]

                # update total progress bar
                if progress and update_progress:
                    ptotal.total = stats['size_count']
                    ptotal.n = stats['size_done'] + stats['size_skip']
                    ptotal.postfix = [stats['err_count'], stats['relogin_count'], stats['files_done']+stats['files_skip'], stats['files_count']]
                    ptotal.refresh()

                time.sleep(0.1)
            
        except KeyboardInterrupt:
            warning("catched ctrl-c, exiting")
            downloader.shutdown(wait=False, cancel_futures=True)
            self.close()

        if progress:
            ptotal.close()
            for pfile in self.progress_file:
                pfile.close()

    def err(self, msg):
        self.close()
        logging.error(msg)
        exit(1)

    def close(self):
        for session in self.session.values():
            self._logout(session)

    def _login(self, session):
        info("[+] login: getting main portal %s" % self.dsmurl)
        self.apis_v = dict()

        # getting home page
        session.req.headers.update({
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'same-site',
            'upgrade-insecure-requests': '1',
        })
        if self.qcid:
            session.req.headers.update({
                'referer': 'https://%s.quickconnect.to/' % self.qcid,
            })
        r = session.get(self.dsmurl)
        s = BeautifulSoup(r.text, 'html.parser')
        debug(s.prettify())

        # reading API 'v' from scripts links
        get_security = False
        for script in s.find_all("script"):
            url = urllib.parse.urlparse(script.attrs['src'])
            if url.path == 'webapi/entry.cgi':
                query = urllib.parse.parse_qs(url.query)
                if 'api' in query:
                    self.apis_v[query['api'][0]] = query['v'][0]
            if url.path == 'webman/security.cgi':
                get_security = True
        debug("parsed APIs 'v' values: %s" % self.apis_v)
        
        # get desktop SessionData
        session.req.headers.update({
            'referer': self.dsmurl,
        })
        js_desktop_session = session.get(self.dsmurl_entry, params={
            'api': "SYNO.Core.Desktop.SessionData",
            'version': 1,
            'method': "getjs",
            'SynoToken': "",
            'v': self.apis_v["SYNO.Core.Desktop.SessionData"],
        })
        debug(js_desktop_session.content)
        json_start = js_desktop_session.content.find(b"SYNO.SDS.Session = {") + 19
        json_end = js_desktop_session.content.rfind(b'}') + 1
        desktop_session = json.loads(js_desktop_session.content[json_start:json_end])
        debug(desktop_session)
        self.infos["hostname"].add(desktop_session["hostname"])
        if "custom_login_title" in desktop_session and len(desktop_session["custom_login_title"]) > 0:
            self.infos["custom_login_title"].add(desktop_session["custom_login_title"])
        if "login_welcome_msg" in desktop_session and len(desktop_session["login_welcome_msg"]) > 0:
            self.infos["login_welcome_msg"].add(desktop_session["login_welcome_msg"])
        if "login_welcome_title" in desktop_session and len(desktop_session["login_welcome_title"]) > 0:
            self.infos["login_welcome_title"].add(desktop_session["login_welcome_title"])
        if "login_footer_msg" in desktop_session and len(desktop_session["login_footer_msg"]) > 0:
            self.infos["login_footer_msg"].add(desktop_session["login_footer_msg"])
        self.infos["version"].add(desktop_session["fullversion"])
        # 1653051291 = 6.2
        # 1420070513 = 6.2
        # 1653468594 = 7
        # 1655138411 = 7 (local)
        self.infos["fullversion"].add(desktop_session["version"])
        v7 = False
        if "is_secure" in desktop_session:
            v7 = True
        self.infos["detected_dsmv7"].add(v7)
        self.infos["public_access"].add(desktop_session["public_access"])
        if len(desktop_session["sso_server"]) > 0:
            self.infos["sso_server"].add(desktop_session["sso_server"])
        self.infos["lang"].add(desktop_session["lang"])
        self.infos["configured"].add(desktop_session["configured"])

        if get_security:
            debug(self.api_security(session))
        debug(self.api_info(session))

        info("[+] login: sending username")
        if self.temporisation > 0:
            time.sleep(random.random() * self.temporisation)
        auth_type = session.post(self.dsmurl_entry, data={
            'api': 'SYNO.API.Auth.Type',
            'method': 'get',
            'version': 1,
            'account': self.login,
        })
        debug(auth_type.content)
        data = auth_type.json()['data']
        if len(data) == 3 and data[1]['type'] == "authenticator" and data[2]['type'] == 'fido':
            warning("login probably does not exist, or uses special authenticator / FIDO")

        info("[+] login: sending password")
        if self.temporisation > 0:
            time.sleep(random.random() * self.temporisation)
        tabid = random.randint(1, 65536)
        auth = session.post(self.dsmurl_entry, data={
            'api': "SYNO.API.Auth",
            'version': 7,
            'method': "login",
            'session': "webui",
            'tabid': tabid,
            'enable_syno_token': "yes",
            # login works without noise ik_message on DSM 7.0
            #'ik_message': "",
            'account': self.login,
            'passwd': self.password,
            'logintype': "local",
            'otp_code': '',
            'enable_device_token': "no",
            'rememberme': 0,
            'timezone': "+04:00",
            'client': "browser",
        })
        debug(auth.content)
        authjson = auth.json()
        if not authjson["success"]:
            self.err("login failed\nanswer json: %s" % authjson)
        session.synotoken = authjson['data']['synotoken']
        session.req.headers.update({
            'x-syno-token': session.synotoken
        })

        info("login success")

        return session

    def api_desktop_defs(self, session=None):
        if not session:
            session = self.session[0]
        js_desktop_defs = session.get(self.dsmurl_entry, params={
            'api': "SYNO.Core.Desktop.Defs",
            'version': 1,
            'method': "getjs",
            'v': self.apis_v["SYNO.Core.Desktop.Defs"],
        })
        return js_desktop_defs.content

    def api_security(self, session=None):
        if not session:
            session = self.session[0]
        js_security = session.get("%s/webman/security.cgi" % self.dsmurl)
        return js_security.content

    def api_info(self, session=None):
        if not session:
            session = self.session[0]
        query_info = session.post(self.dsmurl_query, data={
            'query': 'all',
            'api': "SYNO.API.Info",
            'method': 'query',
            'version': 1,
        })
        return query_info.content

    def api_desktop_initdata_user_service(self, session=None):
        if not session:
            session = self.session[0]
        user_service = session.get(self.dsmurl_entry, params={
            # Initdata get_user_service works without _dc on DSM7.0
            #'_dc': 1655140475682, # timestamp
            'SynoToken': session.synotoken,
            'launch_app': "null",
            'api': "SYNO.Core.Desktop.Initdata",
            'method': "get_user_service",
            'version': 1,
        })
        return user_service.json()

    def api_package_status(self, session=None):
        if not session:
            session = self.session[0]
        package = session.post(self.dsmurl_entry, data={
            'additional': '["status_sketch","dsm_apps"]',
            'api': 'SYNO.Core.Package',
            'method': 'list',
            'version': 2,
        })
        return package.json()

    def api_desktop_ui_configuration(self, session=None):
        if not session:
            session = self.session[0]
        ui_config = session.get(self.dsmurl_entry, params={
            'lang': "enu",
            'debug': 'null',
            'launch_app': 'null',
            'api': "SYNO.Core.Desktop.Initdata",
            'method': "get_ui_config",
            'version': 1,
            'SynoToken': session.synotoken,
        })
        return ui_config.json()
    
    def api_systeminfo_storage(self, session=None):
        if not session:
            session = self.session[0]
        storage = session.get("%s/%s" % (self.dsmurl, "/webman/modules/SystemInfoApp/SystemInfo.cgi"), params={
            'query': "storage",
        })
        return storage.json()

    def _dl_thread(self, path, outfile, size, progress):
        self._log_progress(progress, "downloading %s (%d)" % (path, size))
        pathhex = binascii.b2a_hex(str(path).encode())
        error = None
        worker_id = int(threading.current_thread().name.split('_')[1])
        session = self.session[worker_id]
        if progress:
            pfile = self.progress_file[worker_id]
        try:
            # http request
            with session.req.get("%s/fbdownload/%s" % (self.dsmurl, path.name), stream=True, verify=not self.insecure, params={
                        'dlink': pathhex,
                        'noCache': int(time.time()),
                        'mode': "download",
                        'stdhtml': "false",
                        'SynoToken': session.synotoken,
                        # SynoHash is not mandatory
                        #'SynoHash': "",
                    }) as dl:
                dl.raise_for_status()
                if progress:
                    path_name = path.name
                    if len(path_name) > self.PATH_NAME_DISPLAY_MAX:
                        path_name = "%s...%s" % (path_name[:self.PATH_NAME_DISPLAY_MAX-6], path_name[len(path_name)-6:])
                    pfile.total = size
                    pfile.n = 0
                    pfile.desc = path_name
                    pfile.refresh()
                if outfile == '-':
                    outfile = sys.stdout
                else:
                    # write file chunks
                    f = open(outfile, 'wb')
                    current_size = 0
                    bar_step = 0
                    for chunk in dl.iter_content(chunk_size=8192): 
                        f.write(chunk)
                        len_chunk = len(chunk)
                        current_size += len_chunk
                        if progress:
                            # update file progress bar
                            if current_size > (size / 100) * bar_step or current_size == size:
                                bar_step += 1
                                pfile.n = current_size
                                pfile.refresh()
                if current_size != size:
                    warning("downloader %d: downloaded %d bytes, different than file size %d while downloading file %s" % (worker_id, current_size, size, path))
                    error = "short read: %d" % current_size
                if outfile != '-':
                    f.close()
                    debug("downloader %d: created file %s" % (worker_id, outfile))
        except Exception as e:
            warning("Exception in downloader %d while downloading file %s:\n%s" % (worker_id, path, e))
            error = e
        return path, outfile, size, worker_id, error

    def _log_progress(self, progress, msg):
        if progress and logging.getLogger().getEffectiveLevel() <= logging.INFO:
            tqdm.tqdm.write(msg)
        else:
            info(msg)

    def _logout(self, session):
        debug("logout")
        auth = session.post(self.dsmurl_entry, data={
            'api': "SYNO.API.Auth",
            'version': 7,
            'method': "logout",
        })
        debug(auth.content)

    def _qc_get_dsmurl(self, session, qcid):
        info("[+] fetching main qc page")
        session.get("https://%s.quickconnect.to/" % qcid)

        headers = {
            'origin': 'https://%s.quickconnect.to' % qcid,
            'referer': 'https://%s.quickconnect.to/' % qcid,
            'accept': 'application/json, text/javascript, */*; q=0.01',
            'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
        }
        qc_serv_req_json = [{
            "version": 1,
            "command": "get_server_info",
            "stop_when_error": False,
            "stop_when_success": False,
            "id": "dsm_portal_https",
            "serverID": qcid,
            "is_gofile": False,
        }, {
            "version": 1,
            "command": "get_server_info",
            "stop_when_error": False,
            "stop_when_success": False,
            "id": "dsm_portal",
            "serverID": qcid,
            "is_gofile": False,
        }]

        sites = self.SITE_DEFAULTS
        target_hosts = set()
        relays_url = set()
        while len(sites) > 0:
            site = sites.pop(0)
            info("[+] get server info from site %s" % site)
            r = session.post("https://%s/Serv.php" % site, json=qc_serv_req_json, headers=headers)
            try:
                json = r.json()
            except Exception as e:
                self.err("could not parse JSON answer from site %s: %s\nanswer content: %s" % (site, e, r.content))
            debug(json)
            if len(json) != 2:
                self.err("no 2 components in returned JSON from site %s\naswer content: %s" % (site, r.content))

            for idx, proto in zip([0, 1], ["https", "http"]): # [dsm_portal_https, dsm_portal]
                if json[idx]["errno"] == 0:
                    # check JSON content
                    if not set(["server","service"]) <= set(json[idx].keys()):
                        self.err("returned JSON from site %s is missing components\nanswer content: %s" % (site, r.content))
                    if json[idx]["server"]["ds_state"] != "CONNECTED":
                        warning("Ds is not CONNECTED ! skipping. told by site %s\nanswer content: %s" % (site, r.content))
                        continue
                    if "pingpong" not in json[idx]["service"]:
                        warning("pingpong is not advertised for the target ! continuing anyway. told by site %s\nanswer content: %s" % (site, r.content))
                    if json[idx]["service"]["pingpong"] != "CONNECTED":
                        warning("pingpong is not CONNECTED ! continuing anyway. told by site %s\nanswer content: %s" % (site, r.content))

                    # get pingpong hosts list
                    service_port = json[idx]["service"]["port"]
                    ext_port = json[idx]["service"]["port"]
                    if "smartdns" in json[idx]:
                        target_hosts.update([
                            (proto, json[idx]["smartdns"]["host"].lower(), service_port),
                            (proto, json[idx]["smartdns"]["host"].lower(), ext_port),
                            (proto, json[idx]["smartdns"]["external"], service_port),
                            (proto, json[idx]["smartdns"]["external"], ext_port),
                            (proto, json[idx]["smartdns"]["externalv6"], ext_port),
                            (proto, json[idx]["smartdns"]["externalv6"], service_port),
                        ])
                        if self.lan and "lan" in json[idx]["smartdns"] and len(json[idx]["smartdns"]["lan"]) > 0:
                            target_hosts.add((proto, json[idx]["smartdns"]["lan"][0], service_port))
                        if self.lan and "lanv6" in json[idx]["smartdns"] and len(json[idx]["smartdns"]["lanv6"]) > 0:
                            target_hosts.add((proto, json[idx]["smartdns"]["lanv6"][0], service_port))
                    if "ddns" in json[idx]["server"] and json[idx]["server"]["ddns"] != "NULL":
                        target_hosts.add((proto, json[idx]["server"]["ddns"], service_port))
                        target_hosts.add((proto, json[idx]["server"]["ddns"], ext_port))
                    if "fqdn" in json[idx]["server"] and json[idx]["server"]["fqdn"] != "NULL":
                        target_hosts.add((proto, json[idx]["server"]["fqdn"], service_port))
                        target_hosts.add((proto, json[idx]["server"]["fqdn"], ext_port))
                    relays_url.add("https://%s.%s.quickconnect.to" % (qcid, json[idx]['env']["relay_region"]))

                    # save gathered informations
                    self.infos["control_host"].add(json[idx]['env']["control_host"])
                    self.infos["relay_region"].add(json[idx]['env']["relay_region"])
                    self.infos["server_external_ip"].add(json[idx]["server"]["external"]["ip"])
                    self.infos["server_gateway"].add(json[idx]["server"]["gateway"])
                    if len(json[idx]["server"]["interface"]) > 0:
                        self.infos["server_interface_ip"].add(json[idx]["server"]["interface"][0]["ip"])
                        if len(json[idx]["server"]["interface"][0]["ipv6"]) > 0:
                            self.infos["server_interface_ipv6"].add(json[idx]["server"]["interface"][0]["ipv6"][0]["address"])
                            self.infos["server_interface_ipv6_prefix"].add(json[idx]["server"]["interface"][0]["ipv6"][0]["prefix_length"])
                        self.infos["server_interface_mask"].add(json[idx]["server"]["interface"][0]["mask"])
                        self.infos["server_interface_name"].add(json[idx]["server"]["interface"][0]["name"])
                    break

                elif json[idx]["errno"] == 4 and json[idx]["suberrno"] == 2:
                    # ask another control host
                    sites.extend(set(json[0]["sites"]) - set(sites))

                else:
                    self.err("unknown error return by site %s: errno=%s suberrno=%s\nanswer content: %s" % (site, json[idx]["errno"], json[idx]["suberrno"], r.content))

        info("[+] starting pingpong")
        debug(pformat(target_hosts))

        def req_pingpong(host):
            pingpong_url = "%s://%s:%d/%s" % (host[0], host[1], host[2], json[idx]["server"]["pingpong_path"])
            ans = session.get(pingpong_url, timeout=self.PINGPONG_TIMEOUT)
            return (ans.status_code, ans.json())
        pingpong_ok = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.PINGPONG_WORKERS) as executor:
            futures = { executor.submit(req_pingpong, host): host for host in target_hosts }
            for future in concurrent.futures.as_completed(futures):
                host = futures[future]
                host_url = "%s://%s:%d" % (host[0], host[1], host[2])
                try:
                    res = future.result()
                    pingpong_ok.append((host_url, res))
                    self.infos["hosts_pingpong"].add("%s: %s,%s,%s" % (host_url, res[0], res[1]["success"], res[1]["ezid"]))
                except Exception as exc:
                    self.infos["hosts_pingpong"].add("%s: %s" % (host_url, type(exc).__name__))

        if len(pingpong_ok) > 0:
            info("[+] testing timing connection to DSM portal")
            debug(pformat(pingpong_ok))

            urls_timing = list()
            for host_url, res in pingpong_ok:
                info("using %s" % host_url)
                time1 = time.time()
                r = session.get(host_url)
                delta = time.time() - time1
                urls_timing.append((host_url, delta))
                self.infos["hosts_portal_timing"].add("%s: %s" % (host_url, delta))

            urls_timing.sort(key=lambda x: x[1])
            debug("urls_timing: %s" % urls_timing)

            best_url, best_timing = urls_timing[0]
            info("best portal is %s, fetched is %ss" % (best_url, best_timing))
        else:
            info("no working direct connection, using relay: %s" % relays_url)
        best_url = relays_url.pop()

        return best_url

syno = None
def _at_exit():
    info("closing sessions")
    syno.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=DESCRIPTION, epilog=EXAMPLE_COMMANDLINE, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-k', '--insecure', action='store_true', help='skip SSL certificate verification in all HTTPS connections')
    parser.add_argument('-l', '--login', help='')
    parser.add_argument('-L', '--lan', action='store_true', help='enable connection to LAN IPs')
    parser.add_argument('-p', '--password', help='')
    parser.add_argument('-v', '--verbose', action='count', default=0, help='verbose display, 2 for debug, 3 for debug http requests')
    parser.add_argument('-z', '--temporisation', type=int, default=Syno.TEMPORISATION_DEFAULT, help='temporisation, default=%d' % Syno.TEMPORISATION_DEFAULT)
    parser.add_argument('url_or_qcid', help='DSM url as http[s]://ip|fqdn:port or QuickConnect ID')
    subparsers = parser.add_subparsers(dest='action', required=True, help='action')
    
    subp = subparsers.add_parser('ls', help='[-R] [<directory>] list directory or root')
    subp.add_argument('-R', '--recursive', action='store_true', help='recursive')
    subp.add_argument('directory', nargs='?', default='/', help='directory to list')

    subp = subparsers.add_parser('get', help='[-R] <path> [<out>] download file')
    subp.add_argument('-P', '--no-progress', action='store_true', help='don\'t show progress bar')
    subp.add_argument('-t', '--threads', type=int, default=Syno.DOWNLOAD_THREADS_DEFAULT, help='number of threads, default=%d' % Syno.DOWNLOAD_THREADS_DEFAULT)
    subp.add_argument('-R', '--recursive', action='store_true', help='recursive')
    subp.add_argument('path', help='file path')
    subp.add_argument('out', nargs='?', help='local file name or \'-\'')

    subp = subparsers.add_parser('interact', help='interactive shell')

    args = parser.parse_args()

    # setup logging
    logging.DEBUG_HTTP = 5
    #logging.addLevelName(logging.DEBUG_HTTP, "DEBUG_HTTP")
    class Formatter(logging.Formatter):
        def format(self, record):
            if record.levelno == logging.INFO:
                self._style._fmt = "%(message)s"
            else:
                self._style._fmt = "%(levelname)s %(module)s: %(message)s"
            return super().format(record)
    syno_log = SYNO_LOG % (time.strftime("%Y%m%d_%H%M%S"), args.action)
    handler_file = logging.FileHandler(syno_log, mode='a')
    handler_file.setFormatter(Formatter())
    handler_console = logging.StreamHandler()
    handler_console.setFormatter(Formatter())
    loglevel = logging.WARNING
    if args.verbose == 1:
        loglevel = logging.INFO
    elif args.verbose == 2:
        loglevel = logging.DEBUG
    elif args.verbose >= 3:
        loglevel = logging.DEBUG_HTTP
    logging.basicConfig(level=loglevel, handlers=[handler_file, handler_console])
    print("logging to %s" % syno_log)

    # read login and password
    login = args.login
    if not login:
        login = input("%s login: " % args.url_or_qcid)
    password = args.password
    if not password:
        password = getpass.getpass("%s password: " % args.url_or_qcid)

    info("[^] starting syno with arguments %s" % args)
    syno = Syno(args.url_or_qcid, login, password, insecure=args.insecure, lan=args.lan, temporisation=args.temporisation)
    atexit.register(_at_exit)

    if args.action == "ls":
        syno.ls(args.directory, recursive=args.recursive)
    elif args.action == "get":
        syno.get(args.path, args.out, recursive=args.recursive, progress=not args.no_progress, download_threads=args.threads)
    else:
        synohelp = INTERACTIVE_MODE_HELP
        info(synohelp)
        from IPython import embed
        embed()
