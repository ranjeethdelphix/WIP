#!/usr/bin/env python3
#================================================================================
# File:         execute_dlpx.py
# Type:         python script
# Date:         February 4th 2023
# Author:       Ranjeeth Kashetty
# Ownership:    This script is owned and maintained by the user, not by Delphix
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Copyright (c) 2020 by Delphix. All rights reserved.
#
# Description:
#       Script to be used to trigger and poll masking as well as profiling jobs
#
# Prerequisites:
#       1. Download pg_refresh package into a Linux VM
#       2. This script can be executed standalone or as a called script from chargeback workflow
# Usage:
#       ./execute_dlpx -dh <<delphix host>> -du <<delphix user>> -dp <<delphix password>> -job
#                                   <<job id>> -jt <<job type - profile or mask>>

import argparse
import inspect
import Onboard_Exec
import json
import socket
import os
import os.path
import datetime
from datetime import datetime
import sys
from sys import exit
import subprocess
from subprocess import Popen, PIPE
import time
import requests
from requests.exceptions import RequestException
#from functools import cached_property

from typing import List, Optional, Tuple, Any

import logging


def api_call_status(func_name, request):
    status_code = request.status_code
    status_msg = request.text
    if status_code != 200:
        logging.info(f"Request in operation {func_name} failed with status code {status_code}")
        logging.info(f"Message: {status_msg}")
        print(f"Request in operation {func_name} failed with status code {status_code}")
        print(f"Message: {status_msg}")
        os._exit(1)
    else:
        logging.info(f"Request in Function {func_name} succeeds with status code {status_code}")


def authenticate_api() -> Any:
    """Trigger profiling or masking """
    global dlpx_host, dlpx_user, dlpx_pass, baseurl, job_id

    baseurl_80 = 'http://' + dlpx_host + '/hyperscale-compliance'
    baseurl_443 = 'https://' + dlpx_host + '/hyperscale-compliance'

    logger = logging.getLogger(__name__)

    logger.info("Delphix API authentication ")

    a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    r_check = a_socket.connect_ex((dlpx_host, 80))

    if r_check == 0:
        baseurl = baseurl_80
    else:
        baseurl = baseurl_443
    a_socket.close()

    req_headers = {'Content-Type': 'application/json'}

    session = requests.session()
    formdata = '{ "type": "LoginRequest", "username": "' + dlpx_user + '", "password": "' + dlpx_pass + '" }'
    request = session.post(baseurl + '/login', data=formdata, headers=req_headers, allow_redirects=False, verify=False)
    api_call_status('authenticating', request)
    j = json.loads(request.text)
    authapi = j['Authorization']

    req_headers = {'Accept': 'application/json', 'Authorization': authapi}
    return session, req_headers

def get_engines() -> Any:
    """Trigger profiling or masking """
    global dlpx_host, apk

    baseurl_80 = 'http://' + dlpx_host + '/api'
    baseurl_443 = 'https://' + dlpx_host + '/api'

    logger = logging.getLogger(__name__)

    logger.info("Delphix API authentication ")

    a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    r_check = a_socket.connect_ex((dlpx_host, 80))

    if r_check == 0:
        baseurl = baseurl_80
    else:
        baseurl = baseurl_443
    a_socket.close()

    req_headers = {'Accept': 'application/json', 'Authorization': 'apk ' + str(apk)}
    #req_headers = {'Content-Type': 'application/json'}

    session = requests.session()
    request = session.get(baseurl + '/engines', headers=req_headers, verify=False)
    #api_call_status('authenticating', request)
    j = json.loads(request.text)
    print("return: " +str(j))

    return

def decrypt(strPass):
    key = b'4k89b1lPNQKq2sT5gYq8cptMDHRjKaRTIRkhTZa9F2I='
    f = Fernet(key)
    decryptPass = f.decrypt(strPass).decode()
    return decryptPass

def encrypt(strPass):
    key = b'4k89b1lPNQKq2sT5gYq8cptMDHRjKaRTIRkhTZa9F2I='
    encodestr = strPass.encode()
    fkey = Fernet(key)
    encryptPass = fkey.encrypt(encodestr)
    return encryptPass

def encrypt_Password():
    global ConfigPath

    fappConfig = open(ConfigPath)
    app_data = json.load(fappConfig)
    fappConfig.close()

    if app_data['hyperscale_config']['encrypted'].upper() == 'Y':
        print("Hyperscale APK is already encrypted. No action taken!")
    else:
        app_data['hyperscale_config']['encrypted'] = 'Y'
        en_pass = encrypt(app_data['hyperscale_config']['apk'])
        app_data['hyperscale_config']['apk'] = en_pass.decode("utf-8")

        with open(ConfigPath, "w") as outfile:
            json.dump(app_data, outfile, indent=4)
        outfile.clos()

    print("Passwords and APKs are encrypted in the config file")


def read_config() -> Any:
    """Initialize hashi config data """
    global ConfigPath,db_config,profiler_scripts,hashi_config,hyperscale_config,profiler_scripts,dbhost,dbtype,\
        dbport,dbname,secret_path,dbschema,cc_engine


    logger = logging.getLogger(__name__)
    logger.info("Started fetching user credentials for " + indicator + " DB")

    fConfig = open(ConfigPath)
    data = json.load(fConfig)
    fConfig.close()

    profiler_scripts = data['profiler_scripts']
    hashi_config = data['hashi_config']
    hyperscale_config = data['hyperscale_config']
    cc_engine = data['delphix_compliance']
    try:
        db_config = next(d for d in data['database'] if d['name'] == dbname and d['db_type'].upper() == dbtype.upper())
        if db_config['onboard'] == 'yes':
            print("Database already onboarded!")
            exit(1)
        else:
            onboard_status = db_config['onboard']
    except KeyError as e:
        onboard_status = 'new'

    #if dbschema == all then make an entry into config file for each schema
    db_config['name'] = dbname
    db_config['host'] = dbhost
    db_config['port'] = dbport
    db_config['secret_path'] = secret_path
    db_config['db_type'] = dbtype
    db_config['db_schema'] = dbschema
    db_config['onboard'] = onboard_status

    if onboard_status == 'new':
        data['database'].append(db_config)
        with open(ConfigPath, 'w') as file:
            json.dump(data, file, indent=4)

    return

ConfigPath = './conf/hyper_config.json'
def main():
    global args,db_config,profiler_scripts,hyperscale_config,ConfigPath,dbschema,dbname,dbtype,dbhost,dbport,secret_path

    parser = argparse.ArgumentParser()

    # Add long and short argument
    parser.add_argument("--dbhost", "-dh", required=True, help="Database Host")
    parser.add_argument("--dbport", "-dp", default = "5432", help="Database Port")
    parser.add_argument("--dbname", "-db", required=True, help="Database Name")
    parser.add_argument("--dbschema", "-ds", default="all", help="all or specific schema name")
    parser.add_argument("--dbtype", "-dt", required=True, choices=['aurora','atlas'], help="Database Type:  atlas or aurora ")
    parser.add_argument("--operation", "-op", required=True, choices=['1','2','3'],help="1. Onboard  2. Profile Only 3. Mask Only")
    parser.add_argument("--secret", "-sp", help="Secret Path")

    # Read arguments from the command line
    args = parser.parse_args()
    operation = args.operation
    dbhost = args.dbhost
    dbtype = args.dbtype
    dbport = args.dbport
    dbname = args.dbname
    dbschema = args.dbschema
    secret_path = args.secret

    if operation in ["1","2"]:
        read_config()
        onboard_status = Onboard_Exec.call_onboard(db_config,profiler_scripts,hashi_config,hyperscale_config,operation)

        with open(ConfigPath, 'r') as file:
            app_data = json.load(file)

        for d in app_data['database']:
            if d['name'] == dbname and d['db_type'] == dbtype:
                d['onboard'] = onboard_status
                break;

        with open(ConfigPath, 'w') as file:
            json.dump(app_data, file, indent=4)

    elif operation == "3":
        print("option 3")

    #get_engines()

if __name__ == '__main__':
    main()