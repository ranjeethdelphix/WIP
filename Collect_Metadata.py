#!/usr/bin/env python3
# ================================================================================
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
# from functools import cached_property

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

    baseurl_80 = 'http://' + dlpx_host + '/masking/api'
    baseurl_443 = 'https://' + dlpx_host + '/masking/api'

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


def extract_app_environments() -> Any:
    """Create environment lookup from source engine"""
    global args, dlpx_host, bkp_loc, sync_operation, baseurl, datestamp, ext_file_names, verifyCert, metadata

    logger = logging.getLogger(__name__)

    session, req_headers = authenticate_api()

    logger.info("Creating environments lookup from source engine!")
    print("Creating environments lookup from source engine!")

    a_path_var = '/applications'
    a_params_post = {'page_size': 5000}
    app_extract = session.get(baseurl + a_path_var, headers=req_headers, params=a_params_post, verify=verifyCert)

    api_call_status('Extract applications', app_extract)
    app_lst_tmp = json.loads(app_extract.text)
    app_lst = app_lst_tmp['responseList']

    params_post = {'page_size': 5000}
    for app in app_lst:
        metadata_tmp['applicationName'] = app['applicationName']
        path_var = '/environments?appliation_id=' + app['applicationId']
        env_extract = session.get(baseurl + path_var, headers=req_headers, params=params_post, verify=verifyCert)
        if env_extract.status_code == 404:
            metadata_tmp['environmentName'] = ''
            metadata_tmp['connectorName'] = ''
            metadata_tmp['rulesetName'] = ''
            metadata_tmp['databaseName'] = ''
            metadata_tmp['schemaName'] = ''
            metadata_tmp['databaseType'] = ''
            metadata_tmp['profileJobId'] = ''
            metadata_tmp['maskingJobId'] = ''
            continue
        else:
            env_lst_tmp = json.loads(env_extract.text)
            for env in env_lst_tmp['responseList']:
                metadata_tmp['environmentName'] = env['environmentName']

                conn_lst = get_connectors(session, req_headers,env['environmentId'])
                rule_lst = get_rulesets(session, req_headers, env['environmentId'])
                jobs_lst = get_jobs(session, req_headers, env['environmentId'])

                for conn in conn_lst:
                    metadata_tmp['connectorName'] = conn['connectorName']
                    metadata_tmp['databaseName'] = conn['databaseName']
                    metadata_tmp['schemaName'] = conn['schemaName']
                    metadata_tmp['databaseType'] = conn['databaseType']

                    for rule in rule_lst:
                        if conn['databaseConnectorId'] == rule['databaseConnectorId']:
                            metadata_tmp['rulesetName'] = rule['rulesetName']
                            for job in jobs_lst:
                                if rule['rulesetId'] == job['rulesetId']:
                                    metadata_tmp['profileJobId'] = job['profileJobId']
                                    metadata_tmp['maskingJobId'] = job['maskingJobId']

        metadata.append(metadata_tmp)

def get_connectors(session, req_headers, environmentId) -> Any:
    global dlpx_host, bkp_loc, baseurl, verifyCert

    logger = logging.getLogger(__name__)
    logger.info("Get source environment ID for OTF jobs")

    path_var = '/database-connectors/?environment_id=' + str(environmentId)
    params_post = {'page_size': 5000}

    extract_exec = session.get(baseurl + path_var, params=params_post, headers=req_headers, verify=verifyCert)
    extract_info = json.loads(extract_exec.text)

    for conn in extract_info['responseList']:
        conn_tmp['environmentId'] = conn['environmentId']
        conn_tmp['databaseConnectorId'] = conn['databaseConnectorId']
        conn_tmp['connectorName'] = conn['connectorName']
        conn_tmp['databaseName'] = conn['databaseName']
        conn_tmp['databaseType'] = conn['databaseType']
        conn_tmp['schemaName'] = conn['schemaName']

        conn_lst.append(conn_tmp)

    return conn_lst

def get_rulesets(session, req_headers, environmentId) -> Any:
    global dlpx_host, bkp_loc, baseurl, verifyCert

    logger = logging.getLogger(__name__)
    logger.info("Get source environment ID for OTF jobs")

    path_var = '/database-rulesets/?environment_id=' + str(environmentId)
    params_post = {'page_size': 5000}

    extract_exec = session.get(baseurl + path_var, params=params_post, headers=req_headers, verify=verifyCert)
    extract_info = json.loads(extract_exec.text)

    for rs in extract_info['responseList']:
        rs_tmp['databaseConnectorId'] = rs['databaseConnectorId']
        rs_tmp['rulesetName'] = rs['rulesetName']
        rs_tmp['rulesetId'] = rs['databaseRulesetId']
        rs_lst.append(rs_tmp)

    return rs_lst

def get_jobs(session, req_headers, environmentId) -> Any:
    global dlpx_host, bkp_loc, baseurl, verifyCert

    logger = logging.getLogger(__name__)
    logger.info("Get source environment ID for OTF jobs")

    path_var = '/profile-jobs/?environment_id=' + str(environmentId)
    params_post = {'page_size': 5000}

    extract_exec = session.get(baseurl + path_var, params=params_post, headers=req_headers, verify=verifyCert)
    extract_info = json.loads(extract_exec.text)

    for pj in extract_info['responseList']:
        pj_tmp['profileJobId'] = pj['profileJobId']
        pj_tmp['rulesetId'] = pj['rulesetId']
        pj_tmp['maskingJobId'] = ''

        pj_lst.append(pj_tmp)

    path_var = '/masking-jobs/?environment_id=' + str(environmentId)
    params_post = {'page_size': 5000}

    extract_exec = session.get(baseurl + path_var, params=params_post, headers=req_headers, verify=verifyCert)
    extract_info = json.loads(extract_exec.text)

    for mj in extract_info['responseList']:
        mj_tmp['profileJobId'] = ''
        mj_tmp['rulesetId'] = mj['rulesetId']
        mj_tmp['maskingJobId'] = mj['maskingJobId']

        mj_lst.append(mj_tmp)

    for pj in pj_lst:
        common_lst_tmp['rulesetId'] = pj['rulesetId']
        common_lst_tmp['profileJobId'] = pj['profileJobId']
        common_lst_tmp['maskingJobId'] = ''

        for mj in mj_lst:
            if pj['rulesetId'] == mj['rulesetId']:
                common_lst_tmp['maskingJobId'] = mj['maskingJobId']
                break
        common_lst.append(common_lst_tmp)

    return common_lst
