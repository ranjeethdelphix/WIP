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


def execute_job(host='', user='', password='', job_id_tmp='', job_type_tmp='') -> Any:
    """Trigger profiling or masking """
    global baseurl, dlpx_host, dlpx_user, dlpx_pass, baseurl, job_id

    logger = logging.getLogger(__name__)

    filename = os.path.splitext(os.path.basename(inspect.stack()[1].filename))[0]

    if filename in ("Chargeback", "pg_refresh"):
        dlpx_host = host
        dlpx_user = user
        dlpx_pass = password
        job_id = job_id_tmp
        jobType = job_type_tmp
        chargeback_call = 'Y'

    session, req_headers = authenticate_api()

    if jobType == 'profiling':
        logger.info("Execute profiling ")
    else:
        logger.info("Execute masking ")

    JOBDATA = "{\"jobId\":" + job_id + "}"
    jsondata = json.loads(JOBDATA)

    exec_job = session.post(baseurl + '/executions', headers=req_headers, json=jsondata, verify=False)
    if jobType == 'profiling':
        api_call_status('execute profiling', exec_job)
    else:
        api_call_status('execute masking', exec_job)

    extract_info = json.loads(exec_job.text)
    return extract_info['executionId']


def execute_polling(host='', user='', password='', exec_id_tmp='', job_type_tmp='') -> Any:
    """Trigger profiling or masking """
    global baseurl, dlpx_host, dlpx_user, dlpx_pass, baseurl

    logger = logging.getLogger(__name__)

    filename = os.path.splitext(os.path.basename(inspect.stack()[1].filename))[0]

    if filename in ("Chargeback", "pg_refresh"):
        dlpx_host = host
        dlpx_user = user
        dlpx_pass = password
        exec_id = exec_id_tmp
        jobType = job_type_tmp
        chargeback_call = 'Y'

    session, req_headers = authenticate_api()

    if jobType == 'profiling':
        logger.info("Execute profiling ")
    else:
        logger.info("Execute masking ")

    url_ext = '/executions/' + str(exec_id)

    exec_job = session.get(baseurl + url_ext, headers=req_headers)

    if jobType == 'profiling':
        api_call_status('execute profiling', exec_job)
    else:
        api_call_status('execute masking', exec_job)

    extract_info = json.loads(exec_job.text)
    return extract_info


def collect_table_inventory(ruleset_id, session, req_headers) -> Any:
    global baseurl, dlpx_host, dlpx_user, dlpx_pass, baseurl, job_id

    logger = logging.getLogger(__name__)

    output_dict = {}

    url_ext = '/table-metadata?page_size=1000&ruleset_id=' + str(ruleset_id)
    exec_job = session.get(baseurl + url_ext, headers=req_headers)
    extract_info = json.loads(exec_job.text)
    api_call_status('extract table-metadata', exec_job)

    for tm in extract_info['responseList']:
        output_dict[tm['tableMetadataId']] = tm['tableName']

    return output_dict


def collect_column_inventory(table_metadata_id, session, req_headers) -> Any:
    global baseurl, dlpx_host, dlpx_user, dlpx_pass, baseurl, job_id

    logger = logging.getLogger(__name__)

    output_dict = {}

    url_ext = '/column-metadata?page_size=1000&table_metadata_id=' + str(table_metadata_id)
    exec_job = session.get(baseurl + url_ext, headers=req_headers)
    extract_info = json.loads(exec_job.text)
    api_call_status('extract table-metadata', exec_job)

    for cm in extract_info['responseList']:
        if 'algorithmName' in cm.keys():
            output_dict[cm['columnName']] = str(cm['dataType']) + '|' + str(cm['columnLength']) + '|' + str(
                cm['isMasked']) + \
                                            '|' + str(cm['algorithmName']) + '|' + str(cm['isProfilerWritable'])
        else:
            output_dict[cm['columnName']] = str(cm['dataType']) + '|' + str(cm['columnLength']) + '|' + str(
                cm['isMasked']) + \
                                            '|' + '' + '|' + str(cm['isProfilerWritable'])

    return output_dict


def record_Inventory(host='', user='', password='', job_id_tmp='') -> Any:
    """Trigger profiling or masking """
    global baseurl, dlpx_host, dlpx_user, dlpx_pass, baseurl, job_id
    tm_dictionary = {}
    cm_dictionary_dict = {}

    logger = logging.getLogger(__name__)

    filename = os.path.splitext(os.path.basename(inspect.stack()[1].filename))[0]

    if filename in ("Chargeback", "pg_refresh"):
        dlpx_host = host
        dlpx_user = user
        dlpx_pass = password
        job_id = job_id_tmp
        chargeback_call = 'Y'

    session, req_headers = authenticate_api()

    logger.info("Collect existing inventory..")
    url_ext = '/profile-jobs/' + str(job_id)
    exec_job = session.get(baseurl + url_ext, headers=req_headers)
    extract_info = json.loads(exec_job.text)
    api_call_status('get profile job details', exec_job)
    tm_dictionary = collect_table_inventory(extract_info['rulesetId'], session, req_headers)

    for key, value in tm_dictionary.items():
        cm_dictionary_dict[value] = collect_column_inventory(key, session, req_headers)

    """Refresh ruleset"""
    url_ext = '/database-rulesets/' + str(extract_info['rulesetId']) + '/refresh'
    exec_ref = session.put(baseurl + url_ext, headers=req_headers)
    api_call_status('referesh ruleset', exec_ref)
    return tm_dictionary, cm_dictionary_dict, extract_info['rulesetId']

def execute_profile_mask(indicator: str) -> Any:
    global dlpx_host, dlpx_user, dlpx_pass, reportPath, pjoblist, mjoblist

    logger = logging.getLogger(__name__)

    if indicator == 'profiling':
        for job in pjoblist:
            mismatch_list = []
            """Record existing inventory"""
            curr_tm, curr_cm, rset = record_Inventory(dlpx_host, dlpx_user, dlpx_pass, job)
            """Execute profiling"""
            ex_id = execute_job(dlpx_host, dlpx_user, dlpx_pass, job, indicator)

            print(indicator + " job " + str(job) + " execution initiated!")
            logger.info(indicator + " job " + str(job) + " execution initiated!")

            while True:
                time.sleep(9)
                """Keep polling execution results every 9 seconds"""
                ex_info = execute_polling(dlpx_host, dlpx_user, dlpx_pass, ex_id, indicator)
                if ex_info['status'] == 'SUCCEEDED':
                    """If profiling job succeeds, record column & table metadata"""
                    print(indicator + " job " + str(job) + " execution successful!")
                    logger.info(indicator + " job " + str(job) + " execution successful!")

                    new_tm, new_cm, rset = record_Inventory(dlpx_host, dlpx_user, dlpx_pass, job)

                    """Compare inventory and collect observations"""
                    mismatch_list = compare_inventory(curr_tm, curr_cm, new_tm, new_cm, rset)
                    break

                elif ex_info['status'] == 'CANCELLED':
                    print(indicator + " job " + str(
                        job) + " execution interrupted! Please fix the issue with job and resume or restart refresh")
                    logger.info(indicator + " job " + str(
                        job) + " execution interrupted! Please fix the issue with job and resume or restart refresh")
                    exit(1)

                elif ex_info['status'] == 'FAILED':
                    print(indicator + " job " + str(
                        job) + " execution failed! Please check the job logs, fix issue and resume or restart this script")
                    logger.info(indicator + " job " + str(
                        job) + " execution failed! Please check the job logs, fix issue and resume or restart this script")
                    exit(1)

            if bool(mismatch_list) and indicator == 'profiling':
                """Display mismatch observations and exit the refresh"""
                reportFilePath = reportPath + 'j' + str(ex_info['jobId']) + '_D' + str(date.today()) + '.txt'
                fProfileMismatch = open(reportFilePath, "a")
                fProfileMismatch.write(
                    '======================================================================================================\n\r')
                fProfileMismatch.write('Delphix Engine: ' + str(dlpx_host) + '\n\r')
                fProfileMismatch.write('Job ID: ' + str(ex_info['jobId']) + '\n\r')
                fProfileMismatch.write('Date of Profiling: ' + str(date.today()) + '\n\r')
                fProfileMismatch.write(
                    '......................................................................................................\n\r')

                for x in mismatch_list:
                    fProfileMismatch.write(x + '\n\r')
                fProfileMismatch.write('\n\r')
                fProfileMismatch.close()
                print(
                    "Profiling changes encountered. Stopping Refresh. Check the profile changes report file: " + reportFilePath)
                exit(2)
    elif indicator == 'masking':
        for job in mjoblist:
            """Execute masking jobs"""
            ex_id = execute_job(dlpx_host, dlpx_user, dlpx_pass, job, indicator)

            print(indicator + " job " + str(job) + " execution initiated!")
            logger.info(indicator + " job " + str(job) + " execution initiated!")

            while True:
                time.sleep(9)
                """Execute polling on masking job every 9 seconds"""
                ex_info = execute_polling(dlpx_host, dlpx_user, dlpx_pass, ex_id, indicator)
                if ex_info['status'] == 'SUCCEEDED':
                    print(indicator + " job " + str(job) + " execution successful!")
                    logger.info(indicator + " job " + str(job) + " execution successful!")
                    break
                elif ex_info['status'] == 'CANCELLED':
                    print(indicator + " job " + str(
                        job) + " execution interrupted! Please fix the issue with job and restart refresh")
                    logger.info(
                        indicator + ' job execution interrupted! Please fix the issue with job and restart refresh')
                    exit(1)
                elif ex_info['status'] == 'FAILED':
                    print(indicator + " job " + str(
                        job) + " execution failed! Please check the job logs, fix issue and restart this script")
                    logger.info(
                        indicator + ' job execution failed! Please check the job logs, fix issue and restart this script')
                    exit(1)

def compare_inventory(curr_tm, curr_cm, new_tm, new_cm, rset) -> Any:
    """Compare table metadata"""
    """dataType|columnLength|isMasked|algorithmName|isProfilerWritable"""

    logger = logging.getLogger(__name__)

    mismatch = list()
    mismatch_text = None
    for k, v in new_tm.items():
        """Check for new tables"""
        if k not in curr_tm.keys():
            mismatch_text = 'New table added to the inventory. Table: ' + str(v)
        elif v != curr_tm[k]:
            mismatch_text = 'Table name changed. New Table name: ' + str(v)

        if mismatch_text is not None:
            mismatch.append(mismatch_text)
            mismatch_text = None

    for key, value in new_cm.items():
        if key in curr_cm.keys():
            for sub_key, sub_value in value.items():
                new_cm_values = sub_value.split('|')

                if sub_key not in curr_cm[key].keys():
                    """Check if new column added"""
                    mismatch_text = 'New column added. Table: ' + str(key) + ' / Column: ' + str(sub_key)
                else:
                    curr_cm_values = curr_cm[key][sub_key].split('|')

                    if curr_cm_values != new_cm_values:
                        if curr_cm_values[2] != new_cm_values[2]:
                            """when masking indicator changes for the column"""
                            mismatch_text = 'Column PII indicator changed from no PII to PII or vice versa. Table: ' + str(
                                key) + ' / Column: ' \
                                            + str(sub_key)
                        elif (curr_cm_values[3] != new_cm_values[3]) and (curr_cm_values[2] == 'true'):
                            """when masking indicator remains same & is true and algorithm name changes"""
                            mismatch_text = 'Algorithm assignment changed. Table: ' + str(key) + ' / Column: ' + str(
                                sub_key)
                        elif (curr_cm_values[0] != new_cm_values[0]) and (curr_cm_values[2] == 'true'):
                            """when masking indicator remains same & is true and data type changes"""
                            mismatch_text = 'Data type of PII column changed. Table: ' + str(key) + ' / Column: ' + str(
                                sub_key)
                        elif (curr_cm_values[1] != new_cm_values[1]) and (curr_cm_values[2] == 'true'):
                            """when masking indicator remains same & is true and column length changes"""
                            mismatch_text = 'Column length of PII column changed. Table: ' + str(
                                key) + ' / Column: ' + str(sub_key)

                if mismatch_text is not None:
                    mismatch.append(mismatch_text)
                    mismatch_text = None

    if curr_cm == new_cm:
        logger.info('Inventory Profile Matches')

    return mismatch
