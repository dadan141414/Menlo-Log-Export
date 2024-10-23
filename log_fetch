#!/usr/bin/python
####################################################################################################
# log_fetch_py3.py
# Fetches Menlo Security logs via an API and writes out the Logs to an output file.
####################################################################################################
# dependencies:
# python >= 3.0
# python dependencies:
# requests >= 2.20.1
####################################################################################################
# Copyright 2020 Menlo Security Inc. All rights reserved.                                          #
#                                                                                                  #
# Redistribution and use in source and binary forms, with or without modification, are             #
# permitted provided that the following conditions are met:                                        #
#                                                                                                  #
#    1. Redistributions of source code must retain the above copyright notice, this list of        #
#       conditions and the following disclaimer.                                                   #
#                                                                                                  #
#    2. Redistributions in binary form must reproduce the above copyright notice, this list        #
#       of conditions and the following disclaimer in the documentation and/or other materials     #
#       provided with the distribution.                                                            #
#                                                                                                  #
# THIS SOFTWARE IS PROVIDED BY MENLO SECURITY INC ''AS IS'' AND ANY EXPRESS OR IMPLIED             #
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND         #
# FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL MENLO SECURITY INC OR         #
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR              #
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR         #
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON         #
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING               #
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF             #
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.                                                       #
#                                                                                                  #
# Any views and conclusions contained in the software and documentation are those of the           #
# authors and should not be interpreted as representing official policies, either expressed        #
# or implied, of Menlo Security Inc.                                                               #
####################################################################################################

import argparse
import csv
import datetime
import hashlib
import json
import logging
import time
import os
import sys
import urllib
import re

try:
   import requests
except ImportError:
   raise Exception('python-requests is a required dependency')

# script version
VERSION = '1.13'

CSV_HEADERS_BY_TYPE = {
   'audit': [
      'additional_info', 'audit_actions', 'details', 'event_time', 'name',
      'product', 'rev_id', 'severity', 'sub_event_type', 'uid', 'vendor',
      'version'
   ],
   'safemail': [
      'event_time', 'vendor', 'product', 'version', 'name', 'severity',
      'domain', 'rewritten', 'message_tid', 'charset', 'reason',
      'email_date', 'message_id', 'mime_type', 'to', 'from', 'sender',
      'subject', 'reply_to', 'delivered_to', 'url', 'filename', 'counter'
   ],
   'smtp': [
      'event_time', 'vendor', 'product', 'version', 'name', 'severity',
      'smtp_reply', 'time_handoff_down', 'total_links', 'rows', 'from',
      'src_tls', 'hostname', 'src_ip', 'to', 'message_id', 'timestamp',
      'src_port', 'reason', 'dst_tls', 'rewritten_links', 'time_taken',
      'next_hop_reason', 'time_handoff_up', 'message_tid', 'region',
      'unix_time', 'unix_time_iso', 'mode', 'dst_ip', 'rewrite_success',
      'dst_from_port', 'time_processing', 'bytes'
   ],
   'bandwidth': [
      'event_time', 'vendor', 'product', 'version', 'name', 'severity',
      'browser', 'categories', 'frame_domain', 'is_iframe',
      'is_mobile', 'quota_action', 'quota_event', 'region', 'res_domain',
      'src_ip', 'top_domain', 'ua_type', 'userid', 'user-agent',
      'rule_id', 'rule_name', 'cumulative_bytes', 'rx_bytes', 'sum_bytes',
      'tx_bytes', 'user_groups', 'user_groups_matched'
   ],
   'web': [
      'event_time', 'vendor', 'product', 'version', 'name', 'severity',
      'x-client-ip', 'protocol', 'url', 'browser_and_version', 'userid',
      'request_type', 'pe_action', 'categories', 'threats', 'threat_types',
      'dst', 'user-agent', 'filename', 'magic_name', 'mime_type', 'response_code', 'referer',
      'content-type', 'top_url', 'domain', 'origin_ip', 'has_password',
      'sha256', 'risk_tally', 'egress_ip', 'risk_score', 'tab_id',
      'pe_reason', 'full_session_id', 'xff_ip', 'cached', 'ua_type',
      'email_isolation_state', 'document_url', 'file_size', 'archive_path',
      'casb_app_name', 'casb_cat_name', 'casb_fun_name', 'casb_org_name',
      'casb_profile_id', 'casb_profile_name', 'casb_profile_type',
      'casb_risk_score', 'connId', 'depth_level_in_archive', 'origin_country',
      'egress_country', 'is_casb_ddl', 'is_iframe', 'parent_file_id',
      'parent_filename', 'parent_sha256', 'parent_tid', 'pe_rulename',
      'xHeaders', 'xHeadersMatched', 'proxyEventDetail', 'proxyEventType',
      'region', 'reqId', 'root_file_id', 'root_filename', 'root_sha256',
      'saasHeaders', 'soph_dlp_ref', 'x-client-country',
      'groups', 'groupsMatched', 'upstream_response_code', 'src_port',
      'domain_front', 'fullScanResult', 'sandboxResult', 'sandboxActivity', 'virusDetails'
   ],
   'attachment': [
      'event_time', 'vendor', 'product', 'version', 'name', 'severity',
      'rewritten', 'reason', 'message_tid', 'to', 'from', 'sender',
      'subject', 'reply_to', 'email_date', 'message_id', 'delivered_to',
      'charset', 'domain', 'filename', 'mime_type', 'bytes', 'sha256',
      'file_type', 'rvlabs_risk', 'rvlabs_classification', 'rvlabs_factor',
      'rvlabs_result', 'rvlabs_malicious_indicators'
   ],
   'dlp': [
      'event_time', 'vendor', 'product', 'version', 'name', 'severity',
      'dst_url', 'domain', 'protocol', 'file_type', 'user_input',
      'alerted', 'ccl_ids', 'event_id', 'filename', 'sha256',
      'status', 'ccl_match_counts', 'ccl_scores', 'rule_name',
      'request_type', 'src_url', 'categories', 'stream_name',
      'userid', 'action', 'rule_id', 'xHeaders', 'xHeadersMatched',
      'groups', 'groupsMatched'
   ],
   'firewall': [
      'event_time', 'vendor', 'product', 'version', 'severity', 'name', 
      'action', 'dest_ip', 'dest_port', 'event_name', 'ip_protocol', 'pid',
      'rule_id', 'rule_name', 'src_ip', 'src_port', 'tunnel_id', 'user_id',
      'service_name'
   ],
   'isoc': [
      'alert_name', 'alert_sub_type', 'alert_type',
      'browser', 'browser_and_version', 'browser_type',
      'click_time', 'event_time', 'file_decrypted',
      'file_encrypted', 'file_size', 'file_type', 'filename',
      'recommended_action', 'severity', 'url', 'user-agent', 'accessed_urls', 
      'alert_action', 'alert_id', 'alert_timestamp', 'av_scan_result', 'context',
      'credentials_submitted', 'cve_ids','data_submission_url', 'domain',
      'dest_ips', 'file_download', 'has_password',
      'heat_evasion_descriptions', 'heat_evasion_techniques', 'heat_tactics',
      'intel_logodetection_report', 'intel_rlabs_report',
      'intel_sophos_report', 'intel_urlscan_report', 'intel_vt_report',
      'is_iframe', 'legacy_url_category', 'lure_category', 'mitre_ids',
      'navigation_correlation', 'referer', 'resource_category',
      'download_type', 'pe_action', 'pe_rulename', 'phishing_brand',
      'phishing_kit', 'phishing_visual_similarity', 'redirect_count',
      'request_type', 'response_code', 'risk_score', 'rule_descriptions',
      'rule_names', 'sdoc_download', 'source_ip', 'sha256',
      'threat_actor_group', 'threat_name', 'threat_type', 'virus_details',
      'timestamp', 'ua_type', 'userid', 'x-client-ip'
   ]
}


EXPORT_URL = ('https://{host}/api/rep/{api_version}/fetch/client_select'
   '?start={start}&format={format}&end={end}&limit={limit}')

NUM_SECONDS_FIVE_MINUTES = 300

NUM_SECONDS_ONE_HOUR = 3600

TIME_FORMAT = '%Y%m%d%H%M%S'

def date_to_unix(date_string):
   """Convert a date_string of format YYYYMMDDhhmmss to unix time integer.
   Assumes the date string object is UTC time.
   """
   dt = datetime.datetime.strptime(date_string, TIME_FORMAT)
   epoch = datetime.datetime(1970, 1, 1)
   return int((dt - epoch).total_seconds())

def date_from_unix(seconds):
   """Converts time in seconds since UNIX EPOCH to UTC Time format"""
   return time.strftime(TIME_FORMAT, time.gmtime(seconds))

def fetch_events(args):
   """Fetch the events from the remote server.
   Requests all log events for the requested time period, returning a list
   of those events.
   """
   is_interval = False
   # Create headers
   # A "Content-Type: application/json" header is required.
   headers = {'Content-Type': 'application/json', 'Accept-Encoding': 'gzip'}

   # 'start', 'end' and 'format' URL parameters are optional.
   # If not defined, the log API will currently default them to:
   #   start:  now - 5minutes
   #   end:    now
   #   format: JSON
   # For this example all 3 will be populated, with the same logic.

   # Create 'start' and 'end'. 'start' and 'end' are integers of unixtime.
   # For the purposes of this script, if only 'start' OR 'end' is provided,
   # offset the other by 5 minutes. If neither is provided, use the last
   # 5 minutes.
   try:
      if args.starttime and args.endtime:
        # Both are defined
        start = date_to_unix(args.starttime)
        end = date_to_unix(args.endtime)

      elif args.starttime:
        # Only 'start'
        start = date_to_unix(args.starttime)
        end = start + NUM_SECONDS_FIVE_MINUTES  # Offset 5 minutes into future from 'start'

      elif args.endtime:
        # Only 'end'
        end = date_to_unix(args.endtime)
        start = end - NUM_SECONDS_FIVE_MINUTES  # Offset 5 minutes into past from 'end'

      else:
        # Neither, use current time
         end = int(time.time()) # Take only integer value in seconds
         start = end - NUM_SECONDS_FIVE_MINUTES
         is_interval = True

   except Exception as ex:
      logging.error('Error while processing starttime/endtime, error - %s',
                    str(ex))
      return

   # Check the query syntax and update start/end time in case missing -s/-e
   # If there is an interval in -q, it should be in the first position of the string
   # Ex: -q 'interval=1h resource != "resource"' <== Correct format
   # Ex: -q 'resource != "resource" interval=1h' <== Incorrect format
   if args.query and len(args.query.strip()) > 0:
      idx = args.query.strip().find('interval=')
      if idx > 0:
         logging.error('\"interval\" time in -q is incorrect format.')
         return
      url = EXPORT_URL.format(host = args.hostname,
         api_version = args.api_version, start = start,
         end = end, format = args.format, limit = args.limit)
      url = url + '&query=' + urllib.parse.quote(args.query.strip()) +\
         '&interval_time=true'
      data = {'token': args.token, 'log_type': args.type}
      try:
         response = requests.post(url, headers = headers,
            data = json.dumps(data))
         # Stop script in case BAD_REQUEST
         if not response:
            logging.error('API responded with: %s - %s',
                          response.status_code, response.text)
            return
         response_json = response.json()
         # Update start/end time in case missing -s/-e
         # and has interval in -q
         if is_interval and idx == 0 and \
            'start' in response_json and response_json['start'] and \
            'end' in response_json and response_json['end']:
            start = date_to_unix(response_json['start'])
            end = date_to_unix(response_json['end'])
         # Show warning message if it exists
         if 'reason' in response_json and response_json['reason']:
            logging.warning(response_json['reason'])
      except Exception as ex:
         logging.error('Error while fetching the time interval, '
                       'error - %s', str(ex))

   # In case both '-s' and/or '-e' and interval in '-q' are defined
   # the script will use time from '-s', '-e' arguments
   # and display a warning message
   if (args.starttime or args.endtime) and args.query and \
      'interval=' in args.query:
      logging.warning('You are going to use -s/-e and ignore the interval in -q')

   logging.info('Requested data from UTC Time %s to %s',
                date_from_unix(start), date_from_unix(end))

   logging.debug('Requested data from Local Time %s to %s',
                 time.ctime(start), time.ctime(end))

   if start > end:
      logging.error('starttime can not be greater than endtime')
      return

   # split the original start/end into 1 hour chunks.
   if end - start > NUM_SECONDS_ONE_HOUR:
      intervals = []
      cur_start = start
      cur_end = start + (NUM_SECONDS_ONE_HOUR - (start % NUM_SECONDS_ONE_HOUR))
      intervals.append({'start': cur_start, 'end': cur_end})
      while cur_end < end:
         cur_start = cur_end
         cur_end = min(end, cur_end + NUM_SECONDS_ONE_HOUR)
         intervals.append({'start': cur_start, 'end': cur_end})
   else:
      intervals = [{'start': start, 'end': end}]

   total_event_count = 0
   interval_count = 0
   for interval in intervals:
      cur_start = interval['start']
      cur_end = interval['end']
      interval_count += 1
      interval_event_count = 0

      # Create request URL
      url = EXPORT_URL.format(
         host = args.hostname, api_version = args.api_version,
         start = cur_start, end = cur_end,
         format = args.format, limit = args.limit)
      if args.query and len(args.query.strip()) > 0:
         url = url + '&query=' + urllib.parse.quote(args.query.strip())

      # Create payload
      # The payload consists of JSON object containing:
      #   token:    The log API token to authenticate to the server
      # Optional:
      #   log_type: The requested log type. Defaults to 'web'
      #   pagingIdentifiers: Allows pagination of results. Refer to documentation.
      data = {'token': args.token, 'log_type': args.type}

      logging.debug('Processing interval # %d UTC Time %s to  %s',
                    interval_count, date_from_unix(cur_start),
                    date_from_unix(cur_end))
      logging.debug('Local Time from %s to  %s',
                    time.ctime(cur_start), time.ctime(cur_end))
      # Retrieve the events
      # POST requests are performed in a loop to request the next (up to) 1000
      # events. After each request, the 'pagingIdentifiers' of 'data' need to be
      # updated with all reported 'pagingIdentifiers'. If this is not done, the
      # same data will be returned on each POST.

      page_count = 0
      while True:
         # Make the POST request
         page_count += 1
         logging.debug('Fetching interval %d, page %d', interval_count,
                       page_count)

         logging.debug('Request: URL - %s, Headers - %s, Data - %s',
                       url, headers, json.dumps(data))
         try:
            response = requests.post(url, headers = headers,
               data = json.dumps(data))
         except Exception as ex:
            logging.error('Error while fetching the logs, error - %s', str(ex))
            return

         if not response:
            logging.error('API responded with: %s - %s',
                          response.status_code, response.text)
            return

         if not response.text:
            logging.info('API responded with no data.')
            break

         # 200 OK and data
         response_json = response.json()

         # Response is a list of 1 element if successful
         if not response_json:
            logging.error('API did not respond with any content')
            return

         response_data = response_json[0]

         # The element is a dictionary containing the timestamp of the earliest
         # event and the result dictionary
         #logging.debug('Earliest event: %s', response_data['timestamp'])

         # The result contains an entry for a list of all events, and the
         # pagingIdentifiers. These pagingIdentifiers need to be added the
         # subsequent requests to ensure all events in the time period are
         # received.
         result = response_data['result']

         # Add all new 'pagingIdentifiers' to the payload for the next request
         data.setdefault('pagingIdentifiers', {}).update(
            result['pagingIdentifiers'])

         if result['events']:
            logging.debug('Fetched interval %d page %d events %d '
                          'earliest event: %s', interval_count, page_count,
                          len(result['events']), response_data['timestamp'])
            try:
               current_events = remove_duplicates(result['events'])
               interval_event_count += len(current_events)
               write_result(args, current_events)
            except Exception as ex:
               logging.error('Error while writing the logs to the file %s, '
                             'error - %s', args.output, str(ex))
               break
         else:
            # If no events are returned in this page, all events have been fetched
            logging.debug('All events of interval %d have been fetched in %d '
                          'pages', interval_count, page_count)
            break

      logging.info('Interval #: %d UTC Time %s to %s, pages: %d events: %d ',
                   interval_count, date_from_unix(cur_start),
                   date_from_unix(cur_end), page_count, interval_event_count)
      total_event_count += interval_event_count

   logging.info('Total %d events fetched and appended to the file %s in %d '
                'intervals', total_event_count, args.output, interval_count)

def write_result(args, all_events):
   """Write events to specified output file."""
   headers_written = os.path.isfile(args.output)
   with open(args.output, 'a', newline = '', encoding = 'utf-8') as output:
      if not all_events:
         output.write('No events received')
         return

      # Handle special CSV case
      if args.format == 'CSV':
         write_csv(args, output, all_events, headers_written)
         logging.info('Logs appended to %s', args.output)
         return

      # Otherwise, iterate all_events write them to output
      # Each event in all_events is a dict of {'event': <requested format>}
      # hence the event['event'] usage.
      for event in all_events:
         if not isinstance(event['event'], str):
            # Convert dict to a string
            event_str = json.dumps(event['event'])
         else:
            event_str = event['event']

         if args.format in ['KVP', 'CEF', 'LEEF']:
            append = args.append.strip()
            if append != '':
               event_str += (' ' + append)
         output.write(event_str)
         output.write('\n')

   logging.debug('Appended %d log events to %s', len(all_events), args.output)


seen = set()  # Make this global to dedup across pages
def remove_duplicates(all_events):
   """Remove any duplicate events.
   Sometimes the event's paging results in an overlap causing duplicate logs.
   Simple function to remove those duplicates.
   """
   dedupe_events = []
   for event in all_events:
      json_str = json.dumps(event['event'])
      key = hashlib.sha256(json_str.encode('utf8')).hexdigest()
      if key not in seen:
         dedupe_events.append(event)
         seen.add(key)
   original_len = len(all_events)
   dedupe_len = len(dedupe_events)
   if (original_len != dedupe_len):
      logging.info('Removed %d duplicate events', original_len - dedupe_len)

   return dedupe_events


def write_csv(args, output, all_events, headers_written = False):
   """Handling creating a CSV file from the JSON objects in all_events.
   This example will require different headers dependent on the log_type.
   """
   headers = CSV_HEADERS_BY_TYPE[args.type]
   writer = csv.DictWriter(output, fieldnames = headers,
      extrasaction = 'ignore')

   if not headers_written:
      writer.writeheader()
   for event in all_events:
      writer.writerow(event['event'])

def token_handler(args):
   reg_token = '^[0-9a-z]{32}$'

   # Check token value from command line
   if re.match(reg_token, args.token):
      return True

   # Get Token from file
   token_file = args.token
   logging.info('Getting token value from file.')
   if not os.path.exists(token_file):
      logging.error('Token file %s does not exists.', token_file)
      return False

   logging.info('File %s exists.', token_file)
   try:
      logging.info('Loading token value from file %s.', token_file)
      f = open(token_file, 'r')
      token = f.read()
      if not re.match(reg_token, token):
         logging.error('Token value %s invalid.', token)
         return False
      logging.info('Successfully loaded token from file %s.', token_file)
      args.token = token
      return True
   except Exception as e:
      logging.error('Error when reading token from file %s - error: %s.',
                     token_file, str(e))
      return False

def parse_args():
   """Parse and return the command line arguments."""
   parser = argparse.ArgumentParser(
      description='Utilize Menlo Security Log Fetching API')
   parser.add_argument('token', help = 'Tenant Authentication Token')
   parser.add_argument('-o', '--output', default = 'menlo_logs.txt',
      help = 'Output filename to write logs to. Default: %(default)s')
   parser.add_argument('-d', '--debug', action = 'store_true',
      help = 'Enable debug logging in this script.')
   parser.add_argument('-s', '--starttime',
      help = 'UTC start time for logs. Format: YYYYMMDDhhmmss')
   parser.add_argument('-e', '--endtime',
      help = 'UTC end time for logs Format: YYYYMMDDhhmmss')
   parser.add_argument('-f', '--format', default = 'JSON',
      choices = ['CEF', 'JSON', 'KVP', 'CSV', 'LEEF'], help = 'Logs output format')
   parser.add_argument('-t', '--type', default = 'web',
      choices = ['web', 'safemail', 'audit', 'smtp', 'attachment', 'dlp', 'firewall', 'bandwidth', 'isoc'],
      help = 'Type of Log event')
   parser.add_argument('-host', '--hostname', default = 'logs.menlosecurity.com',
      help = 'Host to query for the logs')
   parser.add_argument('-v', '--version', action = 'version', version = VERSION)
   parser.add_argument('-r', '--api-version', dest = 'api_version',
      choices = ['v1', 'v2'], default = 'v1',
      help = 'Log Export API version. Default: %(default)s')
   parser.add_argument('-l', '--limit', type = int, default = 10000,
      help = 'max number of events to receive in each API call.')
   parser.add_argument('-a', '--append', default = '',
      help = 'Append this string to all log entries of KVP, CEF and LEEF format')
   parser.add_argument('-q', '--query', default = None,
      help = 'The query value used for filtering')
   return parser.parse_args()

def main():
   args = parse_args()
   log_level = logging.DEBUG if args.debug else logging.INFO
   log_format = 'time="%(asctime)s" level=%(levelname)s %(message)s'
   logging.basicConfig(level = log_level, format = log_format)

   if sys.version_info.major < 3:
      logging.info('Please run script with Python v3.x')
      return

   if token_handler(args):
      fetch_events(args)

if __name__ == '__main__':
   main()
