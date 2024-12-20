#!/usr/bin/env python3

from falconpy import EventStreams
import json
import time
import datetime
import requests
import os
import sys
import logging
import threading
import traceback
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from thehive4py import TheHiveApi
from thehive4py.types.alert import InputAlert
from thehive4py.errors import TheHiveError


# Function to create TheHive InputAlert
def create_alert_object(data):
    # Map severity names to numerical values
    severity_mapping = {
        'Informational': 1,
        'Low': 1,
        'Medium': 2,
        'High': 3,
        'Critical': 4
    }

    # Extract fields
    eventType = data.get('type', 'Unknown')
    source = 'CrowdStrike'
    sourceRef = data.get('id', '')
    detection_name = data.get('display_name', 'No Title')
    severity_name = data.get('severity_name', 'Informational').capitalize()
    adjustedSeverity = severity_mapping.get(severity_name, 1)
    falcon_link = data.get('falcon_host_link', "")
    description = data.get('description', "")
    eventTimestamp = data.get('timestamp', None)
    observables = []
    tags = ['CrowdStrike']
    mitreTags = []
    
    device_info = data.get('device', {})
    hostname = device_info.get('hostname', 'Unknown Host')

    # Extract observables
    # Check for MD5
    if 'md5' in data and data['md5'] and data['md5'] != 'N/A':
        observables.append({'dataType': 'hash', 'data': data['md5'], 'tags': ["md5"]})
    # Check for SHA256
    if 'sha256' in data and data['sha256'] and data['sha256'] != 'N/A':
        observables.append({'dataType': 'hash', 'data': data['sha256'], 'tags': ["sha256"]})
    #if 'sha1' in data and data['sha1'] and data['sha1'] != 'N/A':
    #    observables.append({'dataType': 'hash', 'data': data['sha1'], 'tags': ["sha1"]})
    # Filename
    if 'filename' in data and data['filename']:
        filename_observable = {'dataType': 'filename', 'data': data['filename']}
        if 'filepath' in data and data['filepath']:
            filename_observable["tags"] = [data['filepath']]
        observables.append(filename_observable)
    # Filepath
    if 'filepath' in data and data['filepath']:
        observables.append({'dataType': 'other', 'data': data['filepath'], 'tags': ["filepath"]})
    # Command line
    if 'cmdline' in data and data['cmdline']:
        observables.append({'dataType': 'other', 'data': data['cmdline'], 'tags': ["cmdline"]})
    # IP addresses
    if 'external_ip' in device_info and device_info['external_ip']:
        observables.append({'dataType': 'ip', 'data': device_info['external_ip'], 'tags': ["external-ip"]})
    if 'local_ip' in device_info and device_info['local_ip']:
        observables.append({'dataType': 'ip', 'data': device_info['local_ip'], 'tags': ["local-ip"]})
    # Hostname
    if 'hostname' in device_info and device_info['hostname']:
        hostname_observable = {'dataType': 'hostname', 'data': device_info['hostname']}
        hostname_tags = []
        if 'user_name' in data and data['user_name']:
            hostname_tags.append(f"username:{data['user_name']}")
        if "machine_domain" in device_info and device_info["machine_domain"]:
            hostname_tags.append(f"machine_domain:{device_info['machine_domain']}")
        if hostname_tags:
            hostname_observable["tags"] = hostname_tags
        observables.append(hostname_observable)

    # FQDN
    if "machine_domain" in device_info and device_info["machine_domain"] and "hostname" in device_info and device_info["hostname"]:
        fqdn = f"{device_info['hostname']}.{device_info['machine_domain']}"
        observables.append({'dataType': 'fqdn', 'data': fqdn, 'tags': ["machine-domain"]})


    # Extract MITRE ATT&CK techniques
    if 'technique_id' in data and data['technique_id'] and not data['technique_id'].startswith('CS'):
        mitreTags.append(data['technique_id'])
    tags.extend(mitreTags)
    technique = data.get('technique', '').strip()
    if not technique:
        technique = 'Unknown Technique'

    # Procedures
    procedures = []
    for tag in mitreTags:
        procedure = {
            'patternId': tag,
            'occurDate': eventTimestamp,
        }
        procedures.append(procedure)
        

        
    # Title
    title = f"[{severity_name}] Detection on {hostname}: {technique} - {detection_name}"

    
    # Description update
    if description:
        description += "\n\n"
    else:
        description = ""

    description += f"[Link to CrowdStrike Alert]({falcon_link})\n\n"

    # Add the entire data in a code block formatted as JSON
    description += f"```json\n{json.dumps(data, indent=4)}\n```"

    # Alert constrution
    input_alert: InputAlert = {
        "type": eventType,
        "source": source,
        "sourceRef": sourceRef,
        "title": title,
        "severity": adjustedSeverity,
        "description": description,
        "date": eventTimestamp,
        'observables': observables if observables else [],
        'tags': tags,
        'procedures': procedures if procedures else []
    }

    return input_alert

# set offset high to only get new events.
offset = 999999999
#offset = 1

# ###################### TO BE CUSTOMIZED ##################
g_token_url = "https://api.crowdstrike.com/oauth2/token"
g_client_id = 'XXXXXXXXXXXXXX'
g_client_secret = 'YYYYYYYYYY'
appId = "falcon2thehive"
THEHIVE_URL = 'http://127.0.0.1:9000'
THEHIVE_API_KEY = 'XXXXXXXXXXXXXXX'
THEHIVE_ORG = None

## INIT - TH & CRWD

hive = TheHiveApi(
        url=THEHIVE_URL,
        apikey=THEHIVE_API_KEY,
        organisation=THEHIVE_ORG
    )

falcon = EventStreams(client_id=g_client_id, \
                      client_secret=g_client_secret
                      )

response = falcon.list_available_streams(app_id=appId, format="flatjson")
dump = json.dumps(response, sort_keys=True, indent=4)
#print(dump)    #DEBUG



response2use = str(response).replace("\'", "\"")
load = json.loads(response2use)

for i in load["body"]["resources"]:
    print("Data Feed URL : " + i["dataFeedURL"])
    print("Generated Token : " + i["sessionToken"]["token"])
    dataFeedURL = i["dataFeedURL"]
    generatedToken = i["sessionToken"]["token"]
    refreshURL = i["refreshActiveSessionURL"]

# Below variables are created for compatibility reasons
url = dataFeedURL
token = generatedToken

'''
def refresh_stream():
    # refresh active streams
    # @params: None
    # @returns: the access_token
    print("INFO : Refreshing Stream Token")
    print('URL used for refresh operation : %s' % refreshURL)
    refreshHeaders = {'Authorization': "bearer %s" % generatedToken, \
            'Accept': "application/json", \
            'Content-Type': "application/json"}
    print("headers : %s" % refreshHeaders)
    
    try:
        response = requests.request("POST", refreshURL, headers=refreshHeaders)
        
        print("Response : %s" % response)
        if (response.status_code == 200):
            return True
        else:
            return False

    except Exception as e:
        self.error_handler(e)
        print("Unable to refresh stream_token")
        return False

'''
def refresh_stream():
    falcon = EventStreams(client_id=g_client_id,
            client_secret=g_client_secret
            )

    PARTITION = 0   #Refresh the partition we are working with

    response = falcon.refresh_active_stream(action_name="refresh_active_stream_session",
            app_id=appId,
            partition=0
            )
    print(response)

    httpCode = response["status_code"]
    print('HTTP Code is : %s' % httpCode)

    if (httpCode == 200):
        return True
    else:
        return False
        print("Unable to refresh stream_token")



def error_handler(self, e):
    traceback.print_exc()
    print(e)



####################################
## BELOW WE LOOK FOR NEW DETECTIONS
####################################

url += "&offset=%s" % offset
        
try:
    epoch_time = int(time.time())
    headers = {'Authorization': 'Token %s' % token, 'Connection': 'Keep-Alive'}
    r = requests.get(url, headers=headers, stream=True)
    #print("Streaming API Connection established. Thread: %s" % id)
    
    
   


    for line in r.iter_lines():
        try:
            if line:
                decoded_line = line.decode('utf-8')

                print("Got a new message, decoding to JSON...")
                decoded_line = json.loads(decoded_line)
                print(decoded_line)


                #if self.was_event_handled(decoded_line):
                #    print("This is not a new event, already handled!")
                #else:
                #print("This is a new event!")
                #metadata_object = decoded_line.get('metadata', {})
                #print('type(metadata_object): %s' % type(metadata_object))
                #print('metadata_object: %s' % metadata_object)
                #isDetectionSummaryEvent = metadata_object.get('eventType')
           
                isDetectionSummaryEvent = decoded_line.get("metadata.eventType")
            
                print("isDetectionSummaryEvent: '%s'" % isDetectionSummaryEvent)
                if (isDetectionSummaryEvent == "DetectionSummaryEvent"):
                    detection_summary_event = decoded_line

                    # Create the alert
                    try:
                        if 'event' in detection_summary_event:
                            new_alert = hive.alert.create(alert=create_alert_object(detection_summary_event["event"]))
                        else:
                            new_alert = hive.alert.create(alert=create_alert_object(detection_summary_event))
                    except TheHiveError as e:
                        print(f"An error occurred: {e.message}")
                        if e.response:
                            print(f"Response status code: {e.response.status_code}")
                            print(f"Response content: {e.response.text}")
                    except Exception as e:
                        print(f"An unexpected error occurred: {e}")


            # Refreshing stream 
            if (int(time.time()) > (900 + epoch_time)):
                print("Event Window Expired, refreshing Token")
                if (refresh_stream()):
                    print("Stream Refresh Succeded")
                    epoch_time = int(time.time())
                #else:
                    # unable to refresh token, start from scratch
                    #return
            
        except Exception as e:
            print("Error reading stream chunk")
            print("request status code %s\n%s" % (r.status_code, traceback.format_exc()))
            
            

except Exception as e:
    print("Error reading last stream chunk")
    print("request status code %s\n%s" % (r.status_code, traceback.format_exc()))
    os._exit(1)


sys.exit(0)






                    
                    
                    
                    
                    
                    
                                  


