#!/usr/bin/env python3

from falconpy import EventStreams
from falconpy import OAuth2
import json
import time
import datetime
import requests
import os
import sys
import logging
import threading
import traceback
import re
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from thehive4py import TheHiveApi
from thehive4py.types.alert import InputAlert
from thehive4py.errors import TheHiveError


# TheHive supported observable types
THEHIVE_OBSERVABLE_TYPES = {
    "autonomous-system",
    "cve",
    "domain",
    "file",
    "filename",
    "fqdn",
    "hash",
    "hostname",
    "ip",
    "mail",
    "mail-subject",
    "other",
    "regexp",
    "registry",
    "uri_path",
    "url",
    "user-agent",
}


def safe_observable(dataType, data, tags=None):
    """Map unknown types to 'other', preserve intent in tags."""
    tags = tags or []
    # Always use "ip" for both IPv4 and IPv6, and add tag if IPv6
    if dataType in ("ip", "ipv6", "ipv4"):
        dataType = "ip"
        if ":" in str(data) and "ipv6" not in tags:
            tags.append("ipv6")
    if dataType not in THEHIVE_OBSERVABLE_TYPES:
        tags = tags + [dataType]
        dataType = "other"
    return {"dataType": dataType, "data": data, "tags": tags}


def is_mitre_attack_id(val):
    return bool(re.fullmatch(r"T\d{4}(\.\d{3})?", str(val)))


def create_alert_detection(data):
    metadata = data.get("metadata", {})
    event = data.get("event", data)
    eventType = data.get("type", "external")
    source = "CrowdStrike"

    severity_mapping = {
        "informational": 1,
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }

    detection_name = (
        event.get("DetectName")
        or event.get("Name")
        or data.get("display_name")
        or "No Title"
    )
    description_field = (
        event.get("DetectDescription")
        or event.get("Description")
        or data.get("description")
        or ""
    )
    severity_name = (
        event.get("SeverityName") or data.get("severity_name") or ""
    ).capitalize() or "Informational"
    severity_value = event.get("Severity") or data.get("severity") or 1
    # Normalize large CrowdStrike severity to TheHive (1–4)
    if isinstance(severity_value, int) and severity_value > 4:
        if severity_value >= 80:
            adjustedSeverity = 4
        elif severity_value >= 70:
            adjustedSeverity = 3
        elif severity_value >= 50:
            adjustedSeverity = 2
        else:
            adjustedSeverity = 1
    else:
        adjustedSeverity = severity_mapping.get(severity_name.lower(), 1)

    eventTimestamp = (
        event.get("EventCreationTime")
        or event.get("eventCreationTime")
        or event.get("ProcessStartTime")
        or metadata.get("eventCreationTime")
        or data.get("timestamp")
        or int(time.time() * 1000)
    )
    if isinstance(eventTimestamp, str):
        try:
            eventTimestamp = int(eventTimestamp)
        except Exception:
            eventTimestamp = int(time.time() * 1000)

    falcon_link = event.get("FalconHostLink") or data.get("falcon_host_link") or ""
    sourceRef = (
        event.get("DetectId")
        or event.get("CompositeId")
        or data.get("id")
        or str(time.time())
    )
    hostname = (
        event.get("Hostname")
        or event.get("ComputerName")
        or event.get("hostname")
        or "Unknown Host"
    )
    technique = event.get("Technique", "").strip() or "Unknown Technique"

    # MITRE only if valid ATT&CK ID
    mitreTags = []
    if "technique_id" in data and is_mitre_attack_id(data["technique_id"]):
        mitreTags.append(data["technique_id"])
    if "Technique" in event and is_mitre_attack_id(event["Technique"]):
        mitreTags.append(event["Technique"])

    tags = ["CrowdStrike"] + mitreTags

    # Observables
    observables = []
    # Hashes
    hashes = [
        ("MD5String", "md5", "md5"),
        ("SHA256String", "sha256", "sha256"),
        ("SHA1String", "sha1", "sha1"),
    ]
    for cs_field, flat_field, tag in hashes:
        value = event.get(cs_field) or data.get(flat_field)
        if (
            value
            and value != "N/A"
            and value != "0000000000000000000000000000000000000000"
        ):
            observables.append(safe_observable("hash", value, [tag]))

    # Filename and file path
    filename = event.get("FileName") or data.get("filename")
    filepath = event.get("FilePath") or data.get("filepath")
    if filename:
        tags_fp = [filepath] if filepath else []
        observables.append(safe_observable("filename", filename, tags_fp))
    if filepath:
        observables.append(safe_observable("other", filepath, ["filepath"]))

    # CommandLine
    cmdline = event.get("CommandLine") or data.get("cmdline")
    if cmdline:
        observables.append(safe_observable("other", cmdline, ["cmdline"]))

    # Host/Network
    computername = event.get("ComputerName") or event.get("Hostname")
    if computername:
        observables.append(safe_observable("hostname", computername))
    machinedomain = event.get("MachineDomain") or event.get("LogonDomain")
    if machinedomain and computername:
        fqdn = f"{computername}.{machinedomain}"
        observables.append(safe_observable("fqdn", fqdn, ["machine-domain"]))

    # Local IPs
    local_ip = event.get("LocalIP") or event.get("LocalIPv6")
    if local_ip:
        observables.append(safe_observable("ip", local_ip, ["local-ip"]))

    # MAC
    mac = event.get("MACAddress")
    if mac:
        observables.append(safe_observable("other", mac, ["mac"]))

    # User
    user = event.get("UserName") or data.get("user_name")
    if user:
        observables.append(safe_observable("other", user, ["username"]))

    # IOC Value(s)
    ioc_type = event.get("IOCType")
    ioc_value = event.get("IOCValue")
    if ioc_type and ioc_value:
        for val in str(ioc_value).split(","):
            dtype = "hash" if "hash" in ioc_type else ioc_type.lower()
            observables.append(safe_observable(dtype, val.strip()))

    # NetworkAccesses
    for net in event.get("NetworkAccesses", []):
        for ip_field in ["LocalAddress", "RemoteAddress"]:
            ip = net.get(ip_field)
            if ip:
                tag = f"{ip_field.lower()}:{net.get('Protocol','')}"
                observables.append(safe_observable("ip", ip, [tag]))
        for port_field in ["LocalPort", "RemotePort"]:
            port = net.get(port_field)
            if port:
                observables.append(
                    safe_observable("other", str(port), [port_field.lower()])
                )
        proto = net.get("Protocol")
        if proto:
            observables.append(safe_observable("other", proto, ["protocol"]))

    # DnsRequests
    for dns in event.get("DnsRequests", []):
        domain = dns.get("DomainName")
        if domain:
            observables.append(safe_observable("domain", domain))
        reqtype = dns.get("RequestType")
        if reqtype:
            observables.append(safe_observable("other", reqtype, ["dns_query_type"]))

    # Title
    title = f"[{severity_name}] Detection on {hostname}: {technique} - {detection_name}"

    # Description
    description = description_field.strip()
    if description:
        description += "\n\n"
    description += f"[Link to CrowdStrike Alert]({falcon_link})\n\n"
    description += f"```json\n{json.dumps(data, indent=4)}\n```"

    # Procedures (only valid mitre att&ck techniques IDs)
    procedures = []
    for tag in mitreTags:
        procedures.append({"patternId": tag, "occurDate": eventTimestamp})

    input_alert: InputAlert = {
        "type": eventType,
        "source": source,
        "sourceRef": sourceRef,
        "title": title,
        "severity": adjustedSeverity,
        "description": description,
        "date": eventTimestamp,
        "observables": observables if observables else [],
        "tags": tags,
    }
    if procedures:
        input_alert["procedures"] = procedures
    return input_alert


def refresh_stream():
    # Define the custom header
    extra_headers = {"User-Agent": "strangebee-thehive/1.0"}

    # Initialize the EventStreams service class with custom headers
    auth = OAuth2(
        client_id=CRWD_CLIENT_ID,
        client_secret=CRWD_CLIENT_SECRET,
        base_url=CRWD_BASE_URL,
    )
    falcon = EventStreams(auth_object=auth, ext_headers=extra_headers)

    PARTITION = 0  # Refresh the partition we are working with

    response = falcon.refresh_active_stream(
        action_name="refresh_active_stream_session", app_id=appId, partition=0
    )
    print(response)

    httpCode = response["status_code"]
    print("HTTP Code is : %s" % httpCode)

    if httpCode == 200:
        return True
    else:
        return False
        print("Unable to refresh stream_token")


def error_handler(self, e):
    traceback.print_exc()
    print(e)


if __name__ == "__main__":
    # set offset high to only get new events.
    offset = 999999999
    # offset = 1

    CRWD_BASE_URL = os.environ.get(
        "CRWD_BASE_URL", "https://api.crowdstrike.com"
    )  # Also supports short region names : US-1, US-2, EU-1, US-GOV-1
    CRWD_CLIENT_ID = os.environ.get("CRWD_CLIENT_ID")
    CRWD_CLIENT_SECRET = os.environ.get("CRWD_CLIENT_SECRET")
    THEHIVE_URL = os.environ.get("THEHIVE_URL", "http://127.0.0.1:9000")
    THEHIVE_API_KEY = os.environ.get("THEHIVE_API_KEY")
    THEHIVE_ORG = os.environ.get("THEHIVE_ORG", None)
    appId = os.environ.get("APP_ID", "falcon2thehive")

    if not CRWD_CLIENT_ID or not CRWD_CLIENT_SECRET:
        print(
            "ERROR: CRWD_CLIENT_ID or CRWD_CLIENT_SECRET environment variable not set."
        )
        sys.exit(1)
    if not THEHIVE_API_KEY:
        print("ERROR: THEHIVE_API_KEY environment variable not set.")
        sys.exit(1)

    ## INIT - TH & CRWD

    hive = TheHiveApi(url=THEHIVE_URL, apikey=THEHIVE_API_KEY, organisation=THEHIVE_ORG)

    # Define the custom header
    extra_headers = {"User-Agent": "strangebee-thehive/1.0"}

    # Initialize the EventStreams service class with custom headers
    auth = OAuth2(
        client_id=CRWD_CLIENT_ID,
        client_secret=CRWD_CLIENT_SECRET,
        base_url=CRWD_BASE_URL,
    )
    falcon = EventStreams(auth_object=auth, ext_headers=extra_headers)

    response = falcon.list_available_streams(app_id=appId, format="flatjson")
    dump = json.dumps(response, sort_keys=True, indent=4)
    # print(dump)    #DEBUG

    response2use = str(response).replace("'", '"')
    load = json.loads(response2use)

    resources = load.get("body", {}).get("resources")
    if not resources:
        errors = load.get("body", {}).get("errors")
        if errors:
            print("\nCrowdStrike API Error:")
            for err in errors:
                print(f" - Code: {err.get('code')}, Message: {err.get('message')}")
            print("\nTroubleshooting tips:")
            print(
                "- Check your CRWD_CLIENT_ID and CRWD_CLIENT_SECRET are correct and valid."
            )
            print(
                "- Check your CRWD_BASE_URL matches your Falcon console region (US-1, EU-1, etc)."
            )
            print(
                "- Make sure your API client has the necessary permissions (at least Event streams: Read)."
            )
            print("- If you just created credentials, wait a few minutes and retry.")
            sys.exit(1)
        print("ERROR: No 'resources' key found in CrowdStrike API response!")
        print("Full response below for debugging:")
        print(json.dumps(load, indent=2))
        sys.exit(1)

    for i in resources:
        print("Data Feed URL : " + i["dataFeedURL"])
        print("Generated Token : " + i["sessionToken"]["token"])
        dataFeedURL = i["dataFeedURL"]
        generatedToken = i["sessionToken"]["token"]
        refreshURL = i["refreshActiveSessionURL"]

    # Below variables are created for compatibility reasons
    url = dataFeedURL
    token = generatedToken

    url += "&offset=%s" % offset

    try:
        epoch_time = int(time.time())
        headers = {"Authorization": "Token %s" % token, "Connection": "Keep-Alive"}
        r = requests.get(url, headers=headers, stream=True)
        # print("Streaming API Connection established. Thread: %s" % id)

        for line in r.iter_lines():
            try:
                if line:
                    decoded_line = line.decode("utf-8")
                    print("Got a new message, decoding to JSON...")
                    decoded_line = json.loads(decoded_line)
                    print(decoded_line)

                    # Support all event types in a dispatcher
                    event_type = decoded_line.get("metadata.eventType") or (
                        decoded_line.get("metadata", {}) or {}
                    ).get("eventType")
                    print("event_type: '%s'" % event_type)
                    event_payload = decoded_line.get("event", decoded_line)

                    try:
                        if event_type in (
                            "DetectionSummaryEvent",
                            "EppDetectionSummaryEvent",
                        ):
                            new_alert = hive.alert.create(
                                alert=create_alert_detection(event_payload)
                            )
                        else:
                            print(f"Unsupported event_type: {event_type}")
                            continue
                    except TheHiveError as e:
                        print(f"An error occurred: {e.message}")
                        if e.response:
                            print(f"Response status code: {e.response.status_code}")
                            print(f"Response content: {e.response.text}")
                    except Exception as e:
                        print(f"An unexpected error occurred: {e}")

                # Refreshing stream
                if int(time.time()) > (900 + epoch_time):
                    print("Event Window Expired, refreshing Token")
                    if refresh_stream():
                        print("Stream Refresh Succeded")
                        epoch_time = int(time.time())

            except Exception as e:
                print("Error reading stream chunk")
                print(
                    "request status code %s\n%s"
                    % (r.status_code, traceback.format_exc())
                )

    except Exception as e:
        print("Error reading last stream chunk")
        print("request status code %s\n%s" % (r.status_code, traceback.format_exc()))
        os._exit(1)

    sys.exit(0)
