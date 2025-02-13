#!/usr/bin/python3
import requests
import time
import urllib3
import os
from datetime import datetime

# Suppress InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

## Device variables
fortigate_api_token = os.getenv("FORTIGATE_API_TOKEN")
fortigate_ip = os.getenv("FORTIGATE_IP")
fortigate_port = os.getenv("FORTIGATE_PORT")
fortigate_vdom = os.getenv("FORTIGATE_VDOM")

## Interface variables
vpn_interface = os.getenv("VPN_INTERFACE")

## Policy variables
policy_number = os.getenv("POLICY_NUMBER")

## API session
apisession = requests.session()

## API prefix
default_api_prefix = f'https://{fortigate_ip}:{fortigate_port}/api/v2'

## VPN API prefix
vpn_api_prefix = f'{default_api_prefix}/monitor/vpn/ipsec'

## API header
api_header = {
    'Accept': 'application/json',
    'Authorization': f'Bearer {fortigate_api_token}'
}

## Store the last known VPN status
last_vpn_status = None

## Logging function with timestamp
def log_message(message):
    timestamp = datetime.now().strftime('%D-%M-%Y %H:%M:%S')
    print(f"[{timestamp}] {message}")

## Function to check VPN status (Explicit UP or DOWN check)
def interface_status_function(interface_name, api_url):
    try:
        response = apisession.get(api_url, headers=api_header, verify=False)
        response.raise_for_status()
        data = response.json()

        for result in data.get('results', []):
            for proxy in result.get('proxyid', []):
                if proxy['p2name'] == interface_name:
                    status = proxy.get('status', 'unknown')  # Get status, default to 'unknown'
                    if status == 'up':
                        return True
                    elif status == 'down':
                        return False

        log_message(f"VPN interface {interface_name} not found in API response or missing status field")
        
    except requests.RequestException as e:
        log_message(f"Error fetching VPN status: {e}")
    
    return False  # Default to 'down' if we can't determine status

## Function to change PBR (Policy-Based Routing)
def change_pbr_status(status):
    api_url = f"{default_api_prefix}/cmdb/router/policy/{policy_number}?scope=vdom&vdom={fortigate_vdom}"
    api_body = {"seq-num": 1, "status": status}
    
    try:
        response = apisession.put(api_url, json=api_body, headers=api_header, verify=False)
        response.raise_for_status()
        log_message(f"Policy {policy_number} set to {status}")
    except requests.RequestException as e:
        log_message(f"Error updating PBR policy: {e}")

## Check VPN status in a loop
while True:
    vpn_status = interface_status_function(vpn_interface, vpn_api_prefix)

    if last_vpn_status is None:
        log_message(f"Initial VPN status: {'UP' if vpn_status else 'DOWN'}")
    elif last_vpn_status != vpn_status:
        if vpn_status:
            log_message("VPN transitioned to UP - Enabling PBR")
            change_pbr_status("enable")
        else:
            log_message("VPN transitioned to DOWN - Disabling PBR")
            change_pbr_status("disable")
    
    last_vpn_status = vpn_status
    time.sleep(5)  # Adjust polling interval as needed