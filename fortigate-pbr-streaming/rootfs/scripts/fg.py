#!/usr/bin/python3
import requests
import time
import urllib3
import os

# Suppress only the single InsecureRequestWarning from urllib3 needed
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
    'Accept': 'application/json',  # Specify API format
    'Authorization': f'Bearer {fortigate_api_token}'  # Specify Bearer token
}

## API Interface check Function
def interface_status_function(interface_name, api_url):
    try:
        response = apisession.get(api_url, headers=api_header, verify=False)
        response.raise_for_status()
        data = response.json()
        
        ## If type is VPN
        for result in data.get('results', []):
            for proxy in result.get('proxyid', []):
                if proxy['p2name'] == interface_name:
                    return proxy['status'] == 'up'
        
                
    ## Throw error
    except requests.RequestException as e:
        print(f"An error occurred: {e}")
    return False

## Function to change PBR (Policy-Based Routing)
def change_pbr_status(status):
    api_url = f"{default_api_prefix}/cmdb/router/policy/{policy_number}&vdom={fortigate_vdom}"
    api_body = {
        "seq-num": 1,
        "status": status
    }
    apisession.put(api_url, json=api_body, headers=api_header, verify=False)

## Check if VPN is up
while True:
    vpn_status = interface_status_function(vpn_interface, vpn_api_prefix)
    
    if vpn_status: ## VPN up
        change_pbr_status("enable") ## Set PBR status to enable

    else: ## VPN down
        change_pbr_status("disable") ## Set PBR status to disable
    
    time.sleep(2)