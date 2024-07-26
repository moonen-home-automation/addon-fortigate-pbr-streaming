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

## Interface variables
wan_interface = os.getenv("WAN_INTERFACE")
vpn_interface = os.getenv("VPN_INTERFACE")

## Policy variables
policy_number = os.getenv("POLICY_NUMBER")

## API session
apisession = requests.session()

## API prefix
default_api_prefix = f"https://{fortigate_ip}:{fortigate_port}/api/v2"

## Interface API prefix
interface_api_prefix = f"{default_api_prefix}/monitor/system/available-interfaces?"

## VPN API prefix
vpn_api_prefix = f"{default_api_prefix}/monitor/vpn/ipsec"

## API header
api_header = {
    "Accept": "application/json",  # Specify API format
    "Authorization": f"Bearer {fortigate_api_token}",  # Specify Bearer token
}


## API Interface check Function
def interface_status_function(interface_name, api_url, connection_type):
    try:
        response = apisession.get(api_url, headers=api_header, verify=False)
        response.raise_for_status()
        data = response.json()

        ## If type is VPN
        if connection_type == "proxyid_status":
            for result in data.get("results", []):
                for proxy in result.get("proxyid", []):
                    if proxy["p2name"] == interface_name:
                        return proxy["status"] == "up"

        ## If type is WAN
        else:
            for result in data.get("results", []):
                if result["name"] == interface_name:
                    return result.get(connection_type, "down") == "up"

    ## Throw error
    except requests.RequestException as e:
        print(f"An error occurred: {e}")
    return False


## Function to change PBR (Policy-Based Routing)
def change_pbr_outgoing_interface(new_interface):
    api_url = f"{default_api_prefix}/cmdb/router/policy/{policy_number}"
    api_body = {
        "seq-num": policy_number,
        "output-device": new_interface,
        "status": "enable",
    }
    response = apisession.put(api_url, json=api_body, headers=api_header, verify=False)
    if response.status_code == 200:
        print(f"Successfully changed PBR to {new_interface}.")
    else:
        print(
            f"Failed to change PBR to {new_interface}. Status code: {response.status_code}, Response: {response.text}"
        )


## Main loop to check interfaces
while True:
    wan_status = interface_status_function(wan_interface, interface_api_prefix, "link")
    vpn_status = interface_status_function(
        vpn_interface, vpn_api_prefix, "proxyid_status"
    )

    if vpn_status:  ## VPN up
        ## // Create API request to set policy based routing to VPN S2S-Heusden
        print("VPN up")
        change_pbr_outgoing_interface(vpn_interface)

    else:  ## VPN down
        ## // Create API request to set policy based routing to KPN-PPPoE if KPN-PPPoE is up
        print("VPN down")

        if wan_status:  ## is up?
            ## Change PBR outgoing interface
            print("WAN up")
            change_pbr_outgoing_interface(wan_interface)

        else:
            ## Do nothing
            print("WAN down")

    time.sleep(5)
