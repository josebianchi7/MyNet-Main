# Name: Jose Bianchi 
# Description: Detailed monitoring program with following capability:
#   Perform network discovery by sending ARP (Address Resolution Protocol) 
#   requests to all devices on the local network and collecting responses.
#   Store the list of devices in device library in multiple formats. 
#   Write discovery of devices to a flat File for a local log file.

import time
import asyncio
import scapy.all as scapy
import requests
from datetime import datetime
import json
import textwrap
from credentials import ip_range
from registered_devices import known_devices


def welcome():
    """
    Greeting and navigation function.
    """
    print("\nMyNet\n")
    print("Welcome to the MyNet home network protection program!\n")

    print("*Be advised, pressing the 'Ctrl' key and 'C' key simultaneously will immediately end this program at any point.\n")


def info_help():
    """
    Display Help/ Information data.    
    """
    print("\n\nMyNet\n\nInformation and Resources\n")

    info_message = "Hello, this program is a home network protection tool. "
    info_message += "With this version, you can see devices currently on your network. "
    info_message += "This program will also log network events. "
    info_message += "These network events include when a device connects to your network. "
    info_message += "If an event like this occurs, then the program logs data about the device. "
    info_message += "Users can use the data presented and logged by this program to gain more confidence in their network's security. "
    info_message += "This program may reveal information that motivates the user to enhance their network security measures.\n"

    contact_message = "For further questions or concerns, please contact the developer, "
    contact_message += "Jose Bianchi at bianchjo@oregonstate.edu.\n"
    # Print long string with textwrap to limit words per line
    print(textwrap.fill(info_message, width=70))
    print(textwrap.fill(contact_message, width=70))
    

def read_log(file_path):
    """
    Reads log data.

    :param file_path: location/ name of file to read
    """
    print("\n\nMyNet\n\nLog Report:\n")
    # Open file for read and write
    with open(file_path, 'r') as file:
        all_lines = file.readlines()
        for line in all_lines:
            print(line)
    
    print("--End of Log--")
    # Close file
    file.close()


def discover_devices(ip_range, registered_devices):
    """
    Gets devices on the network.

    :param ip_range (str): range of local network (commonly .1 to .24)
    :param registered_devices (list): list of known devices with name, ip, and mac

    :return devices: list of device information stored as dictionary object
    """
    # Create an ARP request packet to discover devices on the network
    arp_request = scapy.ARP(pdst=ip_range)
    # Create an Ethernet frame to send the ARP request over
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # Combine the Ethernet frame and ARP request
    arp_request_broadcast = broadcast/arp_request
    # Send the packet and capture the response
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    # List to store device info
    devices = []

    # Extract IP and MAC address of each device and store it in a dictionary
    for item in answered_list:
        device_info = {
            "name": "unknown",
            "ip": item[1].psrc,
            "mac": item[1].hwsrc
        }

        # Compare with known devices
        for safe_device in registered_devices:
            if device_info["ip"] == safe_device["ip"] and device_info["mac"] == safe_device["mac"]:
                # When match found, enter known name and break
                device_info["name"] = safe_device["name"]  
                break  

        # Build list with device details      
        devices.append(device_info)
    
    return devices


def print_device_info(devices):
    """
    Prints the device details.

    :param devices: list of devices found.
    """
    # If devices are found, print their details
    if devices:
        # Title format accounting for width of 20 characters for 3 columns 
        print("Devices found on the local network:")
        print("-" * 60)
        print(f"{'Device Name':<20} {'IP Address':<20} {'MAC Address'}")
        print("-" * 60)
        
        for device in devices:
            print(f"{device['name']:<20} {device['ip']:<20} {device['mac']}")
    else:
        print("No devices found on the network.")


def log_devices_to_file(devices, file_path):
    """
    Logs devices to a txt file with a timestamp.

    :param devices: list of devices.
    :param file_path: filename to write data to (filename only if storing in curr directory)
    """
    # Open the file in append mode to log new data
    with open(file_path, "a") as file:
        # Write the timestamp of when the devices were found
        file.write(f"Devices found at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        # Write the device details
        for device in devices:
            file.write(f"{device['name']} {device['ip']} {device['mac']}\n")
        file.write("-" * 60 + "\n")


def send_devices_as_json(devices):
    """
    Sends devices as a JSON object with timestamp

    :param devices: list of devices.

    :return json_data: json object with device list
    """
    # Create a dictionary with device info and timestamp
    device_info_dict = {
        "timestamp": datetime.now().strftime('%Y-%m-%dT%H:%M:%S'),
        "devices": devices,
        "eventDescription": "Device found on network"
    }
    
    # Convert the dictionary to a JSON object for sending in HTTP Post
    json_data = json.dumps(device_info_dict, indent=4)
    
    # Print or send the JSON object (here we are printing for demonstration)
    print("Sending device info as JSON:")
    print(json_data)
    
    # # Store URL of resource (practice server)
    url = 'http://127.0.0.1:5000/send-json' 

    # Send new data via POST request
    response = requests.post(url, json=json_data)

    # Check response from server
    if response.status_code == 200:
        print(f"\nServer Response: {response.json()}")
    else:
        print(f"Failed to send message. Status code: {response.status_code}")
    
    return json_data


def check_for_new_devices(previous_devices, current_devices):
    """
    Checks for new devices by comparing current devices found with stored list.

    :param previous_devices: last recorded list of devices
    :param current_devices: devices currently on network
    """
    # Compare the two device lists and find any new devices
    new_devices = [device for device in current_devices if device not in previous_devices]
    return new_devices


async def network_monitor(prev_devices):
    """
    Runs main functionality to monitor network
    """
    # Path to the log file
    log_file = "devices_log.txt" 

    # Discover devices on the network
    while True:
        print("\n\nMyNet\n\nMonitoring Running\n")
        # Discover devices on the network
        devices = discover_devices(ip_range, known_devices)
        print_device_info(devices)

        # Check if there are new devices to log
        new_devices = check_for_new_devices(prev_devices, devices)
        if new_devices:
            # Log the new devices to the file
            log_devices_to_file(new_devices, log_file)
            
            # # Send the new devices as a JSON object
            # send_devices_as_json(new_devices)
            
            # Update the previous devices list with the current list
            prev_devices = devices
            
        # print_device_info(prev_devices)
        # Wait 2 seconds before checking again
        await asyncio.sleep(2)


async def main():
    """
    Main program.
    """
    p_devices = []
    # Path to the log file
    log_file = "devices_log.txt" 
    # Program running checker   
    monitoring = False

    while True:
        choice = 9
        valid_choices = [0, 1, 2]
        
        # Validate user chooses a number option or do not proceed
        while choice not in valid_choices:
            print("     0) Information/ Help")
            # Change option if monitor function is on/ off
            if monitoring is False:
                print("     1) Turn on MyNet Network Monitoring")
            else:
                print("     1) View Devices Currently On Network")
            print("     2) Open Log Report")
            
            choice = input("\n Enter a listed option number to continue: ")
            # Ensure input is a number
            if choice.isdigit() is False:
                choice = 9
                print("\n Please enter a valid option number\n")
            else:
                choice = int(choice)
    
        # Option 0: Show Help/ Information
        if choice == 0:
            print("\n")
            info_help()

        # Option 1: Main Network Monitoring
        elif choice == 1:
            # Option 1a: Turn on Network Monitoring
            if monitoring is False:
                print("\n\nMyNet\n\nMonitoring is now active.\n")
                monitoring = True
                monitoring_task = asyncio.create_task(network_monitor(p_devices))
            # Option 1b: View Current Devices
            else:
                if monitoring_task.done():
                    monitoring_task = asyncio.create_task(network_monitor(p_devices))

            await asyncio.sleep(1)

        # Option 2: Read Log Report
        elif choice == 2:
            print("\n")
            read_log(log_file)

        time.sleep(1)
        print("\n\nMyNet\n")
            

if __name__ == "__main__":
    welcome()
    asyncio.run(main())
