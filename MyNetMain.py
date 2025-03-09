# Author: Jose Bianchi 
# Description: Detailed monitoring program with following capability:
#   Perform network discovery by sending ARP (Address Resolution Protocol) 
#   requests to all devices on the local network and collecting responses.
#   Store the list of devices in device library in multiple formats. 
#   Write discovery of devices to a flat File for a local log file.

import time
import asyncio
import scapy.all as scapy
from datetime import datetime
import requests
import json
import textwrap
from credentials import ip_range
from credentials import url_post
from credentials import url_get_all
from credentials import url_get_filt
from credentials import url_notify
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
    

def read_local_log(file_path):
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


def post_alert_event(message):
    """
    Sends message to alert system that will log to database 
    and create alert notifications.

    :param message: dictionary object, should include timestamp and eventDescription keys
        Ex:
        message = {
                "timestamp": datetime.now().strftime('%Y-%m-%dT%H:%M:%S'),
                "eventDescription": "event A has occured."
            }
    """
    response = requests.post(url_notify, json=message)
    if response.status_code != 200:
        print(f"Failed to send message. Status code: {response.status_code}")


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
                # When match found, enter known name and end this loop
                device_info["name"] = safe_device["name"]  
                break  
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
            if device['name'] == "Home Router":
                continue
            print(f"{device['name']:<20} {device['ip']:<20} {device['mac']}")
    else:
        print("No devices found on the network.")


def log_event_to_file(event_message):
    """
    Logs message to a txt file.

    :param message: string message.    
    """
    file = "event_log.txt"
    with open(file, "a") as file:
        # Write the timestamp of when the devices were found
        file.write(f"Devices found at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        # Write the device details
        file.write(event_message)
        file.write("-" * 60 + "\n")


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


def get_database_log_all():
    """
    Sends a GET request to database microservice to get all records

    :return json_data: database log
    """   
    print("Retrieving all records from online database log...\n")   
    # Send GET request
    response = requests.get(url_get_all)

    # Check response from server
    if response.status_code == 200:
        # print(f"\nDatabase Log: {response.json()}")
        print("Log retrieved successfully.\n")
    else:
        print(f"Failed to send message. Status code: {response.status_code}\n")
    
    data = response.json()
    # Display log contents with titles
    print("Database Log:")
    print("-" * 60)
    print(f"{'Timestamp':<20} | {'Event Description':<40}")
    print("-" * 60)
    for event in data:
            print(f"{event['timestamp']:<20} | {event['eventDescription']:<40}")


def get_filerted_db_log(start_date, end_date):
    """
    Sends a GET request to database microservice to get 
    records between start_date and end_date, inclusive.

    :param start_date (str): YYYY-MM-DD
    :param end_date (str): YYYY-MM-DD

    :return json_data: filtered database log
    """
    # Format dates
    json_s_date = start_date + "T00:00:00"
    json_e_date = end_date + "T00:00:00"
    message = {
        "startDateTime": json_s_date,
        "endDateTime": json_e_date
    }
    
    # Update URL to have dates in URLS
    url_s_date = "startDateTime=" + json_s_date
    url_e_date = "endDateTime=" + json_e_date
    url_get_filt_final = url_get_filt + url_s_date + "&" + url_e_date

    # Convert the dictionary to a JSON object for sending in HTTP Post
    json_data = json.dumps(message, indent=4)

    # Send GET request for records
    response = requests.get(url_get_filt_final, json=json_data)

    # Check response from server
    if response.status_code == 200:
        # print(f"\nDatabase Log: {response.json()}")
        print(f"Retrieving records from {start_date} to {end_date} from database...\n")  
    else:
        print(f"Failed to send message. Status code: {response.status_code}")

    data = response.json()
    # Display log contents with titles 
    print(f"Database Log From {start_date} to {end_date}:")
    print("-" * 60)
    print(f"{'Timestamp':<20} | {'Event Description':<40}")
    print("-" * 60)
    for event in data:
            print(f"{event['timestamp']:<20} | {event['eventDescription']:<40}")


def check_for_new_devices(previous_devices, current_devices):
    """
    Checks for new devices by comparing current devices found with stored list.
    Creates alert event for log and notification service if unknown device found.

    :param previous_devices: last recorded list of devices
    :param current_devices: devices currently on network
    """
    new_devices = []
    for device in current_devices:
        if device not in previous_devices:
            new_devices.append(device)
            # Save event and send event alert for unkown devices on network
            if device["name"] == "unknown":
                unknown_ip = device["ip"]
                unknown_mac = device["mac"]
                event_msg = f"Unknown device detected on network. Device IP: {unknown_ip}, Device MAC: {unknown_mac}"
                log_event_to_file(event_msg)
                message = {
                "timestamp": datetime.now().strftime('%Y-%m-%dT%H:%M:%S'),
                "eventDescription": f"Unknown device detected on local network. Device IP: {unknown_ip}"
                }
                post_alert_event(message)

    return new_devices


async def network_monitor(prev_devices):
    """
    Runs main functionality to monitor network
    """
    log_file = "devices_log.txt" 

    # Discover devices on the network
    while True:
        print("\n\nMyNet\n\nMonitoring Running\n")
        devices = discover_devices(ip_range, known_devices)
        print_device_info(devices)

        new_devices = check_for_new_devices(prev_devices, devices)
        if new_devices:
            log_devices_to_file(new_devices, log_file)
            prev_devices = devices
            
        await asyncio.sleep(2)


async def main():
    """
    Main program.
    """
    p_devices = []
    # Program running checker   
    monitoring = False

    while True:
        choice = 9
        valid_choices = [0, 1, 2, 3]
        
        # Validate user chooses a number option or do not proceed
        while choice not in valid_choices:
            print("     0) Information/ Help")
            # Change option if monitor function is on/ off
            if monitoring is False:
                print("     1) Turn on MyNet Network Monitoring")
            else:
                print("     1) View Devices Currently On Network")
            print("     2) View Log Report for Specific Timeframe")
            print("     3) View Complete Log")
            
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

        # Option 2: Get Specific Time Window Log Report
        elif choice == 2:
            print("\n")
            print("To see the log for a specific time window, you will need to enter a start and end date.")
            print("Please format dates as YYYY-MM-DD.")
            date1 = input("Start Date: ")
            date2 = input("End Date: \n")
            get_filerted_db_log(date1, date2)
        
        # Option 3: Get complete Log
        elif choice == 3:
            get_database_log_all()


        time.sleep(1)
        print("\n\nMyNet\n")
            

if __name__ == "__main__":
    welcome()
    asyncio.run(main())
