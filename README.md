
# MyNet

#### This project is a network security program that uses various technologies to conduct common network security tasks. 


## Acknowledgements

- [Address Resolution Protocol (ARP): How it works.](https://www.geeksforgeeks.org/how-address-resolution-protocol-arp-works/)
- [Flask: Python ](https://flask.palletsprojects.com/en/stable/installation/#install-flask)
- [Npcap: The Nmap Project's packet capture (and sending)](https://npcap.com/)
- [Scapy: Packet manipulation library written in Python.](https://github.com/secdev/scapy)


## Authors

- [@josebianchi7](https://github.com/josebianchi7)


## Deployment

To deploy this project, the following is required:

1. Download and Install Npcap (https://npcap.com/#download).

2. Install necessary Python libraries (if not already installed):

```bash
  $ pip install flask
```
```bash
  $ pip install scapy
```
3. run main program (MyNetMain.py)
```bash
  $ python MyNetMain.py
```

4. To use full functionality, must be have OSU VPN turned on, and get URLs for database queuries or set up own database and replace the following URLs in MyNetMain.py:
```
url_post
url_get_all
url_get_filt
```
Alternatively, can use local log file only and omit functions that interact with a database. Functions in MyNetMain.py that interact with database:
```
send_devices_as_json(devices)
get_database_log_all()
get_filerted_db_log(start_date, end_date)
```


## Available Functionality and Features
### 1. Detect and Discover Devices on Local Network. 
Devices identified by IP Address and MAC Address. Recommend creating private file, called registered_devices.py, and storing list called known_devices. This list should contain
dictionary objects with commonly connected devices in the following format:
```
device1 = {
    "name": "My Phone",
    "ip": "XXX.XXX.X.XXX",
    "mac": "xx:xx:xx:xx:xx:xx"
}
```

### 2. Log Connection Events and Retrieve Log
When a device connects to your network, the program will send a timestamp and event description to a database. Users can retrieve data from the database using desired dates to filter log report. As a back up, there is a local log file created and updated as well. I recommend turning off the function to write to local log file if concerned about storage or find this feature unnecessary. To prevent program from writing to local log file, go to the function below in MyNetMain.py:
```
network_monitor(prev_devices)
```
Look for the log to file function call:
```
log_devices_to_file(new_devices, log_file)
```
Then either comment or remove this fucntion call.
