# Welcome to Albatross
## Your personal DNS attack monitor.

### Technical Requirements
Currently, Albatross is designed for Mac computers, as it uses the network interface 'en0'
If you are running a non-Mac computer, you can specify the interface within the albatross_monitor.py's
main function with your device's network interface.

### Please install the following packages:
```
sudo pip3 install scapy
pip3 install dnspython
pip install matplotlib
```

### Usage
In order to use Albatross, you can run the following command to check and validate 100 packets by default.

Start by running:
```
python3 albatross_monitor.py
```

Then, continue using the internet normally, searching common websites or websites that you are worried may be being attacked. Albatross will then take a look at the first 100 packets, validating DNS queries, and it will present a chart of any DNS responses that were considered 'untrusted.' 

You may also run Albatross on more packets by running the following command, inputting an integer value for num_of_packets:
```
python3 albatross_monitor.py num_of_packets
```