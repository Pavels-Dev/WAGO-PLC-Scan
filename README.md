# WAGO-PLC-Scan
This is a Nmap dissector that tries to detects and extracts key information about WAGO programmable logic controllers (PLCs) during network scans. It identifies WAGO PLCs, gathers details like device type, firmware version, hardware, and serialnumbers, enhancing network reconnaissance capabilities.
## Instalation
Download the .nse file
Nmap scripts should be placed in the Nmap scripts directory. The location of this directory varies depending on your operating system:
- Linux and macOS: Usually, it's located at /usr/local/share/nmap/scripts/ or /usr/share/nmap/scripts/, depending on how Nmap was installed.
## Usage
To use the script you need to run it as sudo enter give it the interface as a argument and scan for the port 6626
```bash
sudo nmap --script wago-scan.nse --script-args interface=eth0
```
## Example Output
```bash
PORT     STATE SERVICE
6626/tcp open  wago-service
| Wago Scan: 
|   
|     Device: WAGO 750-8202 PFC200 2ETH RS
|   
|     Hardware_Version: 06
|   
|     Serial_Number: X
|   
|     Software_Version: 02.08.24(11)
|   
|     Firmware_Loader_Version: 2014.11.0-w02.02.03 IDX 4
|   
|     Baud: 100MBaud
|   
|     Firmware_Burn_Date: 0000
|   
|_    QS_String: 0000
MAC Address: 00:30:DE:42:AD:53 (Wago Kontakttechnik Gmbh)
```

## Disclaimer:

This tool is designed for information technology security purposes only. It should be used exclusively on networks and systems where explicit authorization has been obtained. Unauthorized scanning of networks and systems is illegal and unethical. Users must ensure they have written permission from the rightful owners of the systems to be scanned. We are not responsible for any misuse of this tool, nor for any consequences that result from such misuse. It is the user's responsibility to adhere to all applicable laws and regulations related to network scanning and data security. Use this tool at your own risk.

## Tested on
- WAGO 750-8202 PFC200
