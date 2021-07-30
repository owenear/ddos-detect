# DDoS-detect
NetFlow data based DDoS detection tool.
It uses nfdump package to analyse NetFlow data and detects possible DDoS attack.
If DDoS attack is occurred it sends an e-mail with victim's ip-address.

### Prerequisites
Linux or FreeBSD, Python > 3.6
NFDUMP

1. Configure NetFlow (v5/v9/ipfix) on a network device with active timeout 60 sec (see the v5 version JunOS config example below).
```
forwarding-options {
    sampling {
        input {
            rate 2000;
            run-length 0;
        }
        family inet {
            output {
                flow-inactive-timeout 15;
                flow-active-timeout 60; 
                flow-server 10.0.0.10 {
                    port 9999;
                    autonomous-system-type origin;
                    source-address 10.0.0.1;
                    version 5;
                }
            }
        }
    }
}
```
2. Install nfdump on a server and configure it to rotate files every minute (see options example below)
```
options='-z -t 60 -w -D -T all -l /var/db/flows/ -I any -S 1 -P /var/run/nfcapd.allflows.pid -p 9999 -b 10.0.0.10 -e 10G'
```

### Installation
Configure some settings in the 'config.ini' file.
1. Check the log options
```
[SYSTEM]
LogDir = /var/log/
# log file size in bytes
LogFileSize = 50000
```
Create the log file 'LogDir'/ddos-detect.log and be sure it's writable by the user that’s running the DDoS-detect.

2. Specify the location of the binary and NetFlow statistics files.
```
[FILES]
NfdumpBinDir = /usr/local/bin/
SysBinDir = /usr/bin/
FlowsDir = /var/db/flows/
```
3. Configure email settings.
```
[EMAIL]
SMTPServer = localhost
MailFrom = mail@example.com
MailTo = mail@example.com
```   
4. DDoS-detect uses four report profiles to detect abnormal traffic. Configure 'threshold's for this profiles based on your traffic activity and network device sampling options or left them default. You can change set of the current working profiles and configure options for them in the 'REPORTS' section config.ini file.
```
[REPORTS]
sdport_flows
dport_packets
flows
packets

[sdport_flows]
threshold = 300
key_field = 4
    
[dport_packets]
threshold = 3000
key_field = 3
    
[flows]
threshold = 1500
key_field = 2
    
[packets]
threshold = 5000
key_field = 2
```
- 'key_field' is a report field index number to which the threshold applies (you don't have to change it).
5. Check the IP WhiteList ACL filename
```
[FILES]
# White List ACL
IpWhiteListFile = ip-white-list.txt
```
And add to the file IP addresses you want to exclude from DDoS-detection (or leave file blank)
```
# Add local ip/net to exclude it from checking on DDoS
127.0.0.1
127.0.0.0/8
```

6. After that put script to a cron to execute it every minute. 


## Authors

* **Evgeniy Kolosov** - [owenear](https://github.com/owenear)
