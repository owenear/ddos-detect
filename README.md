# DDoS-detect
NetFlow data based DDoS detection tool.
It uses flow-capture, flow-report, flow-nfilter, flow-print from flow-tools package to analyse NetFlow data and detects possible DDoS attack.
If DDoS attack is occurred it sends an e-mail with victim's ip-address.

### Prerequisites
Linux or FreeBSD, Python 3.6

1. Configure NetFlow v5/v8 on a network device.
2. Install and configure flow-tools on a server.
```
apt-get install flow-tools
```
or
```
cd /usr/ports/net-mgmt/flow-tools
make install clean
```

### Installation
Configure some settings in the 'config.ini' file.
1. Specify the location of the binary and NetFlow statistics files.
    ```
    [FILES]
    FlowToolsBinDir = /usr/local/bin/
    WhoisBinDir = /usr/bin/
    FlowsDir = /var/db/flows/
    ```
2. Configure email settings.
    ```
    [EMAIL]
    SMTPServer = localhost
    MailFrom = mail@example.com
    MailTo = mail@example.com
    ```   
3. DDoS-detect uses four flow-report profiles to detect abnormal traffic (the profiles are described in a reports.cfg file by default). Configure 'threshold's for this profiles based on your traffic activity and network device sampling options or left them default. You can add/remove profiles and configure options for them in the 'REPORTS' section config.ini file.
    ```
    [REPORTS]
    sdport_flows
    dport_packets
    flows
    packets

    [sdport_flows]
    threshold = 300
    key_field = 4
    filter = white-list
    
    [dport_packets]
    threshold = 3000
    key_field = 3
    filter = white-list
    
    [flows]
    threshold = 1500
    key_field = 2
    filter = white-list
    
    [packets]
    threshold = 5000
    key_field = 2
    filter = white-list
    ```
- 'key_field' is a report field index number to which the threshold applies (you don't have to change it for predefined profiles).
- 'filter' is a name of a filter described in filters.cfg file. It is used for the pre-filter flow statistic before the flow-report profile is applied. By default DDoS-detect uses 'white-list' filter for the all reports. You can add deny terms (ip or net in a format X.X.X.X/XX) to this filter to bypass DDoS-detection for them.
    ```
    filter-primitive white-list-ip
      type ip-address-prefix
      deny 8.8.8.8
      deny 64.233.160.0/19
      default permit
    
    filter-definition white-list
      match ip-destination-address white-list-ip
      match ip-source-address white-list-ip
    ```
You can create your own reports and filters. You can change the filter for each report individually.
Use 'man flow-nfilter' and 'man flow-report' to read more about it. 


After that put script to a cron to execute it every minute


## Authors

* **Evgeniy Kolosov** - [owenear](https://github.com/owenear)
