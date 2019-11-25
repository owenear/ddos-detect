# DDoS-detect
DDoS detection tool based on a flow-tools data.
It uses flow-capture, flow-report, flow-nfilter, flow-print from flow-tools package to analyse NetFlow data and detects possible DDoS attack.
If DDoS attack is occurred it sends e-mail with victim's ip-address.

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
1. DDoS-detect uses four flow-report profiles to detect abnormal traffic (the profiles are described in a report.conf file) You can configure 'threshold's for this profiles based on your traffic activity and network device sampling options or left them default. 'key_field' - is a report field index number to which the threshold applies (you don't have to change it for predefined profiles).
    ```
    RULES = {
        'sdport_flows': {
                'treshold':300,
                'key_field': 4
                },
        'dport_packets': {
                'treshold':3000,
                'key_field':3
                },
        'flows': {
                'treshold':2000,
                'key_field': 2
                },
        'packets':{
                'treshold':5000,
                'key_field': 2
                },
        }
    ```

2. DDoS-detect uses flow-nfilter profile 'white-list' for a white list ip addresses (described in filter.cfg file).
You can add deny terms (ip or net in a format X.X.X.X/XX) to this filter to bypass DDoS-detection for them.
    ```
    filter-primitive white-list
      type ip-address-prefix
      deny 8.8.8.8
      deny 10.0.0.0/8
      default permit
    
    filter-definition white-list
      match ip-destination-address white-list
      match ip-source-address white-list
    ```
3. Configure some dir and e-mail options
    ```
    # Dir with flow-tools binary files
    BIN_DIR = '/usr/local/bin/'
    
    # Dir with flow-capture data
    FLOW_DIR = '/var/flows/'
    
    # E-mail options
    MAIL_FROM = 'example@domain.com'
    MAIL_TO = 'example@domain.com'
    ```
4. Put script to a cron to execute it every minute


## Authors

* **Evgeniy Kolosov** - [owenear](https://github.com/owenear)
