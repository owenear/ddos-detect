import os
import subprocess
from datetime import datetime, timedelta
from smtplib import SMTP_SSL, SMTP
from configparser import ConfigParser
import re
import logging.handlers
from pathlib import Path


# Load and Check Config 
if os.path.exists(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'config.ini')):
    config = ConfigParser(allow_no_value=True)
    config.read(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'config.ini'))
else:
    print("ERROR: Configuration file 'config.ini' not found!")
    exit(1)

try:
    LOG_FILE = os.path.join(config['SYSTEM']['LogDir'], 'ddos-detect.log')
    LOG_FILE_SIZE = int(config['SYSTEM']['LogFileSize'])
    CODE = config['SYSTEM']['code']
    # AWK
    AWK = os.path.join(config['FILES']['SysBinDir'], 'awk')
    # Reports options
    REPORTS = {}
    for key in config['REPORTS']:
        REPORTS.update({key:{}})
        REPORTS[key].update({'threshold': int(config[key]['threshold'])})
        REPORTS[key].update({'key_field': int(config[key]['key_field'])})

    NFDUMP = os.path.join(config['FILES']['NfdumpBinDir'], 'nfdump')
    FLOWS_DIR = config['FILES']['FlowsDir']
    FLOW_REC_AMOUNT = config['EMAIL']['FlowRecAmount']
    IP_WHITE_LIST_FILE = os.path.join(os.path.abspath(os.path.dirname(__file__)), config['FILES']['IpWhiteListFile'])
    
    # E-mail notify freq
    NOTIFY_FREQ = int(config['EMAIL']['NotifyFreq'])    
except KeyError as e:
    print(f"ERROR: Wrong configuration in 'config.ini'!: {e} Not Found")
    exit(1)

# Logging configuration
logger = logging.getLogger("mainlog")
logger.setLevel(logging.INFO)
fh = logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=LOG_FILE_SIZE, backupCount=5)
fh.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
logger.addHandler(fh)


def log(msg = '', notify_counter = 0, level = 6):
    if os.path.getsize(LOG_FILE) == 0:
        logger.info("LogFile created; NotificationCounter: 0")
    # Return Notification minute counter if msg is empty 
    if not msg:
        with open(LOG_FILE, 'r', encoding=CODE) as f:
            match = re.findall(r'NotificationCounter: (\w*)', f.read())
            if match:
                return int(match[-1])
            else:
                return 0
    if level == 3:
        logger.error(f"ERROR: {msg}")
    else:
        logger.info(f"{msg}; NotificationCounter: {notify_counter}")


def whois_net(ip):
    try:
        whois = subprocess.run([os.path.join(config['FILES']['SysBinDir'], 'whois'), ip], stdout=subprocess.PIPE)
    except Exception as e:
        log(f"While runing shell 'whois': {e}", level=3)
    else:
        netname = re.findall(r'(?:[nN]et|[Oo]rg)-?[Nn]ame: +(.+)', whois.stdout.decode(CODE))
        if netname:
            return '; '.join(netname)
    return '---'


def send_mail(msg, ip_set):
    try:
        if config['EMAIL']['Secure'].lower() == 'true':
            server = SMTP_SSL(config['EMAIL']['SMTPServer'], int(config['EMAIL']['SMTPPort']))
        else:
            server = SMTP(config['EMAIL']['SMTPServer'], int(config['EMAIL']['SMTPPort']))
    except Exception as e:
        log(f"While connecting to SMTP server: {e}", level=3)
    else:
        server.set_debuglevel(0)
        if config['EMAIL']['Auth'].lower() == 'true':
            try:
                server.login(config['EMAIL-AUTH']['Login'], config['EMAIL-AUTH']['Password'])
            except Exception as e:
                log(f"While login to SMTP Server: {e}", level=3)
        headers = (f"From: {config['EMAIL']['MailFrom']}\n"
                   f"To: {config['EMAIL']['MailTo']}\n"
                   f"Subject:{config['EMAIL']['Subject']} dIP: {', '.join(ip_set)}\n"
                   "MIME-Version: 1.0\n"
                   f"Content-Type: text/plain; charset=\"{CODE}\"\n")
        try:
            server.sendmail(f"{config['EMAIL']['MailFrom']}", [ f"{config['EMAIL']['MailTo']}" ], headers + msg)
        except Exception as e:
            log(f"While sending e-mail: {e}", level=3)
        else:
            log(f"DDoS E-mail sent to {config['EMAIL']['MailTo']}")
        server.quit()


def format_msg(reports_output, ip_set, flow_print):
    email_msg = ''
    for report, output in reports_output.items():
        email_msg += (f"\nTRIGGERED RULE: '{report}' with a THRESHOLD: " 
                      f"{REPORTS[report]['threshold']} {output['head'].split(',')[-1]}:\n\n")
        email_msg += ''.join(f"{s.replace('*', '').lower():<25}" for s in output['head'].split(','))
        if config['SYSTEM']['Whois'].lower() == 'true':
            email_msg += f"{'netname, orgname':<25}"
        email_msg += "\n" + "-"*120 + "\n"
        for ip, values in output['list']:
            email_msg += f"{ip.strip():<25}" + ''.join(f"{s.strip():<25}" for s in values.split(',') if s)
            if  config['SYSTEM']['Whois'].lower() == 'true':
                email_msg += f"{whois_net(ip):<25}"
            email_msg += "\n"
    email_msg += "\n"
    email_msg += f"\nFlow report (last {FLOW_REC_AMOUNT} flows to dIP: {', '.join(ip_set)}):\n\n"
    email_msg += (  f"{'Start':<24}{'End':<27}{'Sif':<6}{'SrcIPaddress':<16}{'SrcP':<9}"
                    f"{'DIf':<7}{'DstIPaddress':<16}{'DstP':<7}{'Prot':<7}{'Flows':<7}{'Pkts':<7}{'Octets':<7}" )
    email_msg += "\n" + "-"*120 + "\n"
    email_msg += flow_print
    return email_msg


def create_white_filter():
    with open(IP_WHITE_LIST_FILE, 'r', encoding=CODE) as f:
        ip_list = re.findall(r'^\s*(\d+\.\d+\.\d+\.\d+)\/?(\d+)?', f.read(), flags=re.MULTILINE)
    filter_string = ''
    if ip_list:
        for ip, prefix in ip_list:
            filter_string += f"not net {ip}/{prefix} and " if prefix else f"not host {ip} and "
        filter_string = filter_string[:-4]
    return filter_string


def ddos_check(flows_file):
    NFDUMP_REPORTS = {
        'sdport_flows' : { 'aggr' : 'dstip,srcport,dstport' , 'format' : 'fmt:%da,%sp,%dp,%fl', 'order' : 'flows' }, 
        'dport_packets' : { 'aggr' : 'dstip,dstport' , 'format' : 'fmt:%da,%dp,%pkt', 'order' : 'packets'},
        'flows' : { 'aggr' : 'dstip' , 'format' : 'fmt:%da,%fl',  'order' : 'flows'},
        'packets' : { 'aggr' : 'dstip' , 'format' : 'fmt:%da,%pkt', 'order' : 'packets' }
    }
    ip_set = set()
    reports_output = {}
    for report, options in REPORTS.items():
        command = ( f"{NFDUMP}  -r {flows_file} -A {NFDUMP_REPORTS[report]['aggr']} "
                    f"-O {NFDUMP_REPORTS[report]['order']} -N -q -o '{NFDUMP_REPORTS[report]['format']}' '{create_white_filter()}'| "
                    f"{AWK} -F, '${options['key_field']} > int({options['threshold']})'")
        result = subprocess.run([command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        if result.stderr:
            log(f"Return: {result.stderr} Command: '{command}'", level=3)
            exit(1)
        report_head = f"{NFDUMP_REPORTS[report]['aggr']},{NFDUMP_REPORTS[report]['order']}" 
        report_list = re.findall(r'\s*(\d+\.\d+\.\d+\.\d+)(.*)', result.stdout.decode(CODE))
        if report_list:
            reports_output[report] = {}
            reports_output[report]['head'] = report_head
            reports_output[report]['list'] = report_list
            for ip, _ in report_list:
                ip_set.add(ip)
    return (reports_output, ip_set)


def flows_print(ip_set, flows_file):
    filter_ip = ''
    for ip in ip_set:
        filter_ip += f"host {ip} or " 
    command = ( f"{NFDUMP} -r {flows_file} -N -q -o 'fmt:%ts,%te,%in,%sa,%sp,%out,%da,%dp,%pr,%fl,%pkt,%byt' '{filter_ip[:-3]}' | "
                f" tail -n {FLOW_REC_AMOUNT}")
    result = subprocess.run([command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    if result.stderr:
        log(f"Return:{result.stderr}  Command: '{command}'", level = 3)
        exit(1)
    else:
        return result.stdout.decode(CODE)


def main():
    notify_counter = log()
    date = (datetime.now() - timedelta(minutes=2)).strftime('%Y%m%d%H%M')
    try:
        flows_file = next(Path(FLOWS_DIR).rglob(f'*{date}*'))
    except StopIteration:
        log(f"Can not find flow-capture file for the date: {date}", level=3)
        exit(1)
    reports_output, ip_set = ddos_check(flows_file)
    if reports_output:
        if NOTIFY_FREQ > 0:
            if notify_counter == 0:
                email_msg = format_msg(reports_output, ip_set, flows_print(ip_set, flows_file))
                send_mail(email_msg, ip_set)
            notify_counter += 1
            log(f"DDoS dIP:{', '.join(ip_set)}", notify_counter)
            log("Notification counter changed", notify_counter=0) if notify_counter >= NOTIFY_FREQ else True
        else:
            log(f"DDoS dIP:{', '.join(ip_set)}; Printed to STDOUT", notify_counter=0)
            print('\n'.join(ip_set))
    else:
        log("Notification counter changed", notify_counter=0) if log() != 0 else True


if __name__ == '__main__':
    main()
