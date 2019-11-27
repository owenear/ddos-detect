import os
import subprocess
from datetime import datetime, timedelta
from smtplib import SMTP_SSL, SMTP
from configparser import ConfigParser
import re


# Load Config
config = ConfigParser(allow_no_value=True)

config.read(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'config.ini'))

# Reports options
REPORTS = {}
for key in config['REPORTS']:
    REPORTS.update({key:{}})
    REPORTS[key].update({'threshold': int(config[key]['threshold'])})
    REPORTS[key].update({'key_field': int(config[key]['key_field'])})
    REPORTS[key].update({'filter': config[key]['filter']})

# FlowTools options
FLOW_CAT = os.path.join(config['FILES']['FlowToolsBinDir'], 'flow-cat')
FLOW_NFILTER = os.path.join(config['FILES']['FlowToolsBinDir'], 'flow-nfilter')
FLOW_REPORT = os.path.join(config['FILES']['FlowToolsBinDir'], 'flow-report')
FLOW_PRINT = os.path.join(config['FILES']['FlowToolsBinDir'], 'flow-print')
FLOW_PRINT_TAIL = config['EMAIL']['FlowPrintTail']
FLOWS_DIR = config['FILES']['FlowsDir']

REPORT_FILE = os.path.join(os.path.abspath(os.path.dirname(__file__)), config['FILES']['ReportsFileName'])
FILTER_FILE = os.path.join(os.path.abspath(os.path.dirname(__file__)), config['FILES']['FiltersFileName'])


def whois_net(ip):
    whois = subprocess.run([os.path.join(config['FILES']['WhoisBinDir'], 'whois'), ip], stdout=subprocess.PIPE)
    netname = re.findall(r'(?:[nN]et|[Oo]rg)-?[Nn]ame: +(.+)', whois.stdout.decode(config['SYSTEM']['code']))
    if netname:
        return '; '.join(netname)
    else:
        return '---'


def send_mail(msg, ip_set):
    if config['EMAIL']['Secure'].lower() == 'true':
        server = SMTP_SSL(config['EMAIL']['SMTPServer'], int(config['EMAIL']['SMTPPort']))
    else:
        server = SMTP(config['EMAIL']['SMTPServer'], int(config['EMAIL']['SMTPPort']))
    server.set_debuglevel(0)
    if config['EMAIL']['Auth'].lower() == 'true':
        server.login(config['EMAIL-AUTH']['Login'], config['EMAIL-AUTH']['Password'])
    headers = (f"From: {config['EMAIL']['MailFrom']}\n"
               f"To: {config['EMAIL']['MailTo']}\n"
               f"Subject:{config['EMAIL']['Subject']} dIP: {', '.join(ip_set)}\n"
               "MIME-Version: 1.0\n"
               f"Content-Type: text/plain; charset=\"{config['SYSTEM']['code']}\"\n")
    server.sendmail(f"{config['EMAIL']['MailFrom']}", f"{config['EMAIL']['MailTo']}", headers + msg)
    server.quit()


def main():
    t_start = (datetime.now() - timedelta(minutes=2)).strftime('%m/%d/%Y %H:%M')
    t_end = (datetime.now() - timedelta(minutes=1)).strftime('%m/%d/%Y %H:%M') 
    email_msg = ''
    ip_set = set()
    for report, options in REPORTS.items():
        command = (f"{FLOW_CAT} -t '{t_start}' -T '{t_end}' {FLOWS_DIR}* | " 
                   f"{FLOW_NFILTER} -f {FILTER_FILE} -F {options['filter']} | "
                   f"{FLOW_REPORT} -s {REPORT_FILE} -S {report} | "
                   f"awk -F, '${options['key_field']} > int({options['threshold']})'")
        result = subprocess.run([command], stdout=subprocess.PIPE, shell=True)
        report_head = re.search(r'^# recn: (.*)', result.stdout.decode('utf-8')).group(1)
        report_list = re.findall(r'(\d+\.\d+\.\d+\.\d+)([,\w]+)', result.stdout.decode(config['SYSTEM']['code']))
        if report_list:
            email_msg += (f"\nTRIGGERED RULE: '{report}' with a THRESHOLD: " 
                          f"{options['threshold']} {report_head.split(',')[-1]}:\n\n")
            email_msg += ''.join(f"{s.replace('*', '').lower():<25}" for s in report_head.split(','))
            if config['SYSTEM']['Whois'].lower() == 'true':
                email_msg += f"{'netname, orgname':<25}"
            email_msg += "\n" + "-"*120 + "\n"
            for ip, values in report_list:
                ip_set.add(ip)
                email_msg += f"{ip.strip():<25}" + ''.join(f"{s:<25}" for s in values.split(',') if s)
                if  config['SYSTEM']['Whois'].lower() == 'true':
                    email_msg += f"{whois_net(ip):<25}"
                email_msg += "\n"
            email_msg += "\n"
    
    if email_msg:
        awk_query = '$7=="' + '" || $7=="'.join(ip_set) + '"'
        flows = subprocess.run([(f"{FLOW_CAT} -t '{t_start}' -T '{t_end}' {FLOWS_DIR}* | "
                                 f"{FLOW_PRINT} -f5 -p -w | " 
                                 f"awk '{awk_query}' |tail -n {FLOW_PRINT_TAIL}")],
                               stdout=subprocess.PIPE, shell=True)
        email_msg += f"\nFlow report (last {FLOW_PRINT_TAIL} flows to dIP: {', '.join(ip_set)}):\n\n"
        email_msg += ("Start             End               Sif   SrcIPaddress    SrcP  DIf   "
                      "DstIPaddress    DstP  P   Fl Pkts       Octets")
        email_msg += "\n" + "-"*120 + "\n"
        email_msg += flows.stdout.decode(config['SYSTEM']['code'])
        send_mail(email_msg, ip_set)


if __name__ == '__main__':
    main()