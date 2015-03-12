__author__ = 'sp013719'

import csv
import sys
import socket
from connection.ssh import Ssh

RESULT_FILE_NAME = 'result.csv'
USERNAME = '<put your account here>'
PASSWORD = '<put your password here>'


def quality_assurance(file_name, account, password):
    hosts = get_linux_host(file_name, account, password)

    #with open('result.txt', 'w') as f:
        #for idx, host in enumerate(hosts):
            #result = check_credential_and_tz(host)
            #print('credential check on host %d [%s] is %s' % (idx, host['hostname'], 'Pass' if result else 'Failed'))
            #f.write('credential check on %d host[%s] is %s\n' % (idx, host['hostname'], 'Pass' if result else 'Failed'))

    with open(RESULT_FILE_NAME, 'w') as csvfile:
        fieldnames = ['hostname', 'ip', 'dns_reverse', 'os', 'check_credential', 'sys_time']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for host in hosts:
            print('Checking the host [%s] .....' % host['hostname'])

            check_credential, sys_time = check_credential_and_tz(host)
            dns_reverse, real_ip = check_ip(host)
            result = dict()
            result['hostname'] = host['hostname']
            result['ip'] = host['ip']
            result['dns_reverse'] = 'Pass' if dns_reverse else ('Failed (%s)' % real_ip)
            result['os'] = host['os']
            result['check_credential'] = check_credential
            result['sys_time'] = sys_time
            writer.writerow(result)

            print('Checking the host [%s] done' % host['hostname'])


def get_linux_host(file_name, account, password):
    hosts = []

    with open(file_name, 'r') as f:

        for row in csv.DictReader(f):
            if 'Linux' not in row['OS']:
                continue

            host = dict()
            host['hostname'] = row['Host name']
            host['ip'] = row['IP Address']
            host['os'] = row['OS']
            host['credential'] = []
            #host['credential'].append({'acc': row['Account 1'], 'pwd': row['Password 1']})
            #host['credential'].append({'acc': row['Account 2'], 'pwd': row['Password 2']})
            #host['credential'].append({'acc': row['Account 3'], 'pwd': row['Password 3']})
            host['credential'].append({'acc': account, 'pwd': password})
            #print(host)
            hosts.append(host)

    return hosts


def check_ip(host):
    ip = socket.gethostbyname(host['hostname'])

    if not ip:
        return False, None
    else:
        return True if host['ip'] == ip else False, ip


def check_credential_and_tz(host):
    if not host:
        print('host is None')
        return None, None

    for credential in host['credential']:
        account = credential['acc']
        password = credential['pwd']

        if not account or not password:
            continue

        ssh = Ssh(host['hostname'], account, password, port=22)
        opened = ssh.open()

        if opened:
            sys_time = ssh.execute('date')
            ssh.close()
            return True, sys_time

    return False, None

if __name__ == '__main__':
    assert len(sys.argv) == 2
    quality_assurance(sys.argv[1], USERNAME, PASSWORD)
