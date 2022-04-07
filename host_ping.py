import os
import platform
import subprocess
import threading
import time
from ipaddress import ip_address

result = {
    'Available nodes': '',
    'Not available nodes': ''
}

DNULL = open(os.devnull, 'w')


def check_is_ipaddress(value):
    """
    IP-address validator function
    :param value:
    :return ipv4:
    """
    try:
        ipv4 = ip_address(value)
    except ValueError:
        raise Exception('Bad IP-address')
    return ipv4


def ping(ipv4, result, get_list):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    response = subprocess.Popen(['ping', param, '1', '-w', '1', str(ipv4)],
                                stdout=subprocess.PIPE)

    if response.wait() == 0:
        result['Available nodes'] += f'{ipv4}\n'
        res = f'{ipv4} - host is available'
        if not get_list:
            print(res)
        return res
    else:
        result['Not available nodes'] += f'{ipv4}\n'
        res = f'{str(ipv4)} - host is not available'
        if not get_list:
            print(res)
        return res


def host_ping(hosts_list, get_list=False):
    """
    Host checker function
    :param hosts_list:
    :param get_list:
    :return dict:
    """
    print('Check started...')
    threads = []
    for host in hosts_list:
        try:
            ipv4 = check_is_ipaddress(host)
        except Exception as e:
            print(f'{host} - {e} is domain name')
            ipv4 = host

        thread = threading.Thread(target=ping, args=(ipv4, result, get_list), daemon=True)
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    if get_list:
        return result


if __name__ == '__main__':
    hosts_list = ['192.168.8.1', '8.8.8.8', 'mail.ru', 'google.com',
                  '0.0.0.1', '0.0.0.2', '0.0.0.3', '0.0.0.4']
    start = time.time()
    host_ping(hosts_list)
    end = time.time()
