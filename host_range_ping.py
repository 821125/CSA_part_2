from host_ping import check_is_ipaddress, host_ping


def host_range_ping(get_list=False):
    """
    The function response origin address and number of address
    then return hosts list
    :param get_list:
    :return:
    """

    while True:
        start_ip = input('Input origin address: ')
        try:
            ipv4_start = check_is_ipaddress(start_ip)
            last_oct = int(start_ip.split('.')[3])
            break
        except Exception as e:
            print(e)
    while True:
        end_ip = input('Input number of address: ')
        if not end_ip.isnumeric():
            print('You must input a number')
        else:
            if (last_oct + int(end_ip)) > 255 + 1:
                print(f'Max number of hosts {255 + 1 - last_oct}')
            else:
                break
    host_list = []
    [host_list.append(str(ipv4_start + x)) for x in range(int(end_ip))]
    if not get_list:
        host_ping(host_list)
    else:
        return host_ping(host_list, True)


if __name__ == '__main__':
    host_range_ping()
