from tabulate import tabulate
from host_range_ping import host_range_ping


def host_range_ping_tab():
    res_dict = host_range_ping(True)
    print()
    print(tabulate([res_dict], headers='keys', tablefmt='pipe', stralign='center'))

    if __name__ == '__main__':
        host_range_ping_tab()
