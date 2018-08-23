#!/usr/bin/python3.5
"""
create file with "n" users config for radius server
!AHTUNG! Login and Password will be admin00000000, admin00000001 .. adminnnnnnnnn (n)
"""
from optparse import OptionParser
from ipaddress import IPv4Network, IPv4Interface


def logopass(line):
    """
    make user login and passwords
    :return: user (login == pass)
    """
    count = line.to_bytes(4, byteorder='big')
    user = "admin" + count.hex()
    return user


def ipaddr(network):
    """
    make ip address
    :param network: network (def 192.168.0.0/30)
    :return:
    """
    ipa = []
    for ip in IPv4Network(network):
        ipa.append(str(ip))

    ipaddress = IPv4Interface(network)
    all_address = ipaddress.with_netmask
    mask = str(all_address).rsplit('/', 1)

    return ipa[2:], ipa[1], str(mask[1])  # first ip address x.x.x.0 do not need


def main(count_users, network):
    """

    :param count_users:
    :param network:
    :return:
    """

    ipaddress, iproute, netmask = ipaddr(network)

    file = open("users", 'w')

    for line in range(0, int(count_users)):

        # Create username and password(username==password)
        user = logopass(line)

        # Write info in file
        file.write(
            "{0} Cleartext-Password := {1}\n".format(user, user)
        )
        file.write(
            "    Framed-IP-Address := {},\n".format(ipaddress[line])
        )
        file.write(
            "    Framed-IP-Netmask := {},\n".format(netmask)
        )
        file.write(
            "    Framed-Route := {},\n".format(iproute)
        )

        file.write(
            "    SERVICE_NAME := Unlim\n"
        )
    file.close()


if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option(
        "-c", "--count", dest="count", default=10, help="How many users need to create"
    )
    parser.add_option(
        "-n", "--network", dest="network", default="192.168.0.0/18", help="Network for radius"
    )
    (options, args) = parser.parse_args()

    try:
        main(options.count, options.network)
    except IndexError:
        print("     >>> Count users more then ip addresses in network")
