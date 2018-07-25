#!/usr/bin python
# -*- coding: utf-8 -*-

"""
main.py

Driver for the NoPi4Me program.

Tired of insecure Raspberry Pi machines putting your network at risk? Me too! No Pi 4 Me, please. With the ever-
increasing number of internet-connected devices, malicious actors have a larger and (generally more) insecure attack
surface for penetrating your network. Once inside NoPi4Me bricks the Raspberry Pi by corrupting startup files.

Note: This is a noisy tool that should be used for educational purposes only.

"""

import netaddr
import argparse
from sys import stdout
from socket import socket
from scapy.all import *

ART_AND_TITLE = """
            (
    (       )      )       ____           ____  _ _____      _            
    )  __..---..__  (     |  _ \ __ _ ___|  _ \(_) ____|__ _| |_ ___ _ __ 
   ,-='  /  |  \  `=-.    | |_) / _` / __| |_) | |  _| / _` | __/ _ \ '__| 
((:--..___________..--;)) |  _ < (_| \__ \  __/| | |__| (_| | ||  __/ |    
   \.,_____________,./    |_| \_\__,_|___/_|   |_|_____\__,_|\__\___|_|"""
DESCRIPTION = """
\t  OoOoOoOoOoOoOoOoOoOoOoOoOoOoOoOoOoOoOoOoOoOoOoOoO
\t  Oo - - -     Written by Yoji Watanabe    - - - oO
\t  Oo - - - - - -      July, 2018     - - - - - - oO
\t  OoOoOoOoOoOoOoOoOoOoOoOoOoOoOoOoOoOoOoOoOoOoOoOoO

~~ ANTI-COPYRIGHT ~~
Share, modify, and rebuild as necessary.
For educational and lawful use.
"""
# All reserved private network ranges (RFC 1918)
LOCAL_NET_CIDR = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']
SSH_KEYWORDS = ['ssh']
DEFAULT_USER = 'pi'
DEFAULT_PASS = 'raspberry'
DEFAULT_SSH_PORT = 22
LOG = 'logs/{{{}}}.log'
logger = logging.getLogger()


#   print_intro()
#
#   Prints the introduction page to the program, including a small summary of actions that will be performed.
def print_intro(input):
    print ART_AND_TITLE
    print DESCRIPTION
    # TODO PRINT SUMMARY


#   start_logging()
#
#   Begin logging execution
def start_logging():
    global logger
    logger.setLevel(logging.INFO)

    formatter = logging.Formatter('%(asctime)s %(levelname)-5s - - - %(message)s')

    file_handler = logging.FileHandler(LOG.replace('{{{}}}', '{date:%Y-%m-%d_%H:%M:%S}'.format(date=datetime.now())))
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    clo_handler = logging.StreamHandler()
    clo_handler.setLevel(logging.DEBUG)
    clo_handler.setFormatter(formatter)
    logger.addHandler(clo_handler)

    logger.info('Started execution')


#   parse_arguments()
#
#   Handles arguments using argparse, returns the parsed arguments.
def parse_arguments():
    parser = argparse.ArgumentParser(description='Program to help secure networks from insecure Raspberry Pis')
    parser.add_argument('-a', '--address',  dest='address', help='IPv4 address of RaspberryPi host to target')
    parser.add_argument('-r', '--range', dest='range', help='CIDR block to scan for Raspberry Pis')
    parser.add_argument('-p', '--private', dest='all', help='Scan all private network ranges as specified by RFC 1918')
    parser.add_argument('-P', '--port', dest='port', help='Port number to SSH into')

    parsed = parser.parse_args()
    if parsed.address:
        logger.info('Destination address : %s' % parsed.address)
    elif parsed.range:
        logger.info('Destination address : %s' % parsed.address)
    elif parsed.range:
        logger.info('Destination address : %s' % parsed.address)
    else:
        logger.error('Unknown input, stopping execution')
        exit(1)

    return parsed


#   check_host_up()
#
#   Checks if a given host responds to ICMP requests (pings hosts and checks reply)
def check_host_up(address):
    logging.info('Checking if host is up: sending ICMP packet to host')
    icmp = IP(dst=address)/ICMP()
    reply = sr1(icmp, timeout=5, verbose=0)
    logging.info(icmp.summary())

    if reply is None:
        logging.error('Host not up or no connectivity, check connection to host')
        return False

    logging.info(reply.summary())
    logging.info('Host responding to ICMP requests, host is up')

    return True


def check_ssh_up(address, port, **kwargs):
    logging.info('Checking if SSH service is running on host')
    buffer_size = 1024

    sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if sck.connect_ex((address, port)) == 0:
        logging.info('Established connection to SSH port on the target machine')
        logging.info('Receiving buffer of size ' + str(buffer_size) + ' bytes:')
        response = sck.recv(buffer_size)
        logging.info('Received buffer: ' + str(response).rstrip())

        for keyword in SSH_KEYWORDS:
            if keyword in str(response).lower():
                logging.info('SSH service likely running on the target machine')
                return sck

        logging.info('Could not find default Raspbian SSH service running on the target machine')
        logging.info('Exiting program...')

        exit(1)


#   ssh_into_host
#
# Check if ssh is up, and if so, try to ssh into host
def ssh_into_host(address, **kwargs):
    if 'port' in kwargs:
        check_ssh_up(address, kwargs['port'])
    else:
        check_ssh_up(address, DEFAULT_SSH_PORT)

    credentials = DEFAULT_USER + ":" + DEFAULT_PASS
    if 'user_filename' in kwargs and 'password_filename' in kwargs:
        usernames = readFile(kwargs['user_filename'])
        password = readFile(kwargs['password_filename'])
        credentials_list = match_userpass(usernames, password)
        # TODO handle user-supplied credential files
    # TODO actually ssh



def main():
    start_logging()
    args = parse_arguments()
    if args.address:
        ip_list_to_check = [args.address]
    elif args.range:
        ip_list_to_check = netaddr.IPNetwork(args.range)

    print_intro(ip_list_to_check)

    for host in ip_list_to_check:
        # TODO ssh into specific port
        if not check_host_up(host):
            logging.info('Exiting program...')
            exit(1)

        ssh_into_host(host)

    logging.info('Execution done')


# # # # # # # # # # # # # # # # # # # # # # # # # # # # #
if __name__ == '__main__':
    main()
