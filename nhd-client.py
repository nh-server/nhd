#!/usr/bin/env python3
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('localhost', 18510))

while True:
    while True:
        resp = s.recv(1024).decode('utf-8')
        lines = resp.splitlines()
        do_break = False
        do_disconnect = False
        for line in lines:
            print('Response:', line)
            if line == 'waiting':
                do_break = True
            elif line == 'disconnect':
                do_disconnect = True
        if do_break:
            break
        if do_disconnect:
            s.close()
            print('Daemon has disconnected.')
            exit()
    try:
        inp = input('>nhd:')
    except EOFError:
        print('exit')
        inp = 'exit'
    s.send(b'nhd:' + inp.encode('utf-8') + b'\r\n')
