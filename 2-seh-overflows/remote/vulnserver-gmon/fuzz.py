#!/usr/bin/env python3

from boofuzz import *


def callback(targ, log, *args, **kwargs):
    try:
        msg = targ.recv(1024)

        if msg == b'Welcome to Vulnerable Server! Enter HELP for help.\n':
            log.log_pass('pass: message received')
        else:
            log.log_fail('fail: no message received')
    except:
        log.log_fail('fail: unable to connect')


conn = SocketConnection('192.168.122.186', 9999, proto='tcp')
targ = Target(conn)
sess = Session(target=targ, sleep_time=0.5)

s_initialize(name='Request')
with s_block('Host-Line'):
    s_static('GMON ', name='gmon') 
    s_string('FUZZ')
    s_delim('\r\n')

sess.connect(s_get('Request'), callback=callback)
sess.fuzz()
