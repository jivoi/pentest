#!/usr/bin/python2
# apt-get install python-pyftpdlib
# python ftpd.py -u -p 21

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from optparse import OptionParser

import os
import getpass

read_permisson="elr"
upload_permisson="elrmw"
write_permisson="elradfmwM"
banner = "Welcome to FTPD!"
port = 2121
max_cons = 100
max_cons_per_ip = 5
encoding = None

from asynchat import async_chat

class EncodedProducer:
    def __init__(self, producer):
        self.producer = producer
    def more(self):
        return self.producer.more().decode("utf8").encode(encoding)

class EncodedHandler(FTPHandler):

    def push(self, s):
        async_chat.push(self, s.encode(encoding))

    def push_dtp_data(self, data, isproducer=False, file=None, cmd=None):
        if file==None:
            if isproducer:
                data=EncodedProducer(data)
            else:
                data=data.decode("utf8").encode(encoding)

        FTPHandler.push_dtp_data(self, data, isproducer, file, cmd)

    def decode(self, bytes):
        return bytes.decode(encoding, self.unicode_errors)


def main(home, upload = False, write = False, authorization = False, encoded = False, nat_ip = False, pasv_port = None):

    print "Set home directory to %s"%home

    authorizer = DummyAuthorizer()

    if write:
        print "Warning: All write permisson assigned!"
        permisson = write_permisson
    elif upload:
        print "Warning: Upload permisson assigned!"
        permisson = upload_permisson
    else:
        permisson = read_permisson

    if authorization:
        print "Setting up authorization..."
        user = raw_input("Set user name:")
        while 1:
            password = getpass.getpass("Set password:")
            if getpass.getpass("Confirm password:") == password:
                break
        authorizer.add_user(user, password, home, perm=permisson)
    else:
        authorizer.add_anonymous(home ,perm=permisson)

    if encoded:
        print "Transparent encoding transform enabled, target encoding: %s"%encoding
        handler = EncodedHandler
    else:
        handler = FTPHandler
    handler.authorizer = authorizer

    handler.banner = banner

    if nat_ip:
        handler.masquerade_address = nat_ip
        handler.passive_ports = pasv_port

    address = ('', port)
    server = FTPServer(address, handler)

    server.max_cons = max_cons
    server.max_cons_per_ip = max_cons_per_ip

    server.serve_forever()

if __name__=="__main__":
    parser = OptionParser()
    parser.add_option("-u", "--upload", dest="upload",
            action="store_true",default=False,help="assign upload permissons.")
    parser.add_option("-w", "--write", dest="write",
            action="store_true",default=False,help="assign write permissons.(Overrides -u)")
    parser.add_option("-a", "--authorization", dest="authorization",
            action="store_true",default=False,help="enable authorization.")
    parser.add_option("-p", "--port", dest="port",
            action="store",type=int,default=port,help="set an alternative port.(Default: %d)"%port)
    parser.add_option("-d", "--home-dir", dest="home",
            action="store",default=os.getcwd(),help="set home directory.(Default: current working directory)")
    parser.add_option("-e", "--encoding", dest="encoding",
            action="store",default=None,help="set transparent encoding transform for clients.")
    parser.add_option("-n", "--nat-ip", dest="nat_ip",
            action="store", default=False, help="set NAT public ip for working behind NAT.")
    parser.add_option("-P", "--pasv-ports", dest="pasv_port",
            action="store", default="21210-21220", help="only effective when used together with --nat, set ports for PASV mode, for NAT ports forwarding, format: [start]-[end].(Default: 21210-21220).")

    (options,args) = parser.parse_args()

    port = options.port

    encoding = options.encoding

    pasv_port = range(int(options.pasv_port.split("-")[0]), int(options.pasv_port.split("-")[1]) + 1)

    try :
        main(options.home, options.upload, options.write, options.authorization, encoding!=None, options.nat_ip, pasv_port)
    except Exception as e:
        print "Exception: %s detected."%e
        print "Now quit..."
    except KeyboardInterrupt:
        print "User interrupts!"
        print "Now quit..."

