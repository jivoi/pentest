import multiprocessing
from argparse import RawTextHelpFormatter
import Queue
import threading
import os
import sys
import subprocess
from random import randint

def cli_parser():
   parser = argparse.ArgumentParser(add_help=False, description='''This script Simply routes your nmap scan in a "sort-of" fast way 
   through a ProcyChain that has been setup.
    \n\t(1) You will find out that when routing nmap through a Proxychain connection that Timing performace is out the window.
    \n\t(2) This is do to the nature of a SOCKS proxy and SYN->SYN/ACK connection is already established in NMAPS Eyes.
    \n\t(3) It out puts random (#) of .gnmap file for each IP for parsing. (MAKE A FOLDER) :)
    ''', formatter_class=RawTextHelpFormatter)
   parser.add_argument("-i", metavar="iplist.txt", help="Set Ip List of IPs Delimited by line")
   parser.add_argument('-h', '-?', '--h', '-help', '--help', action="store_true", help=argparse.SUPPRESS)
   args = parser.parse_args()
   if args.h: 
     parser.print_help()
     sys.exit()
   if not args.i:
     print "[!] I need a list IP's!"
     sys.exit()
   return args.i


def Execution(Task_queue):
  while True:
    Ip = Task_queue.get()
    # If the queue is emepty exit this proc
    # Setup a simple output in the folder, For gnmap Parser
    IpName = str(Ip).replace('.',"-") + str(".gnmap")
    if Ip is None:
      break
    try:
      print "[*] On Ip: " + Ip
      test = subprocess.check_output(["proxychains", "nmap", "-Pn", "-n", "-sT", "--max-scan-delay", "0", "-p111,445,139,21-23,80,443", "-oG", IpName, "--open", Ip])
      test = ""
    except:
      pass

def TaskSelector(Task_queue, verbose=False):
    total_proc = int(8)
    for i in xrange(total_proc):
        Task_queue.put(None)
    procs = []
    for thread in range(total_proc):
        procs.append(multiprocessing.Process(target=Execution, args=(Task_queue,)))
    for p in procs:
        p.daemon = True
        p.start()
    for p in procs:
        p.join()
    Task_queue.close()


def Ip_List(Task_queue, cli_IpList):
    items = []
    cli_IpList = str(cli_IpList)
    try:
        with open(cli_IpList, "r") as myfile:
          lines = myfile.readlines()
          for line in lines:
            line = line.rstrip('\n')
            items.append(line)
          for item in items:
            Task_queue.put(item)
          return Task_queue
    except Exception as e:
        print "[!] Please check your Ip List: " + str(e)
        sys.exit(0)

def main():
  cli_IpList = cli_parser()
  Task_queue = multiprocessing.Queue()
  Task_queue = Ip_List(Task_queue, cli_IpList)
  TaskSelector(Task_queue)


if __name__ == "__main__":
    try:  
         main()
    except KeyboardInterrupt:
        print 'Interrupted'
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
