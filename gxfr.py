#!/usr/bin/python -tt
# GXFR replicates dns zone transfers by enumerating subdomains using advanced search engine queries and conducting dns lookups.
# By Tim Tomes (LaNMaSteR53)
# Available for download at http://LaNMaSteR53.com or http://code.google.com/p/gxfr/
print ''
print '       _/_/_/  _/      _/  _/_/_/_/  _/_/_/   '
print '    _/          _/  _/    _/        _/    _/  '
print '   _/  _/_/      _/      _/_/_/    _/_/_/     '
print '  _/    _/    _/  _/    _/        _/    _/    '
print '   _/_/_/  _/      _/  _/        _/    _/     '
print ''
import sys, os.path, urllib, urllib2, re, time, socket, random, socket, json
def help():
  help = """gxfr.py - Tim Tomes (@LaNMaSteR53) (www.lanmaster53.com)
Syntax: python %(0)s domain [mode] [options]
MODES
  =====
  --gxfr [options]         GXFR mode
  --bxfr [options]         BXFR mode (prompts for API key - required)
  --both [options]         GXFR and BXFR modes
   
  OPTIONS FOR ALL MODES
  =====================
  -h, --help               this screen
  -o                       output results to a file
  -v                       enable verbose mode
  --dns-lookup             enable dns lookups of all subdomains
  --user-agent ['string']  set custom user-agent string
  --proxy [file|ip:port|-] use a proxy or list of open proxies to send queries (@random w/list)
                             - [file] must consist of 1 or more ip:port pairs
                             - replace filename with '-' (dash) to accept stdin
                             - http://rmccurdy.com/scripts/proxy/good.txt
 
  OPTIONS FOR GXFR & BOTH MODES (GXFR shun evasion)
  ====================================================
  -t [num of seconds]      set number of seconds to wait between queries (default=15)
  -q [max num of queries]  restrict to maximum number of queries (default=0, indefinite)
  --timeout [seconds]      set socket timeout (default=system default)
 
  Examples:
  $ python %(0)s --bxfr --dns-lookup -o
  $ python %(0)s --both --dns-lookup -v
  $ python %(0)s --gxfr --dns-lookup --proxy open_proxies.txt --timeout 10
  $ python %(0)s --gxfr --dns-lookup -t 5 -q 5 -v --proxy 127.0.0.1:8080
  $ curl -O http://rmccurdy.com/scripts/proxy/good.txt && python %(0)s --both -t 0 --proxy good.txt --timeout 1
  """ % {'0':sys.argv[0]}
  return help
def bxfr():
  print '[-] Resovling subdomains using the Bing API...'
  filename = 'api.keys'
  key = ''
  if os.path.exists(filename):
    print '[-] Extracting Bing API key from \'%s\'.' % filename
    for line in open(filename):
      if 'bing::' in line:
        key = line.split('::')[1].strip()
        print '[-] Key found. Using \'%s\'.' % key
        break
    if not key: print '[!] No Bing API key found.'
  if not key:
    key = raw_input('\nEnter Bing API key: ')
    file = open(filename, 'a')
    print '[-] Bing API key added to \'%s\'.' % filename
    file.write('bing::%s\n' % key)
    file.close
  creds = (':%s' % key).encode('base64')[:-1]
  auth = 'Basic %s' % creds
  base_query = 'site:%s' % domain
  subs = []
  # test API key
  print '[-] Testing API key...'
  request = urllib2.Request('https://api.datamarket.azure.com/Data.ashx/Bing/Search/Web?Query=%27test%27&$top=50&$format=json')
  request.add_header('Authorization', auth)
  request.add_header('User-Agent', user_agent)
  msg, content = sendify(request)
  if not content:
    if str(msg).find('401') != -1:
      print '[!] Invalid API key.'
      return []
    else: print '[-] Unable to test API key. Continuing anyway.'
  else: print '[-] API key is valid.'
  # execute API calls and parse json results
  # loop until no results are returned
  while True:
    try:
      query = ''
      for sub in subs:
        query += ' -site:%s.%s' % (sub, domain)
      full_query = "'%s%s'" % (base_query, query)
      full_url = 'https://api.datamarket.azure.com/Data.ashx/Bing/Search/Web?Query=%s&$top=50&$format=json' % urllib.quote_plus(full_query)
      if verbose: print '[+] using query: %s...' % (full_url)
      request = urllib2.Request(full_url)
      request.add_header('Authorization', auth)
      request.add_header('User-Agent', user_agent)
      if not verbose: sys.stdout.write('.'); sys.stdout.flush()
      if proxy:
        msg, content = proxify(request)
      else:
        msg, content = sendify(request)
      #if not content: return subs
      if not content: break
      jsonobj = json.loads(content)
      results = jsonobj['d']['results']
      if len(results) == 0:
        print '[-] all available subdomains found...'
        break       
      for result in results:
        sub = result['Url'][result['Url'].index('://')+3:result['Url'].index(domain)-1]
        if not sub in subs:
          if verbose: print '[!] subdomain found:', sub
          subs.append(sub)
    except KeyboardInterrupt:
      # catch keyboard interrupt and gracefull complete script
      break
  return subs
def gxfr():
  print '[-] Resovling subdomains using Google...'
  query_cnt = 0
  base_url = 'https://www.google.com'
  base_uri = '/m/search?'
  base_query = 'site:' + domain
  pattern = '>([\.\w-]*)\.%s.+?<' % (domain)
  subs = []
  new = True
  page = 0
  # execute search engine queries and scrape results storing subdomains in a list
  # loop until no new subdomains are found
  while new == True:
    try:
      query = ''
      # build query based on results of previous results
      for sub in subs:
        query += ' -site:%s.%s' % (sub, domain)
      full_query = base_query + query
      start_param = '&start=%s' % (str(page*10))
      query_param = 'q=%s' % (urllib.quote_plus(full_query))
      if len(base_uri) + len(query_param) + len(start_param) < 2048:
        last_query_param = query_param
        params = query_param + start_param
      else:
        params = last_query_param[:2047-len(start_param)-len(base_uri)] + start_param
      full_url = base_url + base_uri + params
      # note: query character limit is passive in mobile, but seems to be ~794
      # note: query character limit seems to be 852 for desktop queries
      # note: typical URI max length is 2048 (starts after top level domain)
      if verbose: print '[+] using query: %s...' % (full_url)
      # build web request and submit query
      request = urllib2.Request(full_url)
      # spoof user-agent string
      request.add_header('User-Agent', user_agent)
      if not verbose: sys.stdout.write('.'); sys.stdout.flush()
      # if proxy is enabled, use the correct handler
      if proxy:
        msg, result = proxify(request)
      else:
        msg, result = sendify(request)
      if not result:
        if str(msg).find('503') != -1: print '[!] possible shun: use --proxy or find something else to do for 24 hours :)'
        break
      #if not verbose: sys.stdout.write('\n'); sys.stdout.flush()
      # iterate query count
      query_cnt += 1
      sites = re.findall(pattern, result)
      # create a uniq list
      sites = list(set(sites))
      new = False
      # add subdomain to list if not already exists
      for site in sites:
        if site not in subs:
          if verbose: print '[!] subdomain found:', site
          subs.append(site)
          new = True
      # exit if maximum number of queries has been made
      if query_cnt == max_queries:
        print '[-] maximum number of queries made...'
        break
      # start going through all pages if querysize is maxed out
      if new == False:
        # exit if all subdomains have been found
        if not 'Next page' in result:
          # curl to stdin breaks pdb
          print '[-] all available subdomains found...'
          break
        else:
          page += 1
          new = True
          if verbose: print '[+] no new subdomains found on page. jumping to result %d.' % (page*10)
      # sleep script to avoid lock-out
      if verbose: print '[+] sleeping to avoid lock-out...'
      time.sleep(secs)
    except KeyboardInterrupt:
      # catch keyboard interrupt and gracefull complete script
      break
  # print list of subdomains
  print '[-] successful queries made:', str(query_cnt)
  if verbose: print '[+] final query string: %s' % (full_url)
  return subs
def sendify(request):
  requestor = urllib2.build_opener()
  #requestor = urllib2.build_opener(urllib2.HTTPHandler(), urllib2.HTTPSHandler())
  # send query to search engine
  try:
    result = requestor.open(request)
    # exit function if successful
    return "Success!'", result.read()
  except Exception as inst:
    # this string marks the end for Bing. possible api bug.
    if inst.read().find('investigating the issue') == -1:
      print '[!] {0}'.format(inst)
    return inst, None
def proxify(request):
  # validate proxies at runtime
  while True:
    # select a proxy from list at random
    num = random.randint(0,len(proxies)-1)
    host = proxies[num]
    opener = urllib2.build_opener(urllib2.ProxyHandler({'https': host}))
    if verbose: print '[+] sending query to', host
    # send query to proxy server
    try:
      result = opener.open(request)
      # exit while loop if successful
      return 'Success!', result.read()
    except Exception as inst:
      try:
        # this string marks the end for Bing. possible api bug.
        if inst.code == 404 and inst.read().find('investigating the issue') != -1:
          return inst, None
      except: pass
      print '[!] %s failed: %s.' % (host, inst)
      if len(proxies) == 1:
        # exit of no proxy servers from list are valid
        print '[-] valid proxy server not found.'
        return inst, None
      else:
        # remove host from list of proxies and try again
        print '[!] removing %s from proxy list.' % (host)
        del proxies[num]
def list_subs(subs):
  print ' '
  print 'Source\tSubdomain - %d' % (len(subs))
  print '======\t========='
  if output: outfile = open(outfilename, 'a')
  if output: outfile.write(";;SUBDOMAINS: %d\n" % (len(subs)))
  for sub in subs:
    print '%s\t%s.%s' % (sub[0], sub[1], domain)
    if output: outfile.write("[S]\t%s\t%s.%s\n" % (sub[0], sub[1], domain))
  if output: outfile.close()
def lookup_subs(subs):
  # conduct dns lookup if argument is present
  if lookup == True:
    print ' '
    print '[-] querying dns, please wait...'
    dict = {}
    print ' '
    print 'Source\tIP Address\tSubdomain'
    print '======\t==========\t========='
    if output: outfile = open(outfilename, 'a')
    if output: outfile.write(";;DNSRECORDS:\n")
    # create a list of all associated ips to the subdomain
    for sub in subs:
      #if len(sub[1]) > 0:
      site = '%s.%s' % (sub[1], domain)
      #if verbose: print '[+] querying dns for %s...' % (sub[1])
      # dns query and dictionary assignment
      try:
        ips = list(set([item[4][0] for item in socket.getaddrinfo(site, 80)]))
      except socket.gaierror:
        # dns lookup failure
        ips = list(set(['no entry']))
      # print table of subdomains and ips
      for ip in ips:
        print '%s\t%s\t%s' % (sub[0], ip, site)
        if output: outfile.write("[R]\t%s\t%s\t%s\n" % (sub[0], ip, site))
    if output: outfile.close()
# --begin--
if len(sys.argv) < 2 or '-h' in sys.argv or '--help' in sys.argv:
  sys.exit(help())
# declare global vars and process arguments
mode = sys.argv[1]
modes = ['--gxfr', '--bxfr', '--both']
if mode not in modes:
  sys.exit('%s\n[!] Invalid mode: %s\n' % (help(), mode))
sys.argv = sys.argv[2:]
lookup = False
proxy = False
user_agent = 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; FDM; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 1.1.4322)'
verbose = False
output = False
secs = 15
max_queries = 0 # infinite
# process command line arguments
if len(sys.argv) > 0:
  if '--dns-lookup' in sys.argv:
    lookup = True
  if '--proxy' in sys.argv:
    proxy = True
    param = sys.argv[sys.argv.index('--proxy') + 1]
    #if param == '-':
    #  proxies = sys.stdin.read().split()    
    #elif
    if os.path.exists(param):
      proxies = open(param).read().split()
    elif re.match(r'^\d+\.\d+\.\d+\.\d+:\d+$', param):
      proxies = [param]
    else:
      sys.exit('%s\n[!] Invalid proxy parameter\n' % help())
  if '--timeout' in sys.argv:
    timeout = int(sys.argv[sys.argv.index('--timeout') + 1])
    socket.setdefaulttimeout(timeout)
  if '--user-agent' in sys.argv:
    user_agent = sys.argv[sys.argv.index('--user-agent') + 1] 
  if '-v' in sys.argv:
    verbose = True
  if '-o' in sys.argv:
    output = True
  if '-t' in sys.argv:
    secs = int(sys.argv[sys.argv.index('-t') + 1])
  if '-q' in sys.argv:
    max_queries = int(sys.argv[sys.argv.index('-q') + 1])
sys.stdin = open('/dev/tty')
domain = raw_input('Enter Domain Name: ')
if output:
  outfilename = raw_input('Enter Output File Name [%s.gxfr]: ' % domain.split('.')[0])
  if not outfilename:
    outfilename = '%s.gxfr' % domain.split('.')[0]
  # check if file can be created
  # will fail and die if not
  try:
    outfile = open(outfilename, 'w')
    outfile.close()
  except IOError:
    print '[!] Error writing to output file location: %s' % outfilename
    print '[!] Make sure the location exists, is writeable and try using an absolute path'
    sys.exit()
print '[-] domain:', domain
if output: print '[-] output file:', outfilename
print '[-] user-agent:', user_agent
 
# execute based on mode
gsubs, bsubs = [], []
if mode == '--gxfr' or mode == '--both': gsubs = gxfr()
if mode == '--bxfr' or mode == '--both': bsubs = bxfr()
# remove empty subdomains
gsubs = [gsub for gsub in gsubs if gsub]
bsubs = [bsub for bsub in bsubs if bsub]
# make 3 separate lists
both = list(set(gsubs) & set(bsubs))
for sub in both:
  if sub in gsubs:
    del gsubs[gsubs.index(sub)]
  if sub in bsubs:
    del bsubs[bsubs.index(sub)]
# build new list of tuples with titles
subs = []
for item in both:
  subs.append(('BOTH', item))
for item in gsubs:
  subs.append(('GXFR', item))
for item in bsubs:
  subs.append(('BXFR', item))
# print output
if len(subs) > 0:
  list_subs(subs)
  lookup_subs(subs)
else:
  print '\n[!] No subdomains were found'
print ''
 
# --end--
 
 
