#!/usr/bin/env python

__description__ = 'Strings command in Python'
__author__ = 'Didier Stevens'
__version__ = '0.0.1'
__date__ = '2017/01/28'

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2015/07/02: start
  2015/07/07: continue
  2015/07/28: continue
  2015/10/24: added option -L
  2016/03/24: fix -S bug
  2016/08/03: added support for unicode; option r
  2017/01/22: added option -p
  2017/01/28: added option -g

Todo:

"""

import optparse
import sys
import os
import zipfile
import cStringIO
import textwrap
import re
import pickle
import gzip

MALWARE_PASSWORD = 'infected'
REGEX_STANDARD = '[\x09\x20-\x7E]'
REGEX_WHITESPACE = '[\x09-\x0D\x20-\x7E]'
FILENAME_GOODWAREDB = 'good-strings.db'

def PrintManual():
    manual = '''
Manual:

'''
    for line in manual.split('\n'):
        print(textwrap.fill(line))

#Convert 2 Bytes If Python 3
def C2BIP3(string):
    if sys.version_info[0] > 2:
        return bytes([ord(x) for x in string])
    else:
        return string

# CIC: Call If Callable
def CIC(expression):
    if callable(expression):
        return expression()
    else:
        return expression

# IFF: IF Function
def IFF(expression, valueTrue, valueFalse):
    if expression:
        return CIC(valueTrue)
    else:
        return CIC(valueFalse)

def ExtractStringsASCII(data, options):
    if options.regex != '':
        regex = options.regex + '{%d,}'
    elif options.whitespace:
        regex = REGEX_WHITESPACE + '{%d,}'
    else:
        regex = REGEX_STANDARD + '{%d,}'
    return re.findall(regex % options.bytes, data)

def ExtractStringsUNICODE(data, options):
    if options.regex != '':
        regex = '((' + options.regex + '\x00){%d,})'
    elif options.whitespace:
        regex = '((' + REGEX_WHITESPACE + '\x00){%d,})'
    else:
        regex = '((' + REGEX_STANDARD + '\x00){%d,})'
    return [foundunicodestring.replace('\x00', '') for foundunicodestring, dummy in re.findall(regex % options.bytes, data)]

def ExtractStrings(data, options):
    if options.type == 'all':
        return ExtractStringsASCII(data, options) + ExtractStringsUNICODE(data, options)
    elif options.type == 'ascii':
        return ExtractStringsASCII(data, options)
    elif options.type == 'unicode':
        return ExtractStringsUNICODE(data, options)
    else:
        print('Unknown type option: %s' % options.type)
        return []

def File2String(filename):
    try:
        f = open(filename, 'rb')
    except:
        return None
    try:
        return f.read()
    except:
        return None
    finally:
        f.close()

def IfWIN32SetBinary(io):
    if sys.platform == 'win32':
        import msvcrt
        msvcrt.setmode(io.fileno(), os.O_BINARY)

#Fix for http://bugs.python.org/issue11395
def StdoutWriteChunked(data):
    while data != '':
        sys.stdout.write(data[0:10000])
        try:
            sys.stdout.flush()
        except IOError:
            return
        data = data[10000:]

def File2Strings(filename):
    try:
        f = open(filename, 'r')
    except:
        return None
    try:
        return map(lambda line:line.rstrip('\n'), f.readlines())
    except:
        return None
    finally:
        f.close()

def ProcessAt(argument):
    if argument.startswith('@'):
        strings = File2Strings(argument[1:])
        if strings == None:
            raise Exception('Error reading %s' % argument)
        else:
            return strings
    else:
        return [argument]

def ExpandFilenameArguments(filenames):
    return list(collections.OrderedDict.fromkeys(sum(map(glob.glob, sum(map(ProcessAt, filenames), [])), [])))

def ConsecutiveLettersLength(data):
    return max([0] + [len(letters) for letters in re.findall(r'[a-z]+', data, re.I)])

def StringsSub(extractedString, dUnique, oExtraSensical, options):
    if options.search == '' or options.search in extractedString:
        doPrint = True
        if options.sensical:
            doPrint = doPrint and oExtraSensical.Test(extractedString)
        if options.letters:
            doPrint = doPrint and ConsecutiveLettersLength(extractedString) >= options.letters
        if options.unique:
            doPrint = doPrint and not extractedString in dUnique
            dUnique[extractedString] = True
        if doPrint and not options.invert or not doPrint and options.invert:
            if options.whitespace:
                StdoutWriteChunked(extractedString)
            else:
                print(extractedString)

def Filter(extractedStrings, imported):
    return [extractedString for extractedString in extractedStrings if not extractedString in imported]

def LoadGoodwareStrings():
    filename = os.path.join(os.path.dirname(sys.argv[0]), FILENAME_GOODWAREDB)
    try:
        fDB = gzip.GzipFile(filename, 'rb')
    except:
        print('Error opening goodware strings DB file: %s' % filename)
        return None
    collection = pickle.loads(fDB.read())
    fDB.close()
    return collection

def Strings(filename, options):
    if filename == '':
        IfWIN32SetBinary(sys.stdin)
        oStringIO = cStringIO.StringIO(sys.stdin.read())
    elif filename.lower().endswith('.zip'):
        oZipfile = zipfile.ZipFile(filename, 'r')
        oZipContent = oZipfile.open(oZipfile.infolist()[0], 'r', C2BIP3(MALWARE_PASSWORD))
        oStringIO = cStringIO.StringIO(oZipContent.read())
        oZipContent.close()
        oZipfile.close()
    else:
        oStringIO = cStringIO.StringIO(open(filename, 'rb').read())

    imported = []
    if options.pefile:
        try:
            import pefile
            oPE = pefile.PE(data=oStringIO.read())
            for entry in oPE.DIRECTORY_ENTRY_IMPORT:
                imported.append(entry.dll)
                for imp in entry.imports:
                    imported.append(imp.name)
        except:
            pass
        oStringIO.seek(0)

    oExtraSensical = None
    if options.sensical:
        import reextra
        oExtraSensical = reextra.cExtraSensical(True)
    if options.whitespace:
        IfWIN32SetBinary(sys.stdout)
    dUnique = {}

    selectedStrings = Filter(ExtractStrings(oStringIO.read(), options), imported)

    if options.goodwarestrings:
        goodware = LoadGoodwareStrings()
        if goodware == None:
            return
        selectedStrings = Filter(selectedStrings, goodware)

    if options.length:
        selectedStrings = sorted(selectedStrings, key=len)
    for extractedString in selectedStrings:
        StringsSub(extractedString, dUnique, oExtraSensical, options)

def Main():
    oParser = optparse.OptionParser(usage='usage: %prog [options] [file]\n' + __description__, version='%prog ' + __version__)
    oParser.add_option('-m', '--man', action='store_true', default=False, help='Print manual')
    oParser.add_option('-n', '--bytes', type=int, default=4, help='Minimum string length (default 4)')
    oParser.add_option('-w', '--whitespace', action='store_true', default=False, help='Include whitespace characters')
    oParser.add_option('-s', '--search', default='', help='String to search for')
    oParser.add_option('-l', '--letters', type=int, default=0, help='Minimum amount of consecutive letters (default 0)')
    oParser.add_option('-S', '--sensical', action='store_true', default=False, help='Output only sensical strings (e.g. no gibberish)')
    oParser.add_option('-v', '--invert', action='store_true', default=False, help='Invert selection')
    oParser.add_option('-u', '--unique', action='store_true', default=False, help='Remove repeated strings')
    oParser.add_option('-L', '--length', action='store_true', default=False, help='Sort by string length')
    oParser.add_option('-t', '--type', default='all', help='Type of strings ascii, unicode or all (default)')
    oParser.add_option('-r', '--regex', default='', help='Regex to be used to match characters')
    oParser.add_option('-p', '--pefile', action='store_true', default=False, help='Parse file as PE file and remove imported symbols')
    oParser.add_option('-g', '--goodwarestrings', action='store_true', default=False, help='Use the goodware strings db to filter out strings')
    (options, args) = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return 0

    if len(args) > 1:
        oParser.print_help()
        print('')
        print('  Source code put in the public domain by Didier Stevens, no Copyright')
        print('  Use at your own risk')
        print('  https://DidierStevens.com')
        return 0
    elif len(args) == 0:
        return Strings('', options)
    else:
        return Strings(args[0], options)

if __name__ == '__main__':
    sys.exit(Main())
