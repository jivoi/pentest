#!/usr/bin/python

# Requires: https://github.com/gitpython-developers/GitPython

"""This script converts a github repo into a list for
directory and file bruteforcing but has to clone the whole repo to do it"""

__author__ = "Scot Berner"

import git
import sys, getopt, shutil

# Store repo URL and output file names
repoURL=''
ofile=''

# Read command line args
myopts, args = getopt.getopt(sys.argv[1:], "u:o:")

###############################
# o == option
# a == argument passed to the o
###############################

for o, a in myopts:
    if o == '-u':
        repoURL=a
    elif o == '-o':
        ofile=a
    else:
        print("Usage: %s -u <repo url> -o <out file>" % sys.argv[0])
        print("IE: %s -u https://github.com/WordPress/WordPress -o wordpress.txt" % sys.argv[0])

# Display input and output file name passed as the args

print ("[*] Repo URL : %s " % (repoURL) )
print ("[*] Outfile : %s " % (ofile) )

if ofile == "":
   print "[*] Outfile required"
   sys.exit()

#infer repo name from URL

repoURLArr = repoURL.split("/")

tempArr = repoURLArr[4].split(".")

repoName = tempArr[0]

#create repo dumping path

chkPath = "/tmp/" + repoName

#create git object

grepo = git.Git()

#clone repo

gitCMD = grepo.execute(["git", "clone", repoURL, chkPath])

#create git object in repo that we created

grepo = git.Git(chkPath)

#get list of files under source control for the master branch

repoFiles = grepo.execute(["git", "ls-tree", "-r", "master", "--full-name"])

#convert list of files to array of each line

repoFiles = repoFiles.split("\n")

#open file for writing with clobber

outFile = open(ofile, 'w+')

#write each file name to txt file

for line in repoFiles:
   #print line.split('\t')[1]
   outFile.write(line.split('\t')[1] + "\n")

outFile.close

print "[*] Cleaning up..."

#delect repo files

shutil.rmtree(chkPath)
