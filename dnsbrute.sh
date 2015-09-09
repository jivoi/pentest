#!/bin/bash
if [ $# == 0 ] ; then
    echo "Run $0 domain_name"
    exit 1;
fi
ruby ./brutelist.rb | parallel -j100 dig +noall {}.$1 +answer

