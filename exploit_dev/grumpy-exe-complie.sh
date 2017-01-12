# Installation
# git clone https://github.com/google/grumpy.git
# cd grumpy && make
# export GOPATH=$PWD/build
# export PYTHONPATH=$PWD/build/lib/python2.7/site-packages

# # hello word test
# # hello: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, not stripped
# echo 'print "hello world"' > hello.py
# tools/grumpc hello.py > hello.go
# go build -o hello hello.go
# ./hello

## If you are not on Linux, you can use Go to build for another platform
## hello-linux-amd64: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, not stripped
# GOOS=linux GOARCH=amd64 go build -o hello-linux-amd64 hello.go

## For windows on Linux
## hello-win-386: PE32 executable (console) Intel 80386 (stripped to external PDB), for MS Windows
# GOOS=windows GOARCH=386 go build -o hello-win-386 hello.go

cd /root/grumpy/
export GOPATH=$PWD/build
export PYTHONPATH=$PWD/build/lib/python2.7/site-packages
tools/grumpc $1 > $1.go
go build -o $1.gobuild $1.go