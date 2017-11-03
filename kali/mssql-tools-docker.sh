#!/bin/sh
mkdir mssql-tools && cd mssql-tools
wget https://raw.githubusercontent.com/Microsoft/mssql-docker/master/linux/mssql-tools/Dockerfile
docker build -t mssql-tools .
docker run --rm --name mssql-tools -it -v /root:/root mssql-tools /bin/bash

# /opt/mssql-tools/bin/sqlcmd -U admin -P 'P@ssw0rd' -S IP
# Print databases;
# SELECT name from sys.databases
# GO

# Print tables from database
# SELECT * FROM database.INFORMATION_SCHEMA.TABLES;
# GO

# Use DB
# USE database
# GO

# Print table
# SELECT * FROM table;
# GO
