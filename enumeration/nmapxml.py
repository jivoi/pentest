#!/usr/bin/env python
import reconf
from reconf import *
from xml.dom import minidom

def iter_hosts(info):
        hosts_nodes = info.getElementsByTagName("host")
        for host_node in hosts_nodes:
            yield(host_node)

def get_IP_Address(info):
        '''Fetch the IP address from the XML object'''
        ip_address = str()
        info_detail = info.getElementsByTagName("address")
        for address in info_detail:
            if(address.getAttribute("addrtype") == "ipv4"):
                ip_address = address.getAttribute("addr")
                break

        return(ip_address)

def get_All_IP(info):
	info_detail = info.getElementsByTagName("address")
	ipaddrs=[]
	for address in info_detail:
        	if(address.getAttribute("addrtype") == "ipv4"):
                	ipaddrs.append(address.getAttribute("addr").encode('ascii'))
	return ','.join(ipaddrs)

def get_FQDN(info):
        fqdn = str()
        info_detail = info.getElementsByTagName("hostname")
        for hostname in info_detail:
            if(hostname.getAttribute("name")):
                fqdn = hostname.getAttribute("name")
                break

        return(fqdn)

def get_OS(info):
        '''Determine the OS by the greatest percentage in accuracy'''
        os = str()
        os_hash = dict()
        percentage = list()

        info_detail = info.getElementsByTagName("osmatch")

        for os_detail in info_detail:
            guessed_os = os_detail.getAttribute("name")
            accuracy = os_detail.getAttribute("accuracy")
            if(guessed_os and accuracy):
                os_hash[float(accuracy)] = guessed_os

        percentages = os_hash.keys()
        if(percentages):
            max_percent = max(percentages)
            os = os_hash[max_percent]

        return(os)

def headersEnum(ip_address, port):
        print "\033[0;33m[>]\033[0;m Identifying Server type on %s" % (url)
        HEADSCAN = "nmap -sV -vv -Pn -n -p %s --script=http-headers -oA %s/%s_%s_httpheader %s" % (port, reconf.exampth, ip_address, port, ip_address)
        try:
                subprocess.call(HEADSCAN, shell=True)
        except:
                pass

def generic_Info(info):
	info_detail = info.getElementsByTagName("port")
	for port_details in info_detail:
	    protocol = port_details.getAttribute("protocol")
	    port_number = port_details.getAttribute("portid")

	    port_service = port_details.getElementsByTagName("state")
	    for port_services in port_service:
		port_state = port_services.getAttribute("state")

		if(port_state == "open"):

		    service_info = port_details.getElementsByTagName("service")
		    for service_details in service_info:
			service = service_details.getAttribute("name")
			product = service_details.getAttribute("product")
			version = service_details.getAttribute("version")

	return(protocol, port_number, service, product, version)

def getiter_Port_Information(info):
        '''Fetch port and service information'''
        info_detail = info.getElementsByTagName("port")
        for port_details in info_detail:
            protocol = port_details.getAttribute("protocol")
            port_number = port_details.getAttribute("portid")

            port_service = port_details.getElementsByTagName("state")
            for port_services in port_service:
                port_state = port_services.getAttribute("state")

                if(port_state == "open"):

                    service_info = port_details.getElementsByTagName("service")
                    for service_details in service_info:
                        service = service_details.getAttribute("name")
                        product = service_details.getAttribute("product")
                        version = service_details.getAttribute("version")

                        yield(port_number,protocol,service,product,version)

def xml2csv(info):
        '''Initiate parsing of nmap XML file and create CSV string object'''
	csv_string = ""
        csv_header = "IP Address,FQDN,OS,Port,Protocol,Service,Name,Version\n"
        csv_format = '{0},"{1}","{2}",{3},{4},"{5}","{6}","{7}"\n'

        csv_string += csv_header

        ip =  get_IP_Address(info)
        fqdn = get_FQDN(info)
        os = get_OS(info)

        for port,protocol,service,product,version in getiter_Port_Information(info):
        	csv_string += csv_format.format(ip,fqdn,os,port,protocol,service,product,version)
	
	csv_outfile = "%s/%s.csv" % (reconf.rsltpth, ip)
        csv_output = open(csv_outfile, "w")
        csv_output.write(csv_string)
        csv_output.close()
