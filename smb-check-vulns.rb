#!/usr/bin/ruby
# = smb-check-vulns has been removed, this will iterate over all nse smb scripts to perhaps save some time - can extend this to any nse script later
# = add nse scripts to scripts hash below 

require 'optparse'

options = {:ports => nil,:ip => nil}
summary = ""

ARGV.push("-h") if ARGV.empty?
parse = OptionParser.new do |opts|
  opts.banner = "Usage: smb-check-vulns.rb [options]"
  opts.on("-p","--ports x,y","-[a-z]","Enter port or ports to scan comma seperated") do |port|
    options[:ports] = port
  end
  opts.on("-i","--ip x,y","ip address") do |ip|
    options[:ip] = ip
  end 
  opts.on("-h", "--help","Displays help")do
    puts opts
    exit
  end
  summary = opts.summarize
end.parse!

@scripts=["smb-vuln-conficker.nse","smb-vuln-cve2009-3103.nse","smb-vuln-ms06-025.nse","smb-vuln-ms07-029.nse","smb-vuln-ms08-067.nse","smb-vuln-ms10-054.nse","smb-vuln-ms10-061.nse","smb-vuln-regsvc-dos.nse"]
@ports = options[:ports]
@ip    = options[:ip]
@output= []
def check_vulns
  @scripts.each{|vuln|puts "[+] checking #{vuln}"; @output << %x[nmap -v #{@ip} -p #{@ports} --script=#{vuln}]}
end

def format_output
  @output.each{|result| puts "\n" + result.partition("VULNERABLE:").first.partition("report for ").last + result.partition("VULNERABLE:").last.partition("NSE: Script Post").first if result.include?("VULNERABLE")}
end

check_vulns
format_output
