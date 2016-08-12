#!/usr/bin/env ruby
# -*- coding: binary -*-
# created by @nopernik
#
# this file should be run from metasploit-framwork installation path
# cd /usr/share/metasploit-framework
# wget https://raw.githubusercontent.com/jivoi/pentest/master/msfvenom_bash_completion.rb
# +x msfvenom_bash_completion.rb
# ./msfvenom_bash_completion.rb


msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), 'lib')))
require 'msfenv'

$:.unshift(ENV['MSF_LOCAL_LIB']) if ENV['MSF_LOCAL_LIB']

require 'msf/base'
  def init_framework(create_opts={})
    create_opts[:module_types] ||= [
      ::Msf::MODULE_PAYLOAD, ::Msf::MODULE_ENCODER, ::Msf::MODULE_NOP
    ]
    @framework = ::Msf::Simple::Framework.create(create_opts.merge('DisableDatabase' => true))
  end

  def framework
    return @framework if @framework

    init_framework

    @framework
  end

if __FILE__ == $0


$stdout.puts ' '
$stdout.puts "[+] Collecting output formats"
formats = ::Msf::Util::EXE.to_executable_fmt_formats + ::Msf::Simple::Buffer.transform_formats
formats = formats.join(' ')

$stdout.puts "[+] Collecting payloads"
init_framework(:module_types => [ ::Msf::MODULE_PAYLOAD ])
tbl = []
framework.payloads.each_module { |name|
   tbl += [ "\t"+name+" \\\n" ]
}
payloads = tbl.join('')

tbl = []
$stdout.puts "[+] Collecting encoders"
init_framework(:module_types => [ ::Msf::MODULE_ENCODER ])
framework.encoders.each_module { |name|
   tbl += [ "\t"+name+" \\\n" ]
}
encoders = tbl.join('')

tbl = []
$stdout.puts "[+] Collecting nops"
init_framework(:module_types => [ ::Msf::MODULE_NOP ])
framework.nops.each_module { |name|
   tbl += [ "\t"+name+" \\\n" ]
}
nops = tbl.join('')

$stdout.puts "[+] Generating bash_completion file"

comp = '
# bash completion for msfvenom by Korznikov Alexander

_msfvenom()
{
    local cur prev

    COMPREPLY=()
    cur=`_get_cword`
    prev=`_get_pword`

    case $prev in

         -f|--format)
            COMPREPLY=( $( compgen -W \' %s \' -- "$cur" ) )
            return 0
            ;;
         -e|--encoder)
            COMPREPLY=( $( compgen -W \' %s \' -- "$cur" ) )
            return 0
            ;;
         -p|--payload)
            COMPREPLY=( $( compgen -W \' %s \' -- "$cur" ) )
            return 0
            ;;
    esac

    if [[ "$cur" == * ]]; then
    COMPREPLY=( $( compgen -W \' -p --payload -l --list -n --nopsled -f --format -e --encoder \
            -a --arch --platform -s --space -b --bad-chars -i --iterations \
            -c --add-code -x --template -k --keep --payload-options -o \
            --out -v --var-name -h --help --help-formats \' -- "$cur" ) )


    onlyonce=\' -p --payload -l --list -n --nopsled -f --format -e --encoder \
            -a --arch --platform -s --space -b --bad-chars -i --iterations \
            -c --add-code -x --template -k --keep --payload-options -o \
            --out -v --var-name -h --help --help-formats \'
    COMPREPLY=( $( \
           (while read -d \' \' i; do
            [[ -z "$i" || "${onlyonce/ ${i%%%% *} / }" == "$onlyonce" ]] &&
            continue
            # flatten array with spaces on either side,
            # otherwise we cannot grep on word boundaries of
            # first and last word
            COMPREPLY=" ${COMPREPLY[@]} "
            # remove word from list of completions
            COMPREPLY=( ${COMPREPLY/ ${i%%%% *} / } )
            done
            printf \'%%s \' "${COMPREPLY[@]}") <<<"${COMP_WORDS[@]}"
          ) )

#    else
#        _filedir
    fi
} &&
complete -F _msfvenom msfvenom

' % [formats, encoders, payloads]

$stdout.puts "[+] Writing out /etc/bash_completion.d/msfvenom"
File.write('/etc/bash_completion.d/msfvenom', comp)
$stdout.puts "[+] Done. Open a new terminal and type msfvenom TABTAB :)"

exit(0)

end
