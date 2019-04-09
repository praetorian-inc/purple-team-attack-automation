##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post

    def initialize(info={})
      super(update_info(info,
                        'Name'          => 'Remote System Discovery (T1018) Linux macOS - Purple Team',
                        'Description'   => %q{
                              Discovery:
                              Adversaries will likely attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system. Functionality could exist within remote access tools to enable this, but utilities available on the operating system could also be used. Examples of tools and commands that acquire this information include "ping" or "net view" using Net. },
                        'License'       => MSF_LICENSE,
                        'Author'        => [ 'Praetorian' ],
                        'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1018' ] ],
                        'Platform'      => [ 'osx', 'linux' ],
                        'SessionTypes'  => [ 'meterpreter' ]
                       ))
      register_options(
      [
        OptAddressRange.new('RHOSTS', [true, 'IP Range to scan']),
        OptBool.new('SCAN', [true, 'Ping sweep. If False, runs \'arp -a \'.', true])
      ])
    end

    def all_platforms
      Msf::Module::Platform.subclasses.collect {|c| c.realname.downcase }
    end

    def run_module(mod)
      framework_mod = framework.modules.create(mod)
      framework_mod.datastore['RHOSTS'] = datastore['RHOSTS']
      framework_mod.datastore['SESSION'] = datastore['SESSION']
      framework_mod.run_simple(
          'LocalInput' => self.user_input,
          'LocalOutput' => self.user_output,
          'Quiet' => false,
          'RunAsJob'  => false)

      select(nil,nil,nil,2)
    end

    def run
      return 0 if session.type != "meterpreter"

      mod = 'post/multi/gather/ping_sweep'
      scan = datastore['SCAN']

      if scan
        begin
          print_status("Executing '#{mod}' on #{session.inspect}")
          run_module(mod)
          print_good("Successful execution!")
        rescue ::Exception => e
            print_error("Unable to execute: #{e.message}")
            return
        end
      else
        arp = 'arp -a'
        result = cmd_exec(arp)
        print_good(result)
      end
    end
  end
