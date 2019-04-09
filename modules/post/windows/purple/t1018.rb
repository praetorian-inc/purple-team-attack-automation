##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'Remote System Discovery (T1018) Windows - Purple Team',

                      'Description'   => %q{
                        Discovery:
                        Adversaries will likely attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system. Functionality could exist within remote access tools to enable this, but utilities available on the operating system could also be used.

                        Windows
                        Examples of tools and commands that acquire this information include "ping" or "net view" using Net.

                        Mac
                        Specific to Mac, the bonjour protocol to discover additional Mac-based systems within the same broadcast domain. Utilities such as "ping" and others can be used to gather information about remote systems.

                        Linux
                        Utilities such as "ping" and others can be used to gather information about remote systems.},
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'Platform'      => [ 'win' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1018' ] ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
  end

  def run
    begin
    raise 'This module requires a meterpreter session.' if session.type != "meterpreter"

    print_status("Using net view to attempt to locate machines on the network.")
    cmd = "net view"

    result = cmd_exec(cmd)
    print_status(result)
    print_good("Module T1018W execution successful.")

    rescue ::Exception => e
      print_error("#{e.message}")
      print_error("Module T1018W execution failed.")
    end
  end
end
