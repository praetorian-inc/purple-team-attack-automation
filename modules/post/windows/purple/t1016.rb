##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'System Network Configuration Discovery (T1016) Windows Purple Team',
                      'Description'   => %q{
                        Discovery:
                        Adversaries will likely look for details about the network
                        configuration and settings of systems they access. Several operating system
                        administration utilities exist that can be used to gather this information.
                        Examples include Arp, ipconfig/ifconfig, nbtstat, and route. },
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'Platform'      => [ 'win' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1016' ] ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
  end

  def run
    begin
      raise 'This module requires a meterpreter session.' if session.type != "meterpreter"

      print_status("Grabbing interface data using ipconfig.")
      cmd = "ipconfig /all"
      result = cmd_exec(cmd)
      print_status(result)
      print_good("Module T1016W execution successful.")

    rescue ::Exception => e
      print_error("#{e.message}")
      print_error("Module T1016W execution failed.")
    end
  end
end
