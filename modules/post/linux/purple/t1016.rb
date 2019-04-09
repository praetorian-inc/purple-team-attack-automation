##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

include Msf::Post::File
include Msf::Post::Linux::Priv
include Msf::Post::Linux::System

class MetasploitModule < Msf::Post

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'System Network Configuration Discovery (T1016) Linux - Purple Team',
                      'Description'   => %q{
                        Discovery:
                        Adversaries will likely look for details about the network
                        configuration and settings of systems they access. Several operating system
                        administration utilities exist that can be used to gather this information.
                        Examples include Arp, ipconfig/ifconfig, nbtstat, and route. },
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'Platform'      => [ 'linux' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1016'] ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
  end

  def run
    return 0 if session.type != "meterpreter"

    cmds = ["/sbin/ifconfig -a", "/usr/sbin/arp -a", "/sbin/iwconfig", "/sbin/route"]
    cmds.each do |cmd|
      print_status("Executing command #{cmd}...")
      print_good(cmd_exec(cmd))
    end
  end
end
