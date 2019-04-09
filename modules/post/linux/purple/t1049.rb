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
      'Name'          => 'System Network Connection Discovery (T1049) Linux - Purple Team',
      'Description'   => %q{
        Discovery:
        Adversaries may attempt to get a listing of networkconnections to or from the compromised system. Utilities and commands that acquire this information include netstat, "net use," and "net session" with Net. },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Praetorian' ],
      'Platform'      => [ 'linux' ],
      'SessionTypes'  => [ 'meterpreter' ],
      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1049'] ],
      ))
  end

  def run
    return 0 if session.type != "meterpreter"

    print_status("Obtaining networking information.")

    cmds = ["/bin/netstat -pantu", "/usr/bin/who -a"]
    cmds.each do |cmd|
      begin
        print_status("Executing command #{cmd}...")
        print_good(cmd_exec(cmd))
      rescue ::Exception => e
        print_error("Error running command #{cmd}: #{e.class} #{e}")
      end
    end
  end
end
