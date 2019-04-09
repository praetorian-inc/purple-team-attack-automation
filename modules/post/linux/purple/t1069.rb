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
                      'Name'          => 'Permissions Groups Discovery (T1069) Linux - Purple Team',
                      'Description'   => %q{
                        Discovery:
                        Adversaries may attempt to find local system or domain
                        level groups and permission settings. Examples of commands that can
                        list groups are net group / domain and net localgroups using the
                        NET Utility. },
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'Platform'      => [ 'linux' ],
                      'References'    => [ ['URL','https://attack.mitre.org/techniques/T1069/'] ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
  end

  def run
    return 0 if session.type != "meterpreter"

    cmds = ["/usr/bin/groups", "/bin/cat /etc/groups", "/usr/bin/sudo -l"]
    cmds.each do |cmd|
      begin
        print_status("Executing command #{cmd}...")
        print_good(cmd_exec(cmd))
      rescue ::Exception => e
        print_error("Error running command #{cmd}: #{e.class} {#e}")
      end
    end
  end
end
