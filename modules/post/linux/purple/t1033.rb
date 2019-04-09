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
      'Name'          => 'System Owner/User Discovery (T1033) Linux - Purple Team',
      'Description'   => %q{
        Discovery:
        Adversaries may attempt to identify the primary user, currently
        logged in user, set of users that commonly uses a system, or whether a user is
        actively using the system. They may do this, for example, by retrieving account
        usernames or by using Credential Dumping. The information may be collected in a
        number of different ways using other Discoverytechniques, because user and
        username details are prevalent throughout a system and include running process
        ownership, file/directory ownership, session information, and system logs. },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Praetorian' ],
      'Platform'      => [ 'linux' ],
      'SessionTypes'  => [ 'meterpreter' ],
      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1033'] ],
      ))
  end

  def run
    return 0 if session.type != "meterpreter"

    print_status("Enumerating all users on the system.")
    cmds = ["/usr/bin/whoami", "/usr/bin/id", "/usr/bin/w", "/bin/cat /etc/passwd", "/bin/cat /etc/group", "/bin/cat /etc/sudoers"]
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

