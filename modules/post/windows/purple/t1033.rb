##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Purple

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'System Owner/User Discovery (T1033) Windows - Purple Team ',
      'Description'   => %q{
        Discovery:
        Adversaries may attempt to identify the primary user, currently
        logged in user, set of users that commonly uses a system, or whether a user is
        actively using the system. They may do this, for example, by retrieving account
        usernames or by using Credential Dumping. The information may be collected in a
        number of different ways using other Discoverytechniques, because user and
        username details are prevalent throughout a system and include running process
        ownership, file/directory ownership, session information, and system logs.

        This module executes the following commands:
        wmic UserAccount get Name
        query user
        whoami
        net config workstation
        net user
        net user /domain
                            },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Praetorian' ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ],
      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1033'] ],
      ))
  end


  def run
    begin
      raise "Module requires meterpreter session." if session.type != "meterpreter"

      cmds = ["wmic UserAccount get Name", "query user", "whoami", "net config workstation", "net user", "net user /domain"]

      cmds.each { |cmd|
        begin
          run_cmd(cmd)
        rescue ::Exception => e
          print_error("#{e.message}")
          print_status("Enumeration method failed")
        end
      }

      print_good("Module T1033W execution successful.")
    rescue ::Exception => e
      print_error("#{e.message}")
      print_error("Module T1033W execution failed.")
    end
  end
end
