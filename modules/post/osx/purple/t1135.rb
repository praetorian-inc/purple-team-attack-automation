##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'Network Share Discovery (T1135) macOS - Purple Team',
      'Description'    => %q{
        Discovery:
        Networks often contain shared network drives and folders that enable users to access file directories on various systems across a network.
      },
      'License'        => MSF_LICENSE,
      'Author'         => [ 'Praetorian' ],
      'Platform'       => [ 'osx' ],
      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1135' ] ],
      'SessionTypes'        => [ 'meterpreter' ]
     ))
  end

  def run
    return 0 if session.type != "meterpreter"

    print_status("Attempting to list locally mounted shares.")
    result = cmd_exec("/bin/df -ah")
    print_good result
    print_good("Module finished with success!")
    end
end
