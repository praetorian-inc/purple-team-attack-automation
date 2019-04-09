##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  include Msf::Post::File
  include Msf::Post::Linux::Priv
  include Msf::Post::Linux::System

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'Process Discovery (T1057) Linux - Purple Team',
                      'Description'   => %q{
                        Discovery:
                        Adversaries may attempt to get information about running
                        processes on a system. An example command that would obtain details on
                        processes is "tasklist" using the Tasklist utility. Information
                        obtained could be used to gain an understanding of common software
                        running on systems within the network. },
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'Platform'      => [ 'linux' ],
                      'References'    => [ ['URL','https://attack.mitre.org/techniques/T1057/'] ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
  end

  def run
    return 0 if session.type != "meterpreter"

    print_status("Running 'ps -ef'")

    begin
      result = cmd_exec("/bin/ps -ef")
      print_good(result)
    rescue ::Exception => e
      print_error("Error running command ps -ef: #{e.class} #{e}")
    end
  end
end
