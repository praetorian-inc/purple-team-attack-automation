##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Purple

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'System Network Connections Discovery (T1049) Windows - Purple Team',
                      'Description'   => %q{
                        Discovery:
                        Adversaries may attempt to get a listing of network connections to or from the compromised system. Utilities and commands that acquire this information include netstat, "net use," and "net session" with Net. },
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'Platform'      => [ 'win' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1049' ] ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
  end

  def run
    begin
      raise "Module requires meterpreter session." if session.type != "meterpreter"

      print_status("Obtaining networking information using netstat and net")
      run_cmd("netstat -ano")
      run_cmd("net use")
      run_cmd("net session")

      print_good("Module T1049W execution successful.")

    rescue ::Exception => e
      print_error("#{e.message}")
      print_error("Module T1049W execution failed.")
    end
  end
end
