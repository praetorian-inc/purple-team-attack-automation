##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Purple

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'Application Window Discovery (T1010) Windows - Purple Team',
                      'Description'   => %q{
                        Discovery:
                        Adversaries may attempt to get a listing of open application windows. Window listings could convey information about how the system is used or give context to information collected by a keylogger.},
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1010' ] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
    [
      OptString.new("CMD", [ true, "Command to execute with CMD.", 'tasklist /fo list /v| find "Window Title" |find /V "N/A"'])
    ])
  end

  def run
    begin
      raise 'Module requires Meterpreter session' if session.type != "meterpreter"

      cmd = datastore['CMD']
      run_cmd(cmd)
      print_good("Module T1010W execution successful.")
    rescue ::Exception => e
      print_error("#{e.message}")
      print_error("Module T1010W execution failed.")
    end
  end
end
