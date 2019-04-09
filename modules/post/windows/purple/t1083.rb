##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Purple

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'File and Directory Discovery (T1083) Windows - Purple Team',
      'Description'   => %q{
        Discovery:
        Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a file system. Example utilities used to obtain this information are dir and tree.Custom tools may also be used to gather file and directory information and interact with the Windows API.},
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Praetorian' ],
      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1083' ] ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
     ))
    register_options(
    [
      OptString.new("CMD", [ true, "Command to execute with CMD.", "dir /s /b *.docx"])
    ])
  end

  def run
    return 0 if session.type != "meterpreter"

    cmd = datastore['CMD']
    begin
        run_cmd(cmd)

        print_good("Module T1083W execution successful.")
    rescue ::Exception => e
        print_error("Unable to execute: #{e.message}")
        print_error("Module T1083W execution failed.")
        return
    end
  end
end
