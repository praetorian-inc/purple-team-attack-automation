##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Purple

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'Data from Local System (T1005) Windows - Purple Team',
                      'Description'   => %q{
                        Collection:
                        Sensitive data can be collected from local system sources, such as the file system or databases of information residing on the system prior to Exfiltration.

                        Adversaries will often search the file system on computers they have compromised to find files of interest. They may do this using a Command-Line Interface, such as cmd, which has functionality to interact with the file system to gather information. Some adversaries may also use Automated Collection on the local system.
                                            },
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1005' ] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
    [
      OptString.new("CMD", [ true, "Command to execute with CMD.", "dir /s /b *.doc*"])
    ])
  end

  def run()
    return 0 if session.type != "meterpreter"

    cmd = datastore['CMD']
    begin
        res = run_cmd(cmd)
        print_good("Module T1005W execution successful.")
    rescue ::Exception => e
        print_error("Unable to execute: #{e.message}")
        print_error("Module T1005W execution failed.")
        return
    end
  end
end
