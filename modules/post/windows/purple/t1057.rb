##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Purple

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'Process Discovery (T1057) Windows - Purple Team',
                      'Description'   => %q{
                        Discovery:
                        Adversaries may attempt to get information about running processes on a system. An example command that would obtain details on processes is "tasklist" using the Tasklist utility. Information obtained could be used to gain an understanding of common software running on systems within the network. },
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'Platform'      => [ 'win' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1057' ] ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
  end

  def run
    begin
      raise "Module requires meterpreter session" if session.type != "meterpreter"

      run_cmd("tasklist /v")

      print_good("Module T1057 execution successful.")

    rescue ::Exception => e
      print_error("#{e.class} #{e}")
      print_error("Module T1057 execution failed.")
    end
  end
end
