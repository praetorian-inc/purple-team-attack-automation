##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Purple
  include Msf::Post::Windows::Powershell

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'System Service Discovery (T1007) Windows - Purple Team',
                      'Description'   => %q{
                        Discovery:
                        Adversaries may try to get information about registered services.
                        Commands that may obtain information about services using operating system
                        utilities are "sc," "tasklist /svc" using Tasklist, and "net start" using Net,
                        but adversaries may also use other tools as well. },
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1007' ] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
  end

  def run
    begin
      raise 'Module requires Meterpreter session.' if session.type != "meterpreter"

      print_status("Grabbing service info using service control manager.")
      cmds = ["sc query state= all", "net start"]
      cmds.each do |cmd|
        run_cmd(cmd)
      end
      cmd = "get-service"
      print_status("Loading PowerShell")
      client.run_cmd("load powershell")
      print_status("Executing 'get-service'")
      client.run_cmd("powershell_execute get-service")
      print_good("Module T1007W execution successful.")
    rescue ::Exception => e
      print_error(e.message)
      print_error("Module T1007W execution failed.")
    end
  end
end
