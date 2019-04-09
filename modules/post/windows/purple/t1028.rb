##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Purple

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'Windows Remote Management (T1028) Windows - Purple Team',
                      'Description'   => %q{
                        Execution, Lateral Movement:
                        Windows Remote Management (WinRM) is the name of both a Windows service and a protocol that allows a user to interact with a remote system (e.g., run an executable, modify the Registry, modify services). It may be called with the winrm command or by any number of programs such as PowerShell.},
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1028' ] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
    [
      OptString.new('CMD', [ true, "Command to execute", 'winrm qc -q & winrm i c wmicimv2/Win32_Process @{CommandLine="calc"}']),
      OptBool.new('CLEANUP', [true, "Close any instances of calc", true])
    ])
  end

  def run
    begin
      raise "Module requires meterpreter session." if session.type != "meterpreter"
      fail_with(Failure::NoAccess, "Module requires administrator rights.") if not is_admin?

      kill_calc()

      cmd = datastore['CMD']
      run_cmd(cmd)

      print_good('Module T1028W execution successful.')
      if datastore['CLEANUP']
        kill_calc(true)
      end

    rescue ::Exception => e
      print_error("#{e.message}")
      print_error("Module T1028W execution failed.")
    end
   end
end
