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
                      'Name'          => 'Security Software Discovery (T1063) Windows - Purple Team',
                      'Description'   => %q{
                        Discovery:
                        Adversaries may attempt to get a listing of security software, configurations, defensive tools, and sensors that are installed on the system. This may include things such as local firewall rules, anti-virus, and virtualization. These checks may be built into early-stage remote access tools.},
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1063' ] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
    [
      OptString.new("CMD", [ true, "Command to execute with CMD.", 'netsh.exe advfirewall show allprofiles'])
    ])
  end


  def run
    begin
      raise "Module requires meterpreter session" if session.type != "meterpreter"

      cmd = datastore['CMD']
      run_cmd(cmd)

      print_good("Module T1063W execution successful.")

    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1063W execution failed.")
    end
   end
end
