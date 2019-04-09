##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Purple

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'System Information Discovery (T1082) Windows - Purple Team',
                      'Description'   => %q{
                        Discovery:
                        An adversary may attempt to get detailed information about the operating system and hardware, including version, patches, hotfixes, service packs, and architecture.},
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1082' ] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
    [
      OptString.new("CMD", [ true, "Command to execute with CMD.", 'systeminfo'])
    ])
  end

  def run
    begin
      raise "Module requires meterpreter session" if session.type != "meterpreter"

      cmd = datastore['CMD']
      run_cmd(cmd)

      print_good("Module T1082W execution successful.")

    rescue ::Exception => e
        print_error("#{e.class}: #{e.message}")
        print_error("Module T1082W execution failed.")
    end
   end
end
