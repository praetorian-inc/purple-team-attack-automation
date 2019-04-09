##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Purple

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'Network Share Discovery (T1135) Windows - Purple Team',
                      'Description'   => %q{
                        Discovery:
                        Networks often contain shared network drives and folders
                       that enable users to access file directories on various systems across
                       a network. },
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'Platform'      => [ 'win' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1135' ] ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
      [
        OptString.new("REMOTESERVER", [ true, "Remote Server to check fileshares", ""])
      ])
  end

  def run
    begin
      return 0 if session.type != "meterpreter"

      print_status("Grabbing network shares from #{datastore['REMOTESERVER']}.")

      run_cmd("net view \\\\#{datastore['REMOTESERVER']}")
      print_good("Module T1135W execution successful.")
    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1135W execution failed.")
    end
   end
end
