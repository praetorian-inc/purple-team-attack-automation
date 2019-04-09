##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'T1201 Password Policy Discovery',
      'Description'   => %q{
        Discovery:
        Password policies for networks are a way to enforce complex passwords that are difficult to guess or crack through Brute Force. An adversary may attempt to access detailed information about the password policy used within an enterprise network. This would help the adversary to create a list of common passwords and launch dictionary and/or brute force attacks which adheres to the policy (e.g. if the minimum password length should be 8, then not trying passwords such as 'pass123'; not checking for more than 3-4 passwords per account if the lockout is set to 6 as to not lock out accounts).
        Password policies can be set and discovered on Windows, Linux, and macOS systems.},
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
     ))
  end

  def run
    begin
    raise "Requires meterpreter" if session.type != "meterpreter"

    print_status("checking local policy")
    cmd = "net accounts"
    output = cmd_exec(cmd)
    print_status(output)

    output = cmd_exec("net accounts /domain")
    output = cmd_exec(cmd)
    print_status(output)

    print_good("Module T1201 completed successfully")

    rescue ::Exception => e
      print_error("Unable to execute: #{e.message}")
      return
    end
  end
end
