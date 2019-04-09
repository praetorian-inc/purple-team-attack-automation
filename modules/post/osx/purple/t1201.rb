##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'nokogiri'

class MetasploitModule < Msf::Post

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'Password Policy Discovery (T1201) macOS - Purple Team',
      'Description'    => %q{
        Discovery:
        Password policies for networks are a way to enforce complex passwords that are difficult to guess or crack through Brute Force. An adversary may attempt to access detailed information about the password policy used within an enterprise network. This would help the adversary to create a list of common passwords and launch dictionary and/or brute force attacks which adheres to the policy (e.g. if the minimum password length should be 8, then not trying passwords such as 'pass123'; not checking for more than 3-4 passwords per account if the lockout is set to 6 as to not lock out accounts).
      },
      'License'        => MSF_LICENSE,
      'Author'         => [ 'Praetorian' ],
      'Platform'       => [ 'osx' ],
      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1201' ] ],
      'SessionTypes'        => [ 'meterpreter' ]
     ))
    register_options(
      [
        OptString.new("ACCOUNT", [false, "If defined, grabs the password policy for this account in particular, if not specified, grabs the global password policy.", ""])
      ])
  end

  def run
    return 0 if session.type != "meterpreter"

    pwpolicy = cmd_exec("/usr/bin/pwpolicy getaccountpolicies #{datastore['ACCOUNT']}")

    if pwpolicy.include?("Getting global account policies") || pwpolicy.include?("Getting account policies for user #{datastore['ACCOUNT']}")
      print_good pwpolicy
      matches = pwpolicy.scan(/(?<=<key>policyContent<\/key>\W).*/)
      matches.each do |matchee|
        print_good matchee.lstrip
      end
    else
      print_error pw_policy
    end

   print_good("Module execution has finished!")
   end
end
