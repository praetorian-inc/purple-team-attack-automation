##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::SMB::Client
  include Msf::Exploit::Remote::SMB::Client::Authenticated

  include Msf::Auxiliary::Report

  # Aliases for common classes
  SIMPLE = Rex::Proto::SMB::Client
  XCEPT  = Rex::Proto::SMB::Exceptions
  CONST  = Rex::Proto::SMB::Constants


  def initialize
    super(
      'Name'        => 'SMB Connection Utility',
      'Description' => %Q{
	This module connects to a target share. This is only used by Praetorian's purple team modules.
      },
      'Author'      =>
        [
          'Praetorian'
        ],
      'References'  =>
        [
        ],
      'License'     => MSF_LICENSE
    )

    register_options([
      OptString.new('SMBSHARE', [true, 'The name of a writeable share on the server', 'C$']), 
    ])

  end

  def run
    print_status("Connecting to the server...")
    begin
      connect()
      smb_login()
      print_status("Mounting the remote share \\\\#{datastore['RHOST']}\\#{datastore['SMBSHARE']}'...")
            self.simple.connect("\\\\#{datastore['RHOST']}\\#{datastore['SMBSHARE']}")
    rescue Rex::Proto::SMB::Exceptions::Error => e
      # SMB has very good explanations in error messages, don't really need to
      # prefix with anything here.
      print_error("#{e}")
    end
  end
end

