##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Exploit::FileDropper
  include Msf::Post::Windows::Priv

  def initialize(info={})
    super(update_info(info,
        'Name'          => 'Remote File Copy (T1105) Windows - Purple Team',
        'Description'   => %q{
          Command and Control, Lateral Movement:
          Files may be copied from one system to another to stage adversary tools or other files over the course of an operation.
          Files may be copied from an external adversary-controlled system through the Command and Control channel to bring tools
          into the victim network or through alternate protocols with another tool such as FTP.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Praetorian' ],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ],
        'References'    => [ 'https://attack.mitre.org/wiki/Technique/T1105']
    ))

    register_options(
      [
        OptString.new('LPATH', [ false, 'Local file to copy to remote host. Default is the string "test".']),
        OptString.new('RPATH', [ true, 'Remote path to copy a file to.', 'C:\\t1105.txt']),
        OptBool.new('CLEANUP', [ false, 'Clean up file created during the module.', true])
      ])
  end

  def run
    begin
      raise "Module requires meterpreter session" unless session.type == 'meterpreter'
      fail_with(Failure::NoAccess, "Module requires administrator rights.") unless is_admin?


      local_path = datastore['LPATH']
      remote_path = datastore['RPATH']

      if local_path
        lfile = ::File.read(local_path)
      else
        lfile = "\ntest\r\n"
      end

      print_status("Uploading #{lfile.length} bytes...")
      write_file(remote_path, lfile)
      if datastore['CLEANUP']
        register_file_for_cleanup(remote_path)
      end

      print_good("Uploaded to #{remote_path}.")
      print_good("Module T1105W execution successful.")

    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1105W execution failed.")
    end
  end
end
