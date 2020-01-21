##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Source (T1153) Linux macOS - Purple Team',
      'Description'    => %q(
      The source command loads functions into the current shell or executes
      files in the current context. This built-in command can be run in two
      different ways source /path/to/filename [arguments] or
      . /path/to/filename [arguments]. Take note of the space after the ".".
      Without a space, a new shell is created that runs the program instead of
       running the program within the current context. This is often used to
       make certain features or functions available to a shell or to update a
       specific shell's environment. Adversaries can abuse this functionality
       to execute programs. The file executed with this technique does not
       need to be marked executable beforehand.
      ),
      'License'        => MSF_LICENSE,
      'Author'         => [ 'Praetorian' ],
      'Platform'       => [ 'linux, osx' ],
      'References'     => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1153' ] ],
      'SessionTypes'   => [ 'meterpreter' ]))
    register_options(
      [
        OptBool.new("CLEANUP", [true, "Cleanup artifacts or not.", true])
      ])
  end

  def clean
    print_status("Cleaning up artifacts")

    cmd = "rm ~/t1153-source.sh ~/t1153-dot.sh ~/t1153-source-proof.txt ~/t1153-dot-proof.txt || echo fail"
    rm_script = cmd_exec(cmd)
    # Test for success
    if rm_script.include? 'fail'
      print_error("Failed to remove artifacts")
    end

    print_status("Cleanup complete")

  end

  def run
    return 0 if session.type != "meterpreter"

    # Module starting
    print_status('Testing the source command then a simple . to execute files')

    #### Tactic 1 - Using the 'source' command
    print_status('Testing the source command...')
    # Create the test script file
    cmd = "echo 'echo T1153-source | tee ~/t1153-source-proof.txt' > t1153-source.sh || echo fail"
    source = cmd_exec(cmd)
    # Test for success
    if source.include? 'fail'
      print_error("Failed to write source test script")
    end

    # Execute the file
    cmd = "source t1153-source.sh"
    test_source = cmd_exec(cmd)
    # Test for success
    if test_source.include? 'T1153-source'
      print_good('Tactic 1 - Source Command Successful!')
    else
      print_error('Tactic 1 - Source Command Failed.')
    end

    #### Tactic 2 - Using the '.' command
    print_status('Testing the . command...')
    # Create the test script file
    cmd = "echo 'echo T1153-dot | tee ~/t1153-dot-proof.txt' > t1153-dot.sh || echo fail"
    dot = cmd_exec(cmd)
    # Test for success
    if dot.include? 'fail'
      print_error("Failed to write dot test script")
    end

    # Execute the file
    cmd = ". t1153-dot.sh"
    test_source = cmd_exec(cmd)
    # Test for success
    if test_source.include? 'T1153-dot'
      print_good('Tactic 2 - Dot Command Successful!')
    else
      print_error('Tactic 2 - Dot Command Failed.')
    end

    clean if datastore['CLEANUP'] == true

  end
end
