# -*- coding: binary -*-

module Msf::Post::Windows::Purple

  #
  # Returns void
  # Checks to see if there is a calc.exe process running and if one is found kills it.
  #
  def kill_calc(finish=false)
    found_calc = false
    all_processes = client.sys.process.get_processes
    all_processes.each do |process|
      if process['name'] =~ /[Cc]alc/
        print_good("Found an instance of Calculator running. Killing it.")
        client.sys.process.kill(process['pid'])
        found_calc = true
      end
    end
    if finish and not found_calc
      print_warning("Calc not found module execution may have failed.")
    end
  end


  #
  # returns void
  # run a command on the remote host, if io is true
  # print the output of the command
  #
  def run_cmd(user_cmd,io=true)
    cmd = "cmd /c #{user_cmd}"
    begin
      print_status("Executing '#{cmd}' on #{session.inspect}")
      if io
        res = cmd_exec(cmd)
        if res
          print_warning(res)
        end
      else
        res = session.sys.process.execute(cmd, nil, {'Hidden' => true})
      end
    rescue ::Exception => e
      print_error("Unable to execute: #{e.message}")
      return
    end
  end


  #
  # Returns true if a calc process is running, false if not
  # Also prints out whether one is found or not found
  #
  def check_for_calc()
    session.sys.process.each_process do |process|
      if process['name'] =~ /[Cc]alc/i
        print_good("Found running calc process!")
        return true
      end
    end
    print_warning("Unable to find running calc process.")
    return false
  end
end
