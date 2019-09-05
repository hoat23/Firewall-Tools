# use local implementation, not the installed gem (if any)
$LOAD_PATH.unshift(File.dirname(__FILE__) + "/lib")

require 'snmp/mib'

if ARGV.size == 1
  mib_path = ARGV[0]
else
  smilint_version = `smilint --version`
  libsmi_version = smilint_version.split[1]
  mib_path = "/usr/local/Cellar/libsmi/#{libsmi_version}/share/mibs/ietf"
end

Dir["#{mib_path}/*"].each do |file|
  print file
  if (File.basename(file) == 'DOT12-RPTR-MIB')
    puts " (skipping)"
  else
    puts
    SNMP::MIB::import_module(file)
  end
end
