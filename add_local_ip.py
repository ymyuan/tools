import os
import sys

def handle_local_ip(ip_range, aciton):
  ip_list = []
  raw_list = ip_range.split("-")
  if len(raw_list) == 1:
    print "len==1"
    os.system("ip addr %s %s/32 dev lo" %(aciton, raw_list[0]))
    print "Complete %s %s" %(aciton, raw_list[0])
  else:
    start = raw_list[0].split(".")[-1]
    ip_prefix = ".".join(raw_list[0].split(".")[0:3]) + "."
    end = raw_list[1]
    for i in range(int(start), int(end) + 1):
	os.system("ip addr %s %s/32 dev lo" %(aciton, ip_prefix + str(i)))
        print "Complete %s %s" %(aciton, ip_prefix + str(i))
  print "Handle local ip complete."

def pre_check_ip(ip_range):
  print "should be check ip format"

if __name__=="__main__":
  if len(sys.argv) <= 2:
    print "\nUsage:\n\tpython %s <add | del> <local_ip_range>" %sys.argv[0]
    print "\t\t <local_ip_range> format is $ip_addr-$num, eg:192.168.80.0-10"
    print "Exit!!"
    sys.exit(1)
  if sys.argv[1] not in ["add", "del"]:
    print "\nError: first parameter should only be 'add' or 'del', not %s" %sys.argv[1]
    print "Exit!!"
    sys.exit(1)
  pre_check_ip(sys.argv[2])

  action = sys.argv[1]
  ip_range = sys.argv[2]

  handle_local_ip(ip_range, action)
  print "End"	

