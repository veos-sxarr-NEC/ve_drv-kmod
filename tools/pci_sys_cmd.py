#!/usr/bin/python2

import argparse
import shutil
import subprocess
import pyudev

def list_specific_device_id_sys_path( list_devid ):
    syspath = []
    context = pyudev.Context()
    for device in context.list_devices(subsystem='pci'):
        device_file = open(device.sys_path+"/device", 'r')
        devid_str = device_file.read(6)
        devid = int(devid_str, 16)
        if devid == list_devid:
            syspath.append(device.sys_path)
        device_file.close()
    return syspath

def doman_bus_dev_func( sysfs_path ):
    dbdf = {"domain":"FFFF", "bus":"FF", "dev":"FF", "func":"F"}
    if sysfs_path == None:
        return None
    path_split = sysfs_path.split("/")
    path_split_last = path_split[len(path_split)-1]
    dbdf["domain"] = path_split_last.split(":")[0]
    dbdf["bus"] = path_split_last.split(":")[1]
    devfn = path_split_last.split(":")[2]
    dbdf["dev"] = devfn.split(".")[0]
    dbdf["func"] = devfn.split(".")[1]
    return dbdf

parser = argparse.ArgumentParser(description=\
        'List sysfs path of specified PCI device id.')
parser.add_argument('deviceid', metavar='PCIDEVID', type=str, nargs=1,\
       help='PCI device id')
parser.add_argument('-d', action='store_true', default=False, dest='show_dbdf',\
       help='Show Domain:Bus:Dev:Func')
parser.add_argument('-p', action='store_true', default=False, dest='show_path',\
       help='Show sysfs path')
parser.add_argument('-l', action='store_true', default=False,\
       dest='show_lspci', help='Show "lspci -v" result')
parser.add_argument('-s', action='store_true', default=False,\
       dest='store_config', help='Store PCI config to /tmp')
parser.add_argument('-r', action='store_true', default=False,\
       dest='restore_config', help='Restore PCI config from /tmp')

args = parser.parse_args()
list_devid = int(args.deviceid[0], 0)

path_array = list_specific_device_id_sys_path(list_devid)
for path in path_array:
    dbdf = doman_bus_dev_func (path)
    if args.show_dbdf:
        print "Domain = "+dbdf["domain"]+" Bus = "+dbdf["bus"]+\
                " Dev = "+dbdf["dev"]+" Func "+dbdf["func"]
    if args.show_path:
        print path
    if args.show_lspci:
        arg = dbdf["bus"]+":"+dbdf["dev"]+"."+dbdf["func"]
        subprocess.call(["lspci", "-v", "-s", arg])
    if args.store_config:
        src = path+"/config"
        dst = "/tmp/"+dbdf["bus"]+".config.bak"
        shutil.copy(src, dst)
    if args.restore_config:
        src = "/tmp/"+dbdf["bus"]+".config.bak"
        dst = path+"/config"
        shutil.copy(src, dst)
