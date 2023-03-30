#
# Vector Engine Driver
#
# Copyright (C) 2017-2018 NEC Corporation
# This file is part of VE Driver.
#
# VE Driver is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# VE Driver is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with the VE Driver; if not, see
# <http://www.gnu.org/licenses/>.
#

obj-m := ve_drv.o
ve_drv-objs := main.o main_ve3.o main_ve1.o fops.o fops_ve3.o fops_ve1.o \
               mmap.o mmap_ve1.o mmap_ve3.o \
               firmware_ve1.o ve_config_regs.o \
               sysfs.o sysfs_ve1.o sysfs_ve3.o decoder.o
ccflags-y += -I$(src)
