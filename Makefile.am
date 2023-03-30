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

ACLOCAL_AMFLAGS = -I m4
sbin_SCRIPTS = src/ve_drv-ctl
include_HEADERS = src/ve_drv.h src/ve_drv_ve1.h src/ve_drv_ve3.h
SENSOR_HDRS = src/sensor_ve1.h src/sensor_ve3.h
EXTRA_DIST = src/Makefile src/main.c src/main_ve1.c src/main_ve3.c \
	     src/firmware_ve1.c \
	     src/fops.c src/fops_ve1.c src/fops_ve3.c \
	     src/mmap.c src/mmap_ve1.c src/mmap_ve3.c \
	     src/sysfs.c src/sysfs_ve1.c src/sysfs_ve3.c \
	     src/sysfs_sensor_attr_gen.h src/ve_config_regs.c \
	     src/ve_drv.h src/ve_drv_ve1.h src/ve_drv_ve3.h \
	     src/decoder.h src/decoder.c \
	     src/internal.h src/internal_ve1.h src/internal_ve3.h \
	     src/hw.h src/hw_ve1.h src/hw_ve3.h src/gen_code.sh \
	     src/mmio.h src/mmio_ve1.h src/mmio_ve3.h \
	     src/ve_drv.conf \
	     src/Module.symvers src/vp.h $(SENSOR_HDRS) src/sensor_ve1.tbl src/sensor_ve3.tbl \
	     src/commitid.h \
	     src/ve_drv-ctl systemd/ve_drv.service.in \
	     dracut/ve_drv.conf \
	     ve_drv-kmod.spec \
	     debian
CLEANFILES = systemd/ve_drv.service $(SENSOR_HDRS) src/commitid.h
dist_noinst_DATA = helper/ve_check_config

# git commit id
src/commitid.h:
	echo "#define COMMITID \"`git log --pretty=format:"%H" -n 1`\"" >> $@

# symvers of vp module
src/Module.symvers:
	cp @prefix@/src/ve_kernel/Module.symvers $(abs_top_builddir)/src
# header file of vp module
src/vp.h:
	cp @prefix@/include/vp.h $(abs_top_builddir)/src
src/sensor_ve1.h: src/sensor_ve1.tbl
	$(srcdir)/src/gen_code.sh $(srcdir)/src/sensor_ve1.tbl > sensor_ve1.h
	mv sensor_ve1.h $(abs_top_builddir)/src/
src/sensor_ve3.h: src/sensor_ve3.tbl
	$(srcdir)/src/gen_code.sh $(srcdir)/src/sensor_ve3.tbl > sensor_ve3.h
	mv sensor_ve3.h $(abs_top_builddir)/src/

src/ve_drv.ko: src/Module.symvers src/vp.h $(SENSOR_HDRS) src/sensor_ve1.tbl src/sensor_ve3.tbl src/commitid.h
	for file in $(EXTRA_DIST); do \
		test -f $(builddir)/$$file || \
		$(LN_S) $(abs_top_srcdir)/$$file $(builddir)/src; \
	done
	$(MAKE) -C $(KERNEL_SRC) M=$(abs_top_builddir)/src

all-local: src/ve_drv.ko

systemd/ve_drv.service: systemd/ve_drv.service.in
	$(SED) -e 's|@sbindir[@]|$(sbindir)|g' $< > $@

install-exec-hook: src/ve_drv.ko systemd/ve_drv.service
	$(MKDIR_P) $(DESTDIR)$(KERNEL_MOD)
	$(INSTALL_DATA) $(builddir)/src/ve_drv.ko $(DESTDIR)$(KERNEL_MOD)/
	$(MKDIR_P) $(DESTDIR)/etc/modprobe.d/
	$(INSTALL_DATA) $(builddir)/src/ve_drv.conf $(DESTDIR)/etc/modprobe.d/
	$(MKDIR_P) $(DESTDIR)/etc/dracut.conf.d/
	$(INSTALL_DATA) $(builddir)/dracut/ve_drv.conf $(DESTDIR)/etc/dracut.conf.d/
	$(MKDIR_P) $(DESTDIR)$(SYSTEMD_UNITDIR)
	$(INSTALL_DATA) $(builddir)/systemd/ve_drv.service \
		$(DESTDIR)$(SYSTEMD_UNITDIR)/ve_drv.service

clean-local:
	$(MAKE) -C $(KERNEL_SRC) M=$(abs_top_builddir)/src clean
	$(RM) $(abs_top_builddir)/$(SENSOR_HDRS)
	$(RM) $(abs_top_builddir)/src/commitid.h
	$(RM) $(abs_top_builddir)/src/vp.h
	$(RM) $(abs_top_builddir)/src/Module.symvers

rpm: dist
	mkdir -p $(distdir)/rpmbuild/{BUILD,RPMS,SOURCES,SRPMS,SPECS}
	rpmbuild -ta --clean --define='_topdir $(CURDIR)/$(distdir)/rpmbuild' ${distdir}.tar.gz
