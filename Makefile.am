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
include_HEADERS = src/ve_drv.h
EXTRA_DIST = src/Makefile src/main.c src/fops.c src/firmware.c \
	     src/mmap.c src/fpga.c src/sysfs.c src/ve_drv.h src/decoder.h \
	     src/internal.h src/hw.h src/gen_code.sh \
	     src/ve_drv.conf \
	     src/Module.symvers src/vp.h src/sensor.h \
	     src/commitid.h \
	     src/ve_drv-ctl systemd/ve_drv.service.in \
	     dracut/ve_drv.conf \
	     ve_drv-kmod.spec \
	     debian
CLEANFILES = systemd/ve_drv.service

# git commit id
src/commitid.h:
	echo "#define COMMITID \"`git log --pretty=format:"%H" -n 1`\"" >> $@

# symvers of vp module
src/Module.symvers:
	cp @prefix@/src/ve_kernel/Module.symvers $(abs_top_builddir)/src
# header file of vp module
src/vp.h:
	cp @prefix@/include/vp.h $(abs_top_builddir)/src
src/sensor.h:
	$(srcdir)/src/gen_code.sh $(srcdir)/src/sensor.tbl
	mv sensor.h $(abs_top_builddir)/src/
src/ve_drv.ko: src/Module.symvers src/vp.h src/sensor.h src/commitid.h
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
	$(RM) $(abs_top_builddir)/src/sensor.h
	$(RM) $(abs_top_builddir)/src/vp.h
	$(RM) $(abs_top_builddir)/src/Module.symvers

rpm: dist
	mkdir -p $(distdir)/rpmbuild/{BUILD,RPMS,SOURCES,SRPMS,SPECS}
	rpmbuild -ta --clean --define='_topdir $(CURDIR)/$(distdir)/rpmbuild' ${distdir}.tar.gz
