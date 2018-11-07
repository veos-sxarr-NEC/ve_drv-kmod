#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
AC_PREREQ([2.69])
AC_INIT([ve_drv-kmod], [1.3.2])
AC_CONFIG_SRCDIR([src/main.c])
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

AC_SUBST(KERNEL)
AC_ARG_WITH([kernel], [AS_HELP_STRING([--with-kernel],
	    [Specify kernel version])],
	    [KERNEL=${with_kernel}],
	    [KERNEL=`uname -r`])
AC_DEFINE_UNQUOTED([KERNEL], ["$KERNEL"], [kernel version])
AC_SUBST([with_kernel_mod], [/lib/modules/$KERNEL/extra])
AC_SUBST([KERNEL_SRC], [/lib/modules/$KERNEL/build])
AC_SUBST([KERNEL_MOD], [$with_kernel_mod])
AC_SUBST(RELEASE)
AC_ARG_WITH([release-id], [AS_HELP_STRING([--with-release-id],
	    [Specify release id])],
	    [RELEASE=_${with_release_id}],
	    [RELEASE=""])
AC_DEFINE_UNQUOTED([RELEASE], ["$RELEASE"], [Release Date])

AC_SUBST(SYSTEMD_UNITDIR)
AC_ARG_WITH([systemd-unitdir], AS_HELP_STRING([--with-systemd-unitdir=DIR],
	    [Directory for systemd unit configuration files]),
	    [SYSTEMD_UNITDIR=$withval],
	    [SYSTEMD_UNITDIR='${prefix}/lib/systemd/system'])
AC_DEFINE_UNQUOTED([SYSTEMD_UNITDIR], ["$SYSTEMD_UNITDIR"], [Systemd unit directory])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MKDIR_P
AC_PROG_LN_S
LT_INIT
AC_SUBST([LIBTOOL_DEPS])

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h inttypes.h])
AC_CHECK_HEADERS([linux/kernel.h])
AC_C_INLINE

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UID_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

# Checks for library functions.

AC_CONFIG_FILES([Makefile
		 ve_drv-kmod.spec
		 debian/rules
		 debian/control
		 debian/ve-drv-kmod.install
		 debian/ve-drv-kmod-dev.install])
AC_OUTPUT
