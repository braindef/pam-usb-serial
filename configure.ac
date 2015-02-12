# SUBJECT     Autoconf file
# DESCRIPTION Process this file with autoconf to produce a configure script.
# DATE        2015-02-12
# AUTHOR      Raphael Medaer <raphael.medaer@straightforward.me>


AC_PREREQ([2.65])
AC_INIT([pam-usb-serial], [1.0.0], [raphael.medaer@straightforward.me])
AM_INIT_AUTOMAKE([pam-usb-serial], [1.0.0])
AC_PROG_RANLIB
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([usb-1.0], [libusb_init], [], [
	      echo "libusb-1.0-0 is required for USB device monitoring"
	      exit -1])
AC_CHECK_LIB([pam], [pam_get_user], [], [
	      echo "libpam is needed to create PAM module"
	      exit -1])

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_CHECK_FUNCS([])

AC_CONFIG_FILES([Makefile
		 man/Makefile
		 src/Makefile])

AC_OUTPUT
