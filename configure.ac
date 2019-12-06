# Process this file with autoconf to produce a configure script.
# Or probably better, run "autoreconf -i" to get it right.

# Use today's date as the version when "configure" is generated
define([ENCROOT_VERSION], esyscmd([date +%F | tr -d '\n']))
AC_INIT([Encroot], ENCROOT_VERSION, [henrik@gulbra.net])
AM_INIT_AUTOMAKE([foreign])

# Checks for programs.
AC_PROG_AWK
AC_PROG_INSTALL
AC_PROG_LN_S

AC_OUTPUT(Makefile)
