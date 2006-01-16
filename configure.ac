# ----------------------------------------------------------------------------
#
# RuleWall: A Firewall Configuration Parser
# Copyright (C) 2006 Benjamin Gaillard
#
# ----------------------------------------------------------------------------
#
#        File: configure.ac
#
# Description: Autoconf Script
#
# ----------------------------------------------------------------------------
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation; either version 2 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc., 59
# Temple Place - Suite 330, Boston, MA 02111-1307, USA.
#
# ----------------------------------------------------------------------------


# Process this file with autoconf to produce a configure script.

# General settings
AC_PREREQ(2.59)
AC_INIT([rulewall], [1.0.0], [b.gaillard@powercode.net])
AM_INIT_AUTOMAKE([dist-bzip2 no-define -Wall])
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_HEADER([config.h])

# Checks for programs
AC_LANG([C])
AC_PROG_CC
AC_PROG_LEX
# Force the use of Flex
if test "$LEX" != flex; then
    LEX="$SHELL $missing_dir/missing flex"
    AC_SUBST([LEX_OUTPUT_ROOT], [lex.yy])
    AC_SUBST([LEXLIB], [''])
fi
AC_PROG_YACC

# Checks for library functions
AC_HEADER_STDC
AC_CHECK_HEADERS([netdb.h])
AC_FUNC_MALLOC
AC_CHECK_FUNCS([strdup])
AC_C_CONST

# Configuration options
AC_CACHE_CHECK([wether to check port names for existence],
	       [ac_cv_enable_check_ports], [
    AC_ARG_ENABLE([check-ports],
		  AC_HELP_STRING([--enable-check-ports],
				 [check port names for existence
				  (default: no)]),
		  [ac_cv_enable_check_ports="$enableval"],
		  [ac_cv_enable_check_ports=no])
])
if test "x$ac_cv_enable_check_ports" = xyes; then
    AC_DEFINE([CHECK_PORT_NAMES], [1],
	      [Wether to check port names for existence.])
fi

# Enable GCC warnings
if test "x$GCC" = xyes; then
    CFLAGS="-ansi -pedantic -Wall -W $CFLAGS"
fi

# Generated files
AC_CONFIG_FILES([
    Makefile
    src/Makefile
    examples/Makefile
])
AC_OUTPUT

# End of File
