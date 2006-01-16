# ----------------------------------------------------------------------------
#
# RuleWall: A Firewall Configuration Parser
# Copyright (C) 2006 Benjamin Gaillard
#
# ----------------------------------------------------------------------------
#
#        File: src/Makefile.am
#
# Description: Automake Makefile
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


# Flags
AM_CPPFLAGS = -D_POSIX_SOURCE -D_BSD_SOURCE
AM_LFLAGS   = -p -p -s
AM_YFLAGS   = -d

# Source files
bin_PROGRAMS = rulewall
rulewall_SOURCES = \
    main.c \
    memory.c \
    memory.h \
    parser.y \
    lexer.l \
    structs.c \
    structs.h \
    iptables.c \
    iptables.h

# Extra files to include in the distribution archive
EXTRA_DIST = Unimakefile.mk

# End of File
