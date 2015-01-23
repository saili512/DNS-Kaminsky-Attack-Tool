#!/bin/bash
echo '  	    GNU GENERAL PUBLIC LICENSE'
echo '		       Version 2, June 1991'
echo
echo ' Copyright (C) 1989, 1991 Free Software Foundation, Inc.,'
echo ' 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA'
echo ' Everyone is permitted to copy and distribute verbatim copies'
echo ' of this license document, but changing it is not allowed.'
echo
echo 'Compiling pacgen.c version 1.10 to binary pacgen using gcc'

gcc `libnet-config --cflags --defines` pacgen.c -o pacgen `libnet-config --libs` -g
