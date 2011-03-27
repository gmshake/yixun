#!/bin/sh
set -x
aclocal
autoheader
automake --foreigh --add-missing --copy
autoconf

