#!/usr/bin/perl
open (FILE, "+<$ARGV[0]") or die("Unable to open file $ARGV[0]");
seek (FILE, 9, 0);
# Code for January 1, 2001
$var = "\01\01\01\00\00\00";
print FILE $var;
