#! usr/local/bin/perl
#
# accent.pl	--- translate dead-key accents to troff, tex etc. (library)
#
# This package and friends can be found at:
# http://cui_www.unige.ch/ftp/PUBLIC/oscar/scripts/README.html
# or ftp: cui.unige.ch:/PUBLIC/oscar/scripts/
#
# Filter "dead-key" conventions to produce the right
# sequences for TeX, Framemaker mml files or troff.
#
# Examples:
# acute accent:	\'a
# grave accent:	\`e
# circumflex:	\^o (or \<o)
# dieresis:	\"u (or \:u)
# tilde:	\~n
# cedilla:	\,c
# slash:	\/o
#
# ring:		\oa		*** FRAME ONLY
# ae:		\ae		*** FRAME ONLY
#
# tau:		\tau		*** PRESENTLY ONLY FOR TEX ***
# pi:		\pi
#
# Author: Oscar Nierstrasz (Revised: Jan 1990)
# Added 7 & 8 bit option (Sept 1991)
# Rewritten as perl script 27/6/93
#
# NB: if you copy this file by ftp BE SURE to use binary mode.
#
# THIS FILE CONTAINS 8-BIT CHARS!!!

package accent;

#$F = "/user/u1/oscar/Framemaker";

$F = "/usr/local/etc/httpd/pub2html";
$FA = "<Include $F/accent.mml>";

# strip dead-key accents
sub strip {
    study;
    s/\\[:"]oe/oe/g;
    s/\\[:"]([AOUaou])/$1e/g;
    s/\\\/([Oo])/$1e/g;
    s/\\o([Aa])/$1a/g;
    s/\\ae/ae/g;
    s/\\ss/ss/g;
    s/\\alpha/alpha/g;
    s/\\beta/beta/g;
    s/\\pi/pi/g;
    s/\\tau/tau/g;
    s/\\.//g;
}

# convert dead-key accents to troff -ms .AM macros
sub ms {
    study;
    s/\\'([aeiou])/$1\\*'/g;
    s/\\`([aeiou])/$1\\*`/g;
    s/\\[\^<]([aeiou])/$1\\*^/g;
    s/\\:([aeiou])/$1\\*:/g;
    s/\\"([aeiou])/$1\\*:/g;
    s/\\:([AOU])/$1e/g;
    s/\\"([AOU])/$1e/g;
    s/\\~([aon])/$1\\*~/g;
    s/\\,([c])/$1\\*,/g;
    s/\\\/([Oo])/$1\\*\//g;
    s/\\ss/ss/g;
    s/\\alpha/alpha/g;
    s/\\beta/beta/g;
    s/\\tau/tau/g;
    s/\\pi/pi/g;
}

# convert dead-key accents to LaTeX
sub tex {
    study;
    s/\$/\\\$/g;
    s/[&#_]/\\$&/g;
    s/\\\/=/\$\\neq\$/g;
    s/\\(['`^"])([aeou])/\\$1{$2}/g;
    s/\\<([aeou])/\\^{$1}/g;
    s/\\(['`^"])i/\\$1{\\i}/g;
    s/\\<i/\\^{\\i}/g;
    s/\\:([aeou])/\\"{$1}/g;
    s/\\:i/\\"{\\i}/g;
    s/\\~([aon])/\\~{$1}/g;
    s/\\,([c])/\\c{$1}/g;
    s/\\\/([Oo])/{\\o}/g;
    s/\\oA/\\AA/g;
    s/\\oa/\\aa/g;
    # s/\\AE/&/g
    # s/\\ae/&/g
    # s/\\ss/&/g
    s/\\alpha/\$$&\$/g;
    s/\\beta/\$$&\$/g;
    s/\\mu/\$$&\$/g;
    s/\\tau/\$$&\$/g;
    s/\\pi/\$$&\$/g;
    s/[<>=|]+/\$$&\$/g;
}


sub mml_init {
	print "$FA";
}

# convert dead-key accents to Framemaker MML
sub mml {
    study;
    s/\\'([aeiou])/<$1acute>/g;
    s/\\`([aeiou])/<$1grave>/g;
    s/\\[\^<]([aeiou])/<$1circumflex>/g;
    s/\\:([aeiou])/<$1dieresis>/g;
    s/\\"([aeiou])/<$1dieresis>/g;
    s/\\~([aon])/<$1tilde>/g;
    s/\\'([AEIOU])/<U$1acute>/g;
    s/\\`([AEIOU])/<U$1grave>/g;
    s/\\[\^<]([AEIOU])/<U$1circumflex>/g;
    s/\\:([AEIOU])/<U$1dieresis>/g;
    s/\\"([AEIOU])/<U$1dieresis>/g;
    s/\\~([AON])/<U$1tilde>/g;
    s/\\,([c])/<$1cedilla>/g;
    s/\\oA/<UAring>/g;
    s/\\oa/<aring>/g;
    s/\\AE/<UAE>/g;
    s/\\ae/<ae>/g;
    s/\\ss/<germandbls>/g;
    # s/\\alpha/<alpha>/g
    # s/\\beta/<beta>/g
    # s/\\tau/<tau>/g
    # s/\\pi/<pi>/g
    s/\\\/([Oo])/<$1slash>/g;
    s/``/<quotedblleft>/g;
    s/''/<quoteblright>/g;
    s/--/<emdash>/g;
}

# convert dead-key accents to HTML
sub html {
    study;
    s/\\AE/\&AElig;/g;
    s/\\'([AEIOUYaeiouy])/\&$1acute;/g;
    s/\\[<^]([AEIOUaeiou])/\&$1circ;/g;
    s/\\`([AEIOUaeiou])/\&$1grave;/g;
    s/\\o([Aa])/\&$1ring;/g;
    s/\\~([ANOano])/\&$1tilde;/g;
    s/\\[:"]([AEIOUYaeiouy])/\&$1uml;/g;
    s/\\,([Cc])/\&$1cedil;/g;
    s/\\\/([Oo])/\&$1slash;/g;
    s/\\ss/\&szlig;/g;
}

# convert dead-key accents to overstruck characters
sub os {
    study;
    s/\\'([aeiou])/\\o'\\'$1'/g;
    s/\\`([aeiou])/\\o'\\(ga$1'/g;
    s/\\[\^<]([aeiou])/\\o'^$1'/g;
    s/\\[:"]([aeiou])/\\o'\\(um$1'/g;
    s/\\~([an])/\\o'~$1'/g;
    s/\\,([c])/\\o'\\(cdc'/g;
    s/\\\/([Oo])/\\o'\/$1'/g;
    s/\\tau/tau/g;
    s/\\pi/pi/g;
}

# convert nixdorf accents to dead-key accents
sub nix {
    study;
    s/\\\*([aeiouAEIOU])/\\"$1/g;
    s/\\tau/tau/g;
    s/\\pi/pi/g;
}

# convert accents from PC (DOS) files
# used for SI files
# pipe through cat -v first
sub si {
    study;
    s/M-^H/\\`a/g; s/M-^J/\\:a/g; s/M-^M/\\,c/g;
    s/M-^N/\\'e/g; s/M-^O/\\`e/g; s/M-^P/\\<e/g;
    s/M-^Y/\\<a/g; s/M-^Z/\\:o/g; s/M-^_/\\:u/g;
}

# convert accents from PC (DOS) files
# pipe through cat -v first
# Used for Gert Florijn's address files
sub pc {
    study;
    s/M-^A/\\:u/g; s/M-^B/\\'e/g; s/M-^C/\\<a/g;
    s/M-^D/\\:a/g; s/M-^E/\\`a/g; s/M-^G/\\,c/g;
    s/M-^H/\\<e/g; s/M-^I/\\:e/g; s/M-^J/\\`e/g;
    s/M-^K/\\:i/g; s/M-^L/\\<i/g; s/M-^S/\\<o/g;
    s/M-^T/\\:o/g;
}

# convert from Mac (Word?) files
# INCOMPLETE
sub mac {
	s/=46/F/g;
	s/=E9/\\'e/g;
	s/=FC/\\:u/g;
}

# convert 8bit ascii to 7bit escapes 
#
# not handled:
# � � � � � � � � � � � � � � �
sub seven {
    study;
    s/�/\\bu/g; s/�/\\??/g; s/�/\\!!/g; s/�/\\xx/g;
    s/�/\\+-/g; s/�/\\-:/g; s/�/\\<</g; s/�/\\>>/g;
    s/�/\\-D/g; s/�/\\-L/g; s/�/\\-Y/g; s/�/\\\/c/g;
    s/�/\\12/g; s/�/\\14/g; s/�/\\34/g; s/�/\\^1/g;
    s/�/\\^2/g; s/�/\\^3/g; s/�/\\ss/g; s/�/\\\/u/g;
    s/�/\\so/g; s/�/\\beta/g; s/�/\\mu/g; s/�/\\co/g;
    s/�/\\ro/g; s/�/\\AE/g; s/�/\\ae/g; s/�/\\oA/g;
    s/�/\\oa/g; s/�/\\\/O/g; s/�/\\\/o/g; s/�/\\,C/g;
    s/�/\\,c/g; s/�/\\`A/g; s/�/\\`E/g; s/�/\\`I/g;
    s/�/\\`O/g; s/�/\\`U/g; s/�/\\`a/g; s/�/\\`e/g;
    s/�/\\`i/g; s/�/\\`o/g; s/�/\\`u/g; s/�/\\'A/g;
    s/�/\\'E/g; s/�/\\'I/g; s/�/\\'O/g; s/�/\\'U/g;
    s/�/\\'Y/g; s/�/\\'a/g; s/�/\\'e/g; s/�/\\'i/g;
    s/�/\\'o/g; s/�/\\'u/g; s/�/\\'y/g; s/�/\\:A/g;
    s/�/\\:E/g; s/�/\\:I/g; s/�/\\:O/g; s/�/\\:U/g;
    s/�/\\:a/g; s/�/\\:e/g; s/�/\\:i/g; s/�/\\:o/g;
    s/�/\\:u/g; s/�/\\:y/g; s/�/\\"A/g; s/�/\\"E/g;
    s/�/\\"I/g; s/�/\\"O/g; s/�/\\"U/g; s/�/\\"a/g;
    s/�/\\"e/g; s/�/\\"i/g; s/�/\\"o/g; s/�/\\"u/g;
    s/�/\\"y/g; s/�/\\<A/g; s/�/\\<E/g; s/�/\\<I/g;
    s/�/\\<O/g; s/�/\\<U/g; s/�/\\<a/g; s/�/\\<e/g;
    s/�/\\<i/g; s/�/\\<o/g; s/�/\\<u/g; s/�/\\^A/g;
    s/�/\\^E/g; s/�/\\^I/g; s/�/\\^O/g; s/�/\\^U/g;
    s/�/\\^a/g; s/�/\\^e/g; s/�/\\^i/g; s/�/\\^o/g;
    s/�/\\^u/g; s/�/\\~A/g; s/�/\\~N/g; s/�/\\~O/g;
    s/�/\\~a/g; s/�/\\~n/g; s/�/\\~o/g;
}

# convert dead-key accents to 8bit meta-chars
# not handled:
# � � � � � � � � � � � � � � � 
sub eight {
    study;
    s/\\bu/�/g; s/\\\?\?/�/g; s/\\!!/�/g; s/\\xx/�/g;
    s/\\\+-/�/g; s/\\-:/�/g; s/\\<</�/g; s/\\>>/�/g;
    s/\\-D/�/g; s/\\-L/�/g; s/\\-Y/�/g; s/\\\/c/�/g;
    s/\\12/�/g; s/\\14/�/g; s/\\34/�/g; s/\\\^1/�/g;
    s/\\\^2/�/g; s/\\\^3/�/g; s/\\ss/�/g; s/\\\/u/�/g;
    s/\\so/�/g; s/\\beta/�/g; s/\\mu/�/g; s/\\co/�/g;
    s/\\ro/�/g; s/\\AE/�/g; s/\\ae/�/g; s/\\oA/�/g;
    s/\\oa/�/g; s/\\\/O/�/g; s/\\\/o/�/g; s/\\,C/�/g;
    s/\\,c/�/g; s/\\`A/�/g; s/\\`E/�/g; s/\\`I/�/g;
    s/\\`O/�/g; s/\\`U/�/g; s/\\`a/�/g; s/\\`e/�/g;
    s/\\`i/�/g; s/\\`o/�/g; s/\\`u/�/g; s/\\'A/�/g;
    s/\\'E/�/g; s/\\'I/�/g; s/\\'O/�/g; s/\\'U/�/g;
    s/\\'Y/�/g; s/\\'a/�/g; s/\\'e/�/g; s/\\'i/�/g;
    s/\\'o/�/g; s/\\'u/�/g; s/\\'y/�/g; s/\\:A/�/g;
    s/\\:E/�/g; s/\\:I/�/g; s/\\:O/�/g; s/\\:U/�/g;
    s/\\:a/�/g; s/\\:e/�/g; s/\\:i/�/g; s/\\:o/�/g;
    s/\\:u/�/g; s/\\:y/�/g; s/\\"A/�/g; s/\\"E/�/g;
    s/\\"I/�/g; s/\\"O/�/g; s/\\"U/�/g; s/\\"a/�/g;
    s/\\"e/�/g; s/\\"i/�/g; s/\\"o/�/g; s/\\"u/�/g;
    s/\\"y/�/g; s/\\<A/�/g; s/\\<E/�/g; s/\\<I/�/g;
    s/\\<O/�/g; s/\\<U/�/g; s/\\<a/�/g; s/\\<e/�/g;
    s/\\<i/�/g; s/\\<o/�/g; s/\\<u/�/g; s/\\^A/�/g;
    s/\\^E/�/g; s/\\^I/�/g; s/\\^O/�/g; s/\\^U/�/g;
    s/\\^a/�/g; s/\\^e/�/g; s/\\^i/�/g; s/\\^o/�/g;
    s/\\^u/�/g; s/\\~A/�/g; s/\\~N/�/g; s/\\~O/�/g;
    s/\\~a/�/g; s/\\~n/�/g; s/\\~o/�/g;
}

1;

