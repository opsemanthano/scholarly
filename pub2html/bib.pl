#! /usr/local/bin/perl
#
# bib.pl       	--- format refer files for framemaker, latex, HTML etc.
#
# Author: Oscar Nierstrasz (Revised: 11/10/88)
#
# This package and friends can be found at:
# http://cui_www.unige.ch/ftp/PUBLIC/oscar/scripts/README.html
# or ftp: cui.unige.ch:/PUBLIC/oscar/scripts/
#
# New Author : J. R. Spanier ( Modified: 14/3/95)
#
# Hacked for own system use ( mainly for Mosaic/httpd web )
#
# Uses: accent.pl

require("accent.pl");

package bib;

#v = "bib v1.0"; # Re-written in perl 4/7/93
#v = "bib v1.1"; # 7/7/93: added -ha and -hk options
#v = "bib v1.2"; # 21/3/94: modified signature
$v = "bib v1.3"; # 11/5/94: created separate package bib.pl
$newv = "pub2html v1.00"; # 14/3/95: Altered bib package for own needs.

$ENV{'PATH'} = '/usr/bin';              # fix to allow setuid scripts

chop($date = `date +%d.%m.%y`);
#omn = '<A HREF="http://cuiwww.unige.ch/OSG/omn.html"><I>OMN</I></A><P>';
#sig = "<I>This file was generated by $v on $date.</I>\n$omn<P>\n";

$ftp = '<A HREF="http://cuiwww.unige.ch/ftp/PUBLIC/oscar/scripts/Old/README.html">';
$sig = "<HR><I>This file was generated by <B>$newv</B> on $date and is based on $ftp$v</A></I>\n<P>\n";

$/ = "";

# build up a reference:
sub getref {
    $ref = $lbl = $keys = $auth = $ed = $title = "";
    $abstract = $ftp = $url = $junk = "";

    # study; # strangely, this slows us down!

    s/\n\s+/\n/g;    # remove leading white space
    s/%L (.*)\n// && ($lbl = $1);            # label
    s/%K (.*)\n// && ($keys = $1);            # keywords
    if ($lbl eq "") { print STDERR "Warning -- missing label:\n$_"; }

    # Collect authors:
    while (s/%[AQ] (.*)\n(%[AQ] .*\n%[AQ])/$2/) { $auth .= "$1,\n"; }
    s/%[AQ] (.*)\n%[AQ] (.*)\n// && ($auth .= "$1 and\n$2");
    s/%[AQ] (.*)\n// && ($auth = $1);

    # Collect editors:
    while (s/%E (.*)\n(%E .*\n%E)/$2/) { $ed .= "$1,\n"; }
    s/%E (.*)\n%E (.*)\n// && ($ed .= "$1 and\n$2");
    s/%E (.*)\n// && ($ed = $1);

    # Check for missing authors:
    if ($auth eq "") {
        if ($ed ne "") { $auth = "$ed (Ed.)"; $ed = ""; }
        else {
            $auth = "(Anonymous)";
            print STDERR "Warning ($lbl): missing author\n";
        }
    }
    $ref = "$auth,\n";

    # from this point on, ref ends without newline so commas
    # can be added incrementally.

    # grab the title:
    s/%T ([^%]*)\n// && ($title = $1);
    # determine kind of publication:
    if (/%J/) {                # Journal paper
        $ref .= "$LQ$title$RQ";
        s/%J ([^%]*)\n// && ($ref .= ",\n$I$1$R");
    }
    elsif(/%B/) {                # Article in book
        $ref .= "$LQ$title$RQ";
        s/%B ([^%]*)\n// && ($ref .= ",\n$I$1$R");
    }
    elsif(/%R/) {                # Technical report
        $ref .= "$LQ$title$RQ";
        s/%R ([^%]*)\n// && ($ref .= ",\n$1");
    }
    else { $ref .= "$I$title$R"; }         # Book
    # If more than one of J, B or R, will show up as JUNK:
    if (/(%[JBR])/) {
        print STDERR "Warning ($lbl): type conflict [$1]\n";
    }

    # add remaining fields in standard ord:
    if ($ed ne "") { $ref .= ",\n$ed (Ed.)"; }
    s/%S (.*)\n// && ($ref .= ",\n$1");        # series
    s/%V (.*)\n// && ($ref .= ",\nvol. $1");    # volume
    s/%N (.*)\n// && ($ref .= ", no. $1");        # number
    s/%I ([^%]*)\n// && ($ref .= ",\n$1");        # institution
    s/%C ([^%]*)\n// && ($ref .= ",\n$1");        # city
    s/%D (.*)\n// && ($ref .= ", $1");        # date
    s/%P (.*)\n// && ($ref .= ",\npp. $1");        # page numbers
    s/%O ([^%]*)\n// && ($ref .= ",\n$1");        # other (e.g. to appear)

    # these may not necessarily be printed:
    s/%X ([^%]*)\n// && do { $abstract = $1; };    # abstract
    s/%% ftp: (.*)\n// && ($ftp = $1);        # should build a list?
    ($url = $ftp) =~ s!^([^:]+):(.*)$!ftp://$1/$2!;

    while(s/%% ([^%]*)\n//) { $junk .= $1; };    # comments

    $ref =~ s/$RQ,/,$RQ/go;                # fix commas
    $ref .= ".\n";

    # If anything is left, complain:
    if ($_ =~ /./) { print STDERR "Warning ($lbl) -- extra fields:\n$_\n"; }
}

sub nextchar { local($c) = @_; return pack("c",1+unpack("c",$c)); }

sub fm_init { $I = "<Italic>"; $R = "<Plain>"; $LQ = "``"; $RQ = "''";
    print '
<MML file -- generated by "bib">
<Units pica>
<!DefineTag Reference>
<!DefineTag UnNumRef>
<!DefineTag UnNumSub>
';
}

sub ms_init { $I = "\\fI"; $R = "\\fR"; $LQ = "``"; $RQ = "''"; }
sub tex_init { $I = "{\\it "; $R = "}"; $LQ = "``"; $RQ = "''"; }
sub txt_init { $I = ""; $R = ""; $LQ = "\""; $RQ = "\""; }

sub html_init {
	$I = "<I>"; $R = "</I>";
	$LQ = "<B>``"; $RQ = "''</B>";
	}

sub genlabels {
    while (<>) {
        $auth = $date = $yr = "";
        # Get old label & year:
        s/^%L (.*)\n// && ($old = $1);
        ($oldyr = $old) =~ s/.*([0-9]{2}).*/$1/;
        # Get first author:
        /%[AEQ] (.*)/ && ($auth = $1);
        if ($auth eq "") { $auth = $old; }
        $auth =~ s/\\[:"]([aou])/\1e/g;    # expand umlauts
        $auth =~ s/\\.//g;        # delete other accents
        $auth =~ s/,.*//;
        $auth =~ s/.*\s(\S+)$/$1/;
        $auth =~ s/[^A-Za-z]//g;    # delete nonalphas
        ($lbl = $auth) =~ s/(\S{4}).*/\1/;
        # Get year:
        /%D .*[0-9]{2}([0-9]{2})/ && ($yr = $1);
        if ($yr eq "") {
            print STDERR "Warning ($old): missing year ($oldyr)\n";
            $yr = $oldyr;
        }
        elsif (($oldyr ne "") && ($yr ne $oldyr)) {
            print STDERR "Warning ($old): date changed to $yr\n";
        }
        $lbl .= "$yr";
        push(@list,"%L $lbl\n$_");
    }
    $prev = "";
    @list = sort(@list);
    while ($ref = shift(@list)){
        $ref =~ s/^%L (.*)\n// && ($lbl = $1);
        if ($lbl eq $prev) { $char = &nextchar($char); }
        else { $char = "a"; $prev = $lbl; }
        $lbl .= $char;
        print "%L $lbl\n$ref";
        # if ($old ne $lbl) { print "$old -> $lbl\n"; }
    }
}

sub setfile {
	local($kwd) = @_;
	local($file) = "$kwd.html";
	local($name);
	if ($file ne $prev) {
		close(STDOUT);
		if ($opened{$kwd}) {
			open(STDOUT,">>$file");
			# print STDERR "Reopening $file\n";
		}
		else {
			$opened{$kwd} = 1;
			open(STDOUT,">$file");
			$name = "References -- $kwd";
			print "<TITLE>$name</TITLE>\n\n";
			print "<H1>$name</H1>\n\n";
			print "<OL>\n";
			# print STDERR "Creating $file\n";
		}
		$prev = $file;
	}
}

sub endfiles {
	local($file);
	open(INDEX,">index.html");
	$name = "Index of References by Primary Keyword";
	print INDEX "<TITLE>$name</TITLE>\n\n";
	print INDEX "<H1>$name</H1>\n\n<DL>\n";
	close(STDOUT);
	foreach $kwd (sort(keys(%opened))) {
		$file = "$kwd.html";
		open(STDOUT,">>$file");
		print "</OL>\n\n$sig";
		close(STDOUT);
		print INDEX "<DD><A HREF=\"$file\">$kwd</A>\n";
	}
	print INDEX "</DL>\n$sig";
	close(INDEX);
}

1;

