
#======================
package DOCSIS::Binary;
#======================

use warnings;
use strict;
use English qw(-no_match_vars);
use File::Basename;
use FileHandle;
#use Apache2::Reload;
use vars qw/$PROGRAM/;

$PROGRAM = 'docsis';


sub encode { #================================================================

    ### init
    my $in_data        = shift or return 'Need $in_data';
    my $out_file       = shift or return 'Need $out_file';
    my $out_dir        = dirname $out_file;
    local $SIG{'CHLD'} = 'DEFAULT';

    ### do some tests
    return "Cannot write to dir '$out_dir'"   if(!-e $out_dir  or  !-w _);
    return "Cannot write to file '$out_file'" if( -e $out_file and !-w _);

    ### open program
    open(my $docsis, "| $PROGRAM -e - $out_file &>/dev/null")
        or return "Open failed: $!";

    ### run program
    if(ref $in_data eq 'ARRAY') {
        print $docsis for(@$in_data);
    }
    elsif(ref $in_data eq 'GLOB') {
        print $docsis while(<$in_data>);
    }
    else {
        print $docsis "$in_data";
    }

    ### the end
    close $docsis;
    return $CHILD_ERROR >> 8;
}

sub decode { #================================================================

    ### init
    my $in_file        = shift or return 'Need $in_file';
    my $match          = qr/
                               SnmpMibObject
                               \s ([^\s]+) \s \w+ \s "?  ([^"]+) "?  \s;
                           /x;
    local $SIG{'CHLD'} = 'DEFAULT';
    my %out_data;

    ### do some tests
    return "Cannot read '$in_file'" unless(-r $in_file);

    ### open program
    open(DOCSIS, "$PROGRAM -d $in_file |")
        or return "Open failed: $!";

    ### run program
    while(<DOCSIS>) {
        $out_data{$1} = $2 if(/$match/x);
    }

    ### the end
    close DOCSIS;
    return $CHILD_ERROR >> 8 if($CHILD_ERROR);
    return \%out_data;
}

sub reopen_stdout { #=========================================================

    ### open to variable
    if(my $in_mem = shift) {
        open(_STDOUT, ">&", \*STDOUT);
        close STDOUT;
        open(STDOUT, ">", $in_mem) or die $!;
    }

    ### reopen
    else {
        open(STDOUT, ">&", \*_STDOUT);
    }
}

#=============================================================================
1;
