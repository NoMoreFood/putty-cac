#!/usr/bin/perl

# Given a list of input PNGs, create a C source file containing a
# const array of XPMs, named by a given C identifier.

$mode = "xpm";
if ($ARGV[0] eq "--rgb") {
    $mode = "rgb";
    shift;
}

$id = shift @ARGV;
$k = 0;
@images = ();

if ($mode eq "rgb") {
    push @images, "#include \"putty.h\"\n", "\n";
}

foreach $f (@ARGV) {
    if ($mode eq "xpm") {
        # XPM format is generated directly by ImageMagick, so that's easy
        # enough. We just have to adjust the declaration line so that it
        # has the right name, linkage and storage class.
        @lines = ();
        open XPM, "convert $f xpm:- |";
        push @lines, $_ while <XPM>;
        close XPM;
        die "XPM from $f in unexpected format\n"
            unless $lines[1] =~ /^static.*\{$/;
        $lines[1] = "static const char *const ${id}_$k"."[] = {\n";
        push @images, @lines, "\n";
    } elsif ($mode eq "rgb") {
        open SIZE, "-|", "identify", "-format", "%w %h", $f;
        chomp($wh = <SIZE>);
        close SIZE;
        ($w, $h) = split / /, $wh;
        die "bad size from $f" unless $w > 0 && $h > 0;
        open RGB, "-|", "convert", "-depth", "8", $f, "rgba:-";
        $rgbdata = '';
        1 while read RGB, $rgbdata, 4096, length $rgbdata;
        close RGB;
        die "bad rgb data from $f" if length $rgbdata != 4*$w*$h;
        push @images, "static const unsigned char ${id}_rgbdata_${k}[] = {\n";
        for ($i = 0; $i < $w*$h; $i++) {
            push @images, sprintf "  0x%02x, 0x%02x, 0x%02x, 0x%02x,\n",
                unpack "CCCC", substr $rgbdata, $i*4, 4;
        }
        push @images,
            "};\n",
            "\n",
            "static const struct RgbIconImage ${id}_rgb_$k = {\n",
            "  .width = ${w},\n",
            "  .height = ${h},\n",
            "  .data = ${id}_rgbdata_$k,\n",
            "};\n",
            "\n";
    } else {
        die "bad mode '$mode'";
    }
    $k++;
}

# Now output.
foreach $line (@images) { print $line; }
if ($mode eq "xpm") {
    print "const char *const *const ${id}[] = {\n";
    for ($i = 0; $i < $k; $i++) { print "    ${id}_$i,\n"; }
    print "};\n";
    print "const int n_${id} = $k;\n";
} elsif ($mode eq "rgb") {
    print "const struct RgbIconImage *const ${id}_rgb[] = {\n";
    for ($i = 0; $i < $k; $i++) { print "    &${id}_rgb_$i,\n"; }
    print "};\n";
    print "const int n_${id}_rgb = $k;\n";
} else {
    die "bad mode '$mode'";
}
