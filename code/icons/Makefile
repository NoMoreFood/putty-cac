# Makefile for the PuTTY icon suite.

ICONS = putty puttycfg puttygen pscp pageant pterm ptermcfg puttyins
ICOSIZES = 16 32 48 64
SIZES = $(ICOSIZES) 128
ICOSUFFIXES = $(ICOSIZES) $(patsubst %,%-mono,$(ICOSIZES))

MODE = # override to -it on command line for opaque testing

PAMS = $(foreach I,$(ICONS),$(foreach S,$(SIZES),$(I)-$(S).pam))
MONOPAMS = $(foreach I,$(ICONS),$(foreach S,$(SIZES),$(I)-$(S)-mono.pam))
TRUEPAMS = $(foreach I,puttyins,$(foreach S,$(SIZES),$(I)-$(S)-true.pam))

PNGS = $(patsubst %.pam,%.png,$(PAMS))
MONOPNGS = $(patsubst %.pam,%.png,$(MONOPAMS))
TRUEPNGS = $(patsubst %.pam,%.png,$(TRUEPAMS))

SVGS = $(patsubst %,%.svg,$(ICONS))
MONOSVGS = $(patsubst %,%-mono.svg,$(ICONS))

ICOS = putty.ico puttygen.ico pscp.ico pageant.ico pageants.ico puttycfg.ico \
       puttyins.ico pterm.ico ptermcfg.ico
ICNS = PuTTY.icns Pterm.icns
CICONS = putty-xpm.c putty-config-xpm.c pterm-xpm.c pterm-config-xpm.c \
         putty-rgb.c putty-config-rgb.c pterm-rgb.c pterm-config-rgb.c

base: icos cicons

all: pngs monopngs base icns svgs monosvgs truepngs

pngs: $(PNGS)
monopngs: $(MONOPNGS)
truepngs: $(TRUEPNGS)
svgs: $(SVGS)
monosvgs: $(MONOSVGS)

icos: $(ICOS)
icns: $(ICNS)
cicons: $(CICONS)

install: icos cicons
	cp $(ICOS) ../windows
	cp $(CICONS) ../unix

$(PAMS): %.pam: mkicon.py
	./mkicon.py $(MODE) $(join $(subst -, ,$(basename $@)),_icon) $@

$(PNGS) $(MONOPNGS) $(TRUEPNGS): %.png: %.pam
	convert $< $@

$(MONOPAMS): %.pam: mkicon.py
	./mkicon.py -2 $(MODE) $(join $(subst -, ,$(subst -mono,,$(basename $@))),_icon) $@

$(TRUEPAMS): %.pam: mkicon.py
	./mkicon.py -T $(MODE) $(join $(subst -, ,$(subst -true,,$(basename $@))),_icon) $@

$(SVGS): %.svg: mksvg.py
	./mksvg.py $(patsubst %.svg,%_icon,$@) -o $@

$(MONOSVGS): %.svg: mksvg.py
	./mksvg.py --mode=bw $(patsubst %-mono.svg,%_icon,$@) -o $@

putty.ico: $(patsubst %,putty-%.png,$(ICOSUFFIXES))
	./icon.pl -4 $(filter-out %-mono.png, $^) -1 $(filter %-mono.png, $^) > $@

puttycfg.ico: $(patsubst %,puttycfg-%.png,$(ICOSUFFIXES))
	./icon.pl -4 $(filter-out %-mono.png, $^) -1 $(filter %-mono.png, $^) > $@

puttygen.ico: $(patsubst %,puttygen-%.png,$(ICOSUFFIXES))
	./icon.pl -4 $(filter-out %-mono.png, $^) -1 $(filter %-mono.png, $^) > $@

pageant.ico: $(patsubst %,pageant-%.png,$(ICOSUFFIXES))
	./icon.pl -4 $(filter-out %-mono.png, $^) -1 $(filter %-mono.png, $^) > $@

pageants.ico: pageant-16.png pageant-16-mono.png
	./icon.pl -4 $(filter-out %-mono.png, $^) -1 $(filter %-mono.png, $^) > $@

pscp.ico: $(patsubst %,pscp-%.png,$(ICOSUFFIXES))
	./icon.pl -4 $(filter-out %-mono.png, $^) -1 $(filter %-mono.png, $^) > $@

pterm.ico: $(patsubst %,pterm-%.png,$(ICOSUFFIXES))
	./icon.pl -4 $(filter-out %-mono.png, $^) -1 $(filter %-mono.png, $^) > $@

ptermcfg.ico: $(patsubst %,ptermcfg-%.png,$(ICOSUFFIXES))
	./icon.pl -4 $(filter-out %-mono.png, $^) -1 $(filter %-mono.png, $^) > $@

# Because the installer icon makes heavy use of brown when drawing
# the cardboard box, it's worth having 8-bit versions of it in
# addition to the 4- and 1-bit ones.
puttyins.ico: $(patsubst %,puttyins-%.png,$(ICOSUFFIXES)) \
              $(patsubst %,puttyins-%-true.png,$(ICOSIZES))
	./icon.pl -8 $(filter %-true.png, $^) \
                  -4 $(filter-out %-true.png, $(filter-out %-mono.png, $^)) \
                  -1 $(filter %-mono.png, $^) > $@

# Assorted icons for the website. (This isn't linked into "make all".)
web: website.ico web180.png web192.png web512.png
website.ico: putty-16.png putty-32.png putty-48.png
	./icon.pl -4 $^ >$@
web180.png: putty.svg
	rsvg-convert -f png -b white -w 180 -h 180 -o $@ $<
web192.png: putty.svg
	rsvg-convert -f png -w 192 -h 192 -o $@ $<
web512.png: putty.svg
	rsvg-convert -f png -w 512 -h 512 -o $@ $<

putty-xpm.c: putty-16.png putty-32.png putty-48.png
	./cicon.pl main_icon $^ > $@
putty-rgb.c: putty-16.png putty-32.png putty-48.png
	./cicon.pl --rgb main_icon $^ > $@

putty-config-xpm.c: puttycfg-16.png puttycfg-32.png puttycfg-48.png
	./cicon.pl cfg_icon $^ > $@
putty-config-rgb.c: puttycfg-16.png puttycfg-32.png puttycfg-48.png
	./cicon.pl --rgb cfg_icon $^ > $@

pterm-xpm.c: pterm-16.png pterm-32.png pterm-48.png
	./cicon.pl main_icon $^ > $@
pterm-rgb.c: pterm-16.png pterm-32.png pterm-48.png
	./cicon.pl --rgb main_icon $^ > $@

pterm-config-xpm.c: ptermcfg-16.png ptermcfg-32.png ptermcfg-48.png
	./cicon.pl cfg_icon $^ > $@
pterm-config-rgb.c: ptermcfg-16.png ptermcfg-32.png ptermcfg-48.png
	./cicon.pl --rgb cfg_icon $^ > $@

PuTTY.icns: putty-16-mono.pam putty-16.pam \
	    putty-32-mono.pam putty-32.pam \
	    putty-48-mono.pam putty-48.pam \
	    putty-128.pam
	./macicon.py mono:putty-16-mono.pam colour:putty-16.pam \
	             mono:putty-32-mono.pam colour:putty-32.pam \
	             mono:putty-48-mono.pam colour:putty-48.pam \
	                                    colour:putty-128.pam \
		output:$@

Pterm.icns: pterm-16-mono.pam pterm-16.pam \
	    pterm-32-mono.pam pterm-32.pam \
	    pterm-48-mono.pam pterm-48.pam \
	    pterm-128.pam
	./macicon.py mono:pterm-16-mono.pam colour:pterm-16.pam \
	             mono:pterm-32-mono.pam colour:pterm-32.pam \
	             mono:pterm-48-mono.pam colour:pterm-48.pam \
	                                    colour:pterm-128.pam \
		output:$@

clean:
	rm -f *.pam *.png *.ico *.icns *.c
