ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
EXTRA_DIST =
CLEANFILES =
MAINTAINERCLEANFILES = Makefile.in aclocal.m4 build-aux/compile \
            build-aux/config.guess build-aux/config.sub build-aux/depcomp \
            build-aux/install-sh build-aux/ltmain.sh build-aux/missing \
            config.h.in config.h.in~ configure m4/libtool.m4 m4/ltoptions.m4 \
            m4/ltsugar.m4 m4/ltversion.m4 m4/lt~obsolete.m4
AM_MAKEFLAGS = --no-print-directory

AM_CPPFLAGS = \
	-include $(top_builddir)/config.h \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DLIBEXECDIR=\""$(libexecdir)"\" \
	-I${top_srcdir}/include \
	-I${top_srcdir}/src

AM_CFLAGS = ${my_CFLAGS} \
	-fvisibility=hidden \
	-ffunction-sections \
	-fdata-sections

AM_LDFLAGS =

SED_PROCESS = \
	$(AM_V_GEN)$(MKDIR_P) $(dir $@) && $(SED) \
	-e 's,@VERSION\@,$(VERSION),g' \
	-e 's,@prefix\@,$(prefix),g' \
	-e 's,@exec_prefix\@,$(exec_prefix),g' \
	-e 's,@libdir\@,$(libdir),g' \
	-e 's,@includedir\@,$(includedir),g' \
	< $< > $@ || rm $@

%.pc: %.pc.in Makefile
	$(SED_PROCESS)

LIBMCASTRX_CURRENT=2
LIBMCASTRX_REVISION=0
LIBMCASTRX_AGE=2

pkginclude_HEADERS = include/mcastrx/libmcastrx.h
lib_LTLIBRARIES = src/libmcastrx.la

src_libmcastrx_la_SOURCES =\
	src/libmcastrx-private.h \
	src/libmcastrx.c

EXTRA_DIST += src/libmcastrx.sym

src_libmcastrx_la_LDFLAGS = $(AM_LDFLAGS) \
	-version-info $(LIBMCASTRX_CURRENT):$(LIBMCASTRX_REVISION):$(LIBMCASTRX_AGE)
src_libmcastrx_la_DEPENDENCIES = ${top_srcdir}/src/libmcastrx.sym

pkgconfigdir = $(libdir)/pkgconfig
nodist_pkgconfig_DATA = src/libmcastrx.pc
EXTRA_DIST += src/libmcastrx.pc.in
CLEANFILES += src/libmcastrx.pc

TESTS = test/test-libmcastrx

check_PROGRAMS = test/test-libmcastrx
test_test_libmcastrx_SOURCES = test/test-libmcastrx.c
test_test_libmcastrx_LDADD = src/libmcastrx.la
