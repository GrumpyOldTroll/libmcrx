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

#AM_LDFLAGS = -levent

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

LIBMCRX_CURRENT=2
LIBMCRX_REVISION=0
LIBMCRX_AGE=2

pkginclude_HEADERS = include/mcrx/libmcrx.h
lib_LTLIBRARIES = src/libmcrx.la

src_libmcrx_la_SOURCES =\
	src/libmcrx-private.h \
	src/libmcrx.c

# with thanks:
# https://stackoverflow.com/questions/29811970/adding-linting-to-autotools-based-build-system
LINTFILES = $(src_libmcrx_la_SOURCES) $(pkginclude_HEADERS)
LINTTARGETS = $(LINTFILES:%=%.lint)

lint: $(LINTTARGETS)

%.lint: %
	$(CPPLINT) $? | tee $@

all-local: lint

.PHONY: lint

EXTRA_DIST += src/libmcrx.sym

src_libmcrx_la_LDFLAGS = $(AM_LDFLAGS) \
	-version-info $(LIBMCRX_CURRENT):$(LIBMCRX_REVISION):$(LIBMCRX_AGE)
src_libmcrx_la_DEPENDENCIES = ${top_srcdir}/src/libmcrx.sym

pkgconfigdir = $(libdir)/pkgconfig
nodist_pkgconfig_DATA = src/libmcrx.pc
EXTRA_DIST += src/libmcrx.pc.in
CLEANFILES += src/libmcrx.pc

TESTS = test/test1-libmcrx

check_PROGRAMS = test/test1-libmcrx
test_test1_libmcrx_SOURCES = test/test1-libmcrx.c
test_test1_libmcrx_LDADD = src/libmcrx.la
