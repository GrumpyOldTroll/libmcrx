ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
EXTRA_DIST =
CLEANFILES =
MAINTAINERCLEANFILES = Makefile.in aclocal.m4 build-aux/compile \
            build-aux/config.guess build-aux/config.sub build-aux/depcomp \
            build-aux/install-sh build-aux/ltmain.sh build-aux/missing \
            config.h.in config.h.in~ configure m4/libtool.m4 m4/ltoptions.m4 \
            m4/ltsugar.m4 m4/ltversion.m4 m4/lt~obsolete.m4
MOSTLYCLEANFILES =
AM_MAKEFLAGS = --no-print-directory

# https://linux.die.net/man/7/feature_test_macros
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

pkginclude_HEADERS = include/mcrx/libmcrx.h include/mcrx/errors.h
lib_LTLIBRARIES = libmcrx.la
lib_LIBRARIES = libmcrx.a
noinst_PROGRAMS = mcrx-check

libmcrx_la_SOURCES =\
	src/libmcrx-private.h \
	src/libmcrx.c \
	src/native.c \
	src/wait.c
libmcrx_la_CFLAGS = $(AM_CFLAGS)

libmcrx_a_SOURCES = $(libmcrx_la_SOURCES)
libmcrx_a_CFLAGS = $(AM_CFLAGS)

mcrx_check_SOURCES = test/mcrx-check.c
mcrx_check_LDADD = libmcrx.a

# with thanks:
# https://stackoverflow.com/questions/29811970/adding-linting-to-autotools-based-build-system
LINTFILES = $(libmcrx_la_SOURCES) $(pkginclude_HEADERS)
LINTTARGETS = $(LINTFILES:%=%.lint)

lint: $(LINTTARGETS)

%.lint: %
	$(CPPLINT) $? | tee $@

all-local: lint

.PHONY: lint

# following hints from:
# https://www.gnu.org/software/automake/manual/html_node/Clean.html
MOSTLYCLEANFILES += $(LINTTARGETS)

EXTRA_DIST += src/libmcrx.sym

libmcrx_la_LDFLAGS = $(AM_LDFLAGS) \
	-version-info $(LIBMCRX_CURRENT):$(LIBMCRX_REVISION):$(LIBMCRX_AGE)
libmcrx_la_DEPENDENCIES = ${top_srcdir}/src/libmcrx.sym

pkgconfigdir = $(libdir)/pkgconfig
nodist_pkgconfig_DATA = src/libmcrx.pc
EXTRA_DIST += src/libmcrx.pc.in
CLEANFILES += src/libmcrx.pc

TESTS = test/test1-libmcrx test/test2-libmcrx test/test-rejoin-same test/test-logstr

check_PROGRAMS = \
		 test/test1-libmcrx \
		 test/test2-libmcrx \
		 test/test-logstr \
		 test/test-rejoin-same

test_test1_libmcrx_SOURCES = test/test1-libmcrx.c
test_test1_libmcrx_LDADD = libmcrx.a

test_test2_libmcrx_SOURCES = test/test2-libmcrx.c
test_test2_libmcrx_LDADD = libmcrx.a

test_test_rejoin_same_SOURCES = test/test-rejoin-same.c
test_test_rejoin_same_LDADD = libmcrx.a

test_test_logstr_SOURCES = test/test-logstr.c
test_test_logstr_LDADD = libmcrx.a

