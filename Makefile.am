
bin_PROGRAMS=ssdeep

ssdeep_LDADD=libfuzzy.la
ssdeep_LDFLAGS=-static

lib_LTLIBRARIES=libfuzzy.la
libfuzzy_la_SOURCES=fuzzy.c edit_dist.c find-file-size.c
libfuzzy_la_LDFLAGS=-no-undefined -version-info 0:0:0

include_HEADERS=fuzzy.h

man_MANS=ssdeep.1

ssdeep_SOURCES = main.c match.c engine.c         \
                 dig.c cycles.c helpers.c ui.c   \
                 main.h fuzzy.h tchar-local.h ssdeep.h

EXTRA_DIST=config.guess config.sub sample.c

nice:
	rm -f *~

preflight:
	@grep RBF $(DISTFILES)
