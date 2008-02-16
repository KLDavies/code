
bin_PROGRAMS=ssdeep

ssdeep_LDADD=libssdeep.la
ssdeep_LDFLAGS=-static

lib_LTLIBRARIES=libssdeep.la
libssdeep_la_SOURCES=fuzzy.c edit_dist.c
libssdeep_la_LDFLAGS=-no-undefined -version-info 0:0:0

include_HEADERS=ssdeep.h

man_MANS=ssdeep.1

ssdeep_SOURCES = cycles.c  dig.c  \
                 helpers.c  main.c  match.c \
                 main.h ssdeep.h tchar-local.h

EXTRA_DIST=config.guess config.sub

nice:
	rm -f *~

preflight:
	grep RBF $(DISTFILES)
