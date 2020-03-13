SUBDIRS	= jansson-2.10

ACLOCAL_AMFLAGS = -I m4
AM_CPPFLAGS =  -I$(top_srcdir)/src/jansson-2.10/src

native_objs :=

if HAVE_AVX2
native_objs += sha256_code_release/sha256_avx2_rorx2.A
endif
if HAVE_AVX1
native_objs += sha256_code_release/sha256_avx1.A
endif
if HAVE_SSE4
native_objs += sha256_code_release/sha256_sse4.A
endif

%.A: %.asm
	yasm -f x64 -f elf64 -X gnu -g dwarf2 -D LINUX -o $@ $<

noinst_LIBRARIES = libasicseerpool.a
libasicseerpool_a_SOURCES = libasicseerpool.c libasicseerpool.h sha2.c sha2.h cashaddr.c cashaddr.h
libasicseerpool_a_LIBADD = $(native_objs)

bin_PROGRAMS = asicseer-pool asicseer-pmsg notifier summariser
asicseer_pool_SOURCES = asicseer-pool.c asicseer-pool.h generator.c generator.h bitcoin.c bitcoin.h \
		 stratifier.c stratifier.h connector.c connector.h uthash.h \
		 utlist.h
asicseer_pool_LDADD = libasicseerpool.a @JANSSON_LIBS@ @LIBS@

asicseer_pmsg_SOURCES = asicseer-pmsg.c
asicseer_pmsg_LDADD = libasicseerpool.a @JANSSON_LIBS@

notifier_SOURCES = notifier.c
notifier_LDADD = libasicseerpool.a @JANSSON_LIBS@

summariser_SOURCES = summariser.c
summariser_LDADD = libasicseerpool.a @JANSSON_LIBS@

if WANT_ASICSEER_DB
bin_PROGRAMS += asicseer-db
asicseer_db_SOURCES = asicseer-db.c ckdb_cmd.c ckdb_data.c ckdb_dbio.c ckdb_btc.c \
		ckdb_crypt.c asicseer-db.h klist.c ktree.c klist.h ktree.h
asicseer_db_LDADD = libasicseerpool.a @JANSSON_LIBS@ @LIBS@
endif
