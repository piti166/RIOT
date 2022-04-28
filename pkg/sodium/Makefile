PKG_NAME=sodium
PKG_URL=https://github.com/jedisct1/libsodium
PKG_VERSION=7389bf7f2968be75520e932704f18f038c29e581
PKG_LICENSE=GPLv2

include $(RIOTBASE)/pkg/pkg.mk

# some variable seem uninitialized to gcc with -Og but are not
# https://gcc.gnu.org/bugzilla/buglist.cgi?quicksearch=may%20be%20used%20uninitialized
# https://gcc.gnu.org/bugzilla/show_bug.cgi?id=42145
# https://gcc.gnu.org/bugzilla/show_bug.cgi?id=90710#c1
#CFLAGS += -Wno-maybe-uninitialized

# wolfcrypt uses uint8_t for block buffers, on which fast
# 32 bit operations are performed. From a quick peek at the
# code it looks like the buffers are correctly aligned, so
# this is a false positive.
#CFLAGS += -Wno-cast-align

#.PHONY: sodium%
all: config build

config:
	(cd $(PKG_SOURCE_DIR) && ./configure)
	
build:
	$(QQ)"$(MAKE)" -C $(PKG_SOURCE_DIR) -f $(RIOTBASE)/Makefile.base
#wolfcrypt:
#	$(QQ)"$(MAKE)" -C $(PKG_SOURCE_DIR)/wolfcrypt/src -f $(CURDIR)/Makefile.wolfcrypt

#wolfcrypt-%:
#	$(QQ)"$(MAKE)" -C $(PKG_SOURCE_DIR)/wolfcrypt/$* -f $(CURDIR)/Makefile.wolfcrypt-$*
