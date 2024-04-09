PREFIX          ?= /usr/local
LUA_LIB_DIR     ?= $(PREFIX)/lib/lua/$(LUA_VERSION)
INSTALL         ?= install

.PHONY: all install

all: ;

install: all
	$(INSTALL) -d $(DESTDIR)$(LUA_LIB_DIR)/resty
	$(INSTALL) lib/resty/*.lua $(DESTDIR)$(LUA_LIB_DIR)/resty/
	$(INSTALL) -d $(DESTDIR)$(LUA_LIB_DIR)/resty/tls_manager
	$(INSTALL) lib/resty/tls_manager/*.lua $(DESTDIR)$(LUA_LIB_DIR)/resty/tls_manager/

