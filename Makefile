
SUBDIRS := openssl libevent nghttp2 \
		   libconfig libhttp libs \
		   libjansson libjwt \
		   httpreq httpc https \
		   json-c jslint \
		   perfsim \
		   authsvr

subdirs: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@ $(MAKEFLAGS)

all: 
	@for dir in $(SUBDIRS); do \
	$(MAKE) -C $$dir all; \
	done
new: 
	@for dir in $(SUBDIRS); do \
	$(MAKE) -C $$dir new; \
	done
install: 
	@for dir in $(SUBDIRS); do \
	$(MAKE) -C $$dir install; \
	done
clean: 
	@for dir in $(SUBDIRS); do \
	$(MAKE) -C $$dir clean; \
	done

.PHONY: subdirs $(SUBDIRS)
.PHONY: all new install clean
