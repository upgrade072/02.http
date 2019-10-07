
SUBDIRS := openssl libevent nghttp2 \
		   json-c jslint libconfig \
		   libjansson libjwt libffi glib2 \
		   libhttp libs lbengine \
		   httpreq httpc https authsvr \
		   perfsim restsvr restcli \
		   libnrf nrfm nrfc 

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
