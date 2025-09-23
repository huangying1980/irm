SUBDIRS = src test

TARGET ?= release

IRM_EFVI ?= off
IRM_DPDK ?= off
IRM_XDP ?= off

all: $(SUBDIRS)

.PHONY: all $(SUBDIRS)

$(SUBDIRS):
	export TARGET IRM_EFVI IRM_DPDK IRM_XDP
	$(MAKE) -C $@

clean:
	for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir clean; \
	done

install:
	$(MAKE) -C src install
