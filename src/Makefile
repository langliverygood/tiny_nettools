-include ../Makefile.env

SUBDIRS = $(shell ls -l| grep ^d |awk '{print $$9}' )

all:subdirs

subdirs: $(SUBDIRS)
	@for dir in $(SUBDIRS);do $(MAKE) -C $$dir all||exit 1;done

.PHONY: all
