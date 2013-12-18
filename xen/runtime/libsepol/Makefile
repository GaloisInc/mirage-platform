all: 
	$(MAKE) -C src 

install: 
	$(MAKE) -C include install
	$(MAKE) -C src install
	$(MAKE) -C man install

relabel:
	$(MAKE) -C src relabel

clean:
	$(MAKE) -C src clean
	$(MAKE) -C tests clean

indent:
	$(MAKE) -C src $@
	$(MAKE) -C include $@

test:
	$(MAKE) -C tests test

