BUILD = bin

LIB = lib
NETBACK = netback
NETPROXY = netproxy
MONITOR = monitor
GENERATOR = generator

all: 
	cd $(LIB) && $(MAKE) all 
	cd $(MONITOR) && $(MAKE) all
	cd $(GENERATOR) && $(MAKE) all
	cd $(NETBACK) && $(MAKE) all
	cd $(NETPROXY) && $(MAKE) all
	
	cp -f $(MONITOR)/$(MONITOR) $(BUILD)/$(MONITOR)
	cp -f $(GENERATOR)/$(GENERATOR) $(BUILD)/$(GENERATOR)
	cp -f $(NETBACK)/$(NETBACK) $(BUILD)/$(NETBACK)
	cp -f $(NETPROXY)/$(NETPROXY) $(BUILD)/$(NETPROXY)

clean:
	cd $(MONITOR) && $(MAKE) clean
	cd $(GENERATOR) && $(MAKE) clean
	cd $(NETBACK) && $(MAKE) clean
	cd $(NETPROXY) && $(MAKE) clean
	cd $(LIB) && $(MAKE) clean

	rm -f $(BUILD)/*
