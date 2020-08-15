include /usr/local/etc/PcapPlusPlus.mk

SYSCONF_LINK = g++
CPPFLAGS     = -O2 -g
LDFLAGS      = 
LIBS         = -lm

DESTDIR = ./
TARGET  = main
OBJECTS := $(patsubst %.cpp,%.o,$(wildcard *.cpp))

INCLUDES += $(PCAPPP_INCLUDES)
LIBS += $(PCAPPP_LIBS)

LIBS_DIR = -L/usr/local/lib

all: $(DESTDIR)$(TARGET)

$(DESTDIR)$(TARGET): $(OBJECTS)
	$(SYSCONF_LINK) $(LIBS_DIR) -Wall $(LDFLAGS) -o $(DESTDIR)$(TARGET) $(OBJECTS) $(LIBS)

$(OBJECTS): %.o: %.cpp
	$(SYSCONF_LINK) $(INCLUDES) -Wall $(CPPFLAGS) -c $(CFLAGS) $< -o $@

clean:
	rm -f $(OBJECTS)
	rm -f $(TARGET)
