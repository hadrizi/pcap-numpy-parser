include /usr/local/etc/PcapPlusPlus.mk

SYSCONF_LINK = g++
CPPFLAGS     = -O2 -g -std=c++17
LDFLAGS      = 
LIBS         = -lm -lpython3.6m -lstdc++fs

DESTDIR = ./
TARGET  = main
OBJECTS := $(patsubst %.cpp,%.o,$(wildcard *.cpp))

INCLUDES += $(PCAPPP_INCLUDES)
INCLUDES += -I/usr/include/python3.6
INCLUDES += -I/usr/include/numpy
INCLUDES += -I/usr/include/spdlog
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
