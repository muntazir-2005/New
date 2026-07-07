# Makefile
XCRUN      = xcrun
SDK        = iphoneos
CLANG      = $(XCRUN) -sdk $(SDK) clang

ARCH       = arm64e
MIN_VER    = 14.0
ARCH_FLAGS = -arch $(ARCH) -miphoneos-version-min=$(MIN_VER)

CFLAGS     = $(ARCH_FLAGS) -O2 -fobjc-arc -I.
LDFLAGS    = $(ARCH_FLAGS) -dynamiclib -framework Foundation -lobjc -L. -ldobby -lc++

SRC        = main.m
OBJ        = $(SRC:.m=.o)
TARGET     = bypass.dylib

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ) libdobby.a dobby.h
	$(CLANG) $(LDFLAGS) $(OBJ) -o $@

%.o: %.m
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)
