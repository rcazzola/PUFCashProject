# Location of ARM toolchain. NOTE: Using 2017.4 makes this work with EITHER ZYBO or CORA
SDK_PATH = /picard_home/research/Xilinx/SDK/2017.4
ARM_TOOLS_PATH = $(SDK_PATH)/gnu/aarch32/lin/gcc-arm-linux-gnueabi/bin

MKDIR_P = mkdir -p

# Compilation tools
CC = gcc
CC_ARM = $(ARM_TOOLS_PATH)/arm-linux-gnueabihf-gcc
CXX_ARM = $(ARM_TOOLS_PATH)/arm-linux-gnueabihf-g++

#CFLAGS = -Wall -std=c99 -Wno-format-overflow 
#CXXFLAGS = -Wall -Wno-format-overflow
CFLAGS = -Wall -std=c99
CXXFLAGS = -Wall

# DATABASE
DEFINES = 

LIB_PATHS = -L/usr/local/lib64
INCLUDE_PATHS = -I. -IAES 
LINK_FLAGS = -lm -lsqlite3 -lssl -lcrypto -lpthread

LIB_PATHS_ARM = -LARM_LIBS
INCLUDE_PATHS_ARM = -I. -IARM_INCLUDES -IAES 
LINK_FLAGS_ARM = -lm -lssl -lcrypto -lsqlite3 -lpthread

# All output binaries
BIN_VRG = verifier_regeneration
BIN_DRG = device_regeneration.elf
BIN_TTP = TTP_DB.elf

TARGETS = $(BIN_VRG) $(BIN_DRG) $(BIN_TTP) 

# Object files required for each binary
USER_OBJS_VRG = utility.o common.o aes_128_ecb_openssl.o aes_256_cbc_openssl.o sha_3_256_openssl.o commonDB.o commonDB_RT.o commonDB_RT_PUFCash.o verifier_regen_funcs.o verifier_regeneration.o
USER_OBJS_DRG = utility.o common.o aes_128_ecb_openssl.o aes_256_cbc_openssl.o sha_3_256_openssl.o device_common.o device_regen_funcs.o interface.o commonDB.o commonDB_RT_PUFCash.o device_regeneration.o
USER_OBJS_TTP = utility.o common.o aes_128_ecb_openssl.o aes_256_cbc_openssl.o device_common.o device_regen_funcs.o commonDB.o commonDB_RT.o commonDB_RT_PUFCash.o sha_3_256_openssl.o ttp.o

# Build directory locations
OBJDIR_X86 = build/x86
OBJDIR_ARM_CXX = build/arm-g++
OBJDIR_ARM_CC = build/arm-gcc

# Append build directory paths to lists of object files
OBJS_VRG = $(patsubst %, $(OBJDIR_X86)/%, $(USER_OBJS_VRG))
OBJS_DRG = $(patsubst %, $(OBJDIR_ARM_CC)/%, $(USER_OBJS_DRG))
OBJS_TTP = $(patsubst %, $(OBJDIR_ARM_CC)/%, $(USER_OBJS_TTP))

# Create the build directory automatically
$(shell $(MKDIR_P) $(OBJDIR_X86) $(OBJDIR_ARM_CC) $(OBJDIR_ARM_CXX))

# Default target
.PHONY: all
all: $(TARGETS)


# Output binaries
$(BIN_DRG): $(OBJS_DRG)
	$(CC_ARM) $^ -o $@ $(LIB_PATHS_ARM) $(LINK_FLAGS_ARM)

$(BIN_VRG): $(OBJS_VRG)
	$(CC) $^ -o $@ $(LIB_PATHS) $(LINK_FLAGS)

$(BIN_TTP): $(OBJS_TTP)
	$(CC_ARM) $^ -o $@ $(LIB_PATHS_ARM) $(LINK_FLAGS_ARM) 

# x80 object files
$(OBJDIR_X86)/utility.o: utility.c utility.h
$(OBJDIR_X86)/common.o: common.c common.h
$(OBJDIR_X86)/verifier_common.o: verifier_common.c verifier_common.h common.h 

$(OBJDIR_X86)/aes_128_ecb_openssl.o: AES/aes_128_ecb_openssl.c AES/aes_128_ecb_openssl.h 
$(OBJDIR_X86)/aes_256_cbc_openssl.o: AES/aes_256_cbc_openssl.c AES/aes_256_cbc_openssl.h 
$(OBJDIR_X86)/sha_3_256_openssl.o: AES/sha_3_256_openssl.c 

$(OBJDIR_X86)/commonDB.o: commonDB.c commonDB.h
$(OBJDIR_X86)/commonDB_RT.o: commonDB_RT.c commonDB_RT.h commonDB.h verifier_common.h common.h
$(OBJDIR_X86)/commonDB_RT_PUFCash.o: commonDB_RT_PUFCash.c commonDB_RT_PUFCash.h commonDB.h verifier_common.h common.h
$(OBJDIR_X86)/verifier_regen_funcs.o: verifier_regen_funcs.c commonDB.h verifier_regen_funcs.h verifier_common.h commonDB_RT.h common.h
$(OBJDIR_X86)/verifier_regeneration.o: verifier_regeneration.c commonDB.h verifier_regen_funcs.h verifier_common.h commonDB_RT.h commonDB_RT_PUFCash.h common.h

$(OBJDIR_X86)/%.o:
	$(CC) $(CFLAGS) $(DEFINES) $(INCLUDE_PATHS) -c $< -o $@


# ARM C object files
$(OBJDIR_ARM_CC)/utility.o: utility.c utility.h
$(OBJDIR_ARM_CC)/common.o: common.c common.h

$(OBJDIR_ARM_CC)/aes_128_ecb_openssl.o: AES/aes_128_ecb_openssl.c AES/aes_128_ecb_openssl.h 
$(OBJDIR_ARM_CC)/aes_256_cbc_openssl.o: AES/aes_256_cbc_openssl.c AES/aes_256_cbc_openssl.h 
$(OBJDIR_ARM_CC)/sha_3_256_openssl.o: AES/sha_3_256_openssl.c 

$(OBJDIR_ARM_CC)/commonDB.o: commonDB.c commonDB.h
$(OBJDIR_ARM_CC)/commonDB_RT.o: commonDB_RT.c commonDB_RT.h commonDB.h verifier_common.h common.h
$(OBJDIR_ARM_CC)/commonDB_RT_PUFCash.o: commonDB_RT_PUFCash.c commonDB_RT_PUFCash.h commonDB.h verifier_common.h common.h
$(OBJDIR_ARM_CC)/device_common.o: device_common.c device_common.h common.h device_regen_funcs.h commonDB_RT_PUFCash.h commonDB.h device_hardware.h
$(OBJDIR_ARM_CC)/device_regen_funcs.o: device_regen_funcs.c device_regen_funcs.h device_common.h common.h device_hardware.h commonDB.h
$(OBJDIR_ARM_CC)/interface.o: interface.c interface.h
$(OBJDIR_ARM_CC)/device_regeneration.o: device_regeneration.c device_regen_funcs.h device_common.h common.h interface.h device_hardware.h commonDB.h
$(OBJDIR_ARM_CC)/ttp.o: ttp_DB.c device_regen_funcs.h device_common.h common.h device_hardware.h commonDB.h

$(OBJDIR_ARM_CC)/%.o:
	$(CC_ARM) $(CFLAGS) $(DEFINES) $(INCLUDE_PATHS_ARM) -c $< -o $@


# ARM C++ object files
$(OBJDIR_ARM_CXX)/utility.o: utility.c utility.h
$(OBJDIR_ARM_CXX)/common.o: common.c common.h

$(OBJDIR_ARM_CXX)/aes_128_ecb_openssl.o: AES/aes_128_ecb_openssl.c AES/aes_128_ecb_openssl.h 
$(OBJDIR_ARM_CXX)/aes_256_cbc_openssl.o: AES/aes_256_cbc_openssl.c AES/aes_256_cbc_openssl.h 
$(OBJDIR_ARM_CXX)/sha_3_256_openssl.o: AES/sha_3_256_openssl.c 

$(OBJDIR_ARM_CXX)/commonDB.o: commonDB.c commonDB.h
$(OBJDIR_ARM_CXX)/device_common.o: device_common.c device_common.h common.h device_regen_funcs.h commonDB_RT_PUFCash.h commonDB.h device_hardware.h
$(OBJDIR_ARM_CXX)/device_regen_funcs.o: device_regen_funcs.c device_regen_funcs.h device_common.h common.h device_hardware.h
$(OBJDIR_ARM_CXX)/interface.o: interface.c interface.h
$(OBJDIR_ARM_CXX)/device_regeneration.o: device_regeneration.c device_regen_funcs.h device_common.h common.h interface.h device_hardware.h

$(OBJDIR_ARM_CXX)/%.o:
	$(CXX_ARM) $(CXXFLAGS) $(DEFINES) $(INCLUDE_PATHS_ARM) -c $< -o $@

# Utility
.PHONY: clean install

clean:
	-rm $(TARGETS)
	-rm -r build
