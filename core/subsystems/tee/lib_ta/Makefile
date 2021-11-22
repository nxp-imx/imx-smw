LIBNAME = $(TA_LIBNAME)
CPPFLAGS += -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL)

include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

all: install

install:
	@echo "Move target $(libname).a to $(LIB_DIR)"
	$(q)mv $(libname).a $(LIB_DIR)
	@echo "Copy library include(s) to $(INCLUDE_DIR)"
	$(q)cp -r include $(INCLUDE_DIR)
