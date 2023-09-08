LIBNAME = $(TA_LIBNAME)
CPPFLAGS += -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL)

include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

all: install

install:
	@if [ -e $(O)/$(libname).a ]; then \
		echo "install target $(O)/$(libname).a to $(LIB_DIR)"; \
		install $(O)/$(libname).a $(LIB_DIR); \
	else \
		echo "install target $(libname).a to $(LIB_DIR)"; \
		install $(libname).a $(LIB_DIR); \
	fi

	@echo "Copy library include(s) to $(INCLUDE_DIR)"
	$(q)mkdir -p $(INCLUDE_DIR)
	$(q)cp -r include/* $(INCLUDE_DIR)
