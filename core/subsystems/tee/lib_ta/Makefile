LIBNAME = libsmw_ta
CPPFLAGS += -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL)

include ${TA_DEV_KIT_DIR}/mk/ta_dev_kit.mk

all: move

move:
	@echo "Move target $(libname).a to ${O}"
	@echo $(link-out-dir)
	$(q)mv $(libname).a ${O}
