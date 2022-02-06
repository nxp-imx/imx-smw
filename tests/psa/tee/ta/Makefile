BINARY = ${BINARY}

CFLAGS += --sysroot=${SYSROOT}
CXXLAGS += --sysroot=${SYSROOT}

CPPFLAGS += -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL)

LDADD = -L$(LIBDEPS_DIR) -lsmw_ta

include ${TA_DEV_KIT_DIR}/mk/ta_dev_kit.mk
