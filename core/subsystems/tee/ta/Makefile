BINARY = ${BINARY}
CPPFLAGS += -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL)

# Hack: to locate the TA smw library, we assume that parent directory of the
# TA is the same as the TA smw library
LDADD = -L$(abspath $(link-out-dir))/../lib_ta -lsmw_ta

include ${TA_DEV_KIT_DIR}/mk/ta_dev_kit.mk
