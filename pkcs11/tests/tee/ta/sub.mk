global-incdirs-y += inc

srcs-y += ta_entry.c

# Work around to add library dependency include header path
cppflags-y += -I$(LIBDEPS_INC)
