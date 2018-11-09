dot_CFLAGS := -fPIC
# We use a symbol that's not in libkres but the daemon.
# On darwin this isn't accepted by default.
dot_LDFLAGS := -Wl,-undefined -Wl,dynamic_lookup
dot_SOURCES := modules/dot/dot.c
dot_DEPEND := $(libkres)
dot_LIBS := $(contrib_TARGET) $(libkres_TARGET) $(libkres_LIBS)
$(call make_c_module,dot)
