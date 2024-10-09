include $(top_srcdir)/build/modmake.rulesam
MODNAME=mod_openai_s2s

mod_LTLIBRARIES = mod_openai_s2s.la
mod_openai_s2s_la_SOURCES  = mod_openai_s2s.c openai_glue.cpp audio_pipe.cpp parser.cpp vector_math.cpp
mod_openai_s2s_la_CFLAGS   = $(AM_CFLAGS)
mod_openai_s2s_la_CXXFLAGS = $(AM_CXXFLAGS) -std=c++11
mod_openai_s2s_la_LIBADD   = $(switch_builddir)/libfreeswitch.la
mod_openai_s2s_la_LDFLAGS  = -avoid-version -module -no-undefined -shared `pkg-config --libs libwebsockets` 
