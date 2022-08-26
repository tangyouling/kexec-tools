#
# kexec loongarch (linux booting linux)
#
loongarch_KEXEC_SRCS =  kexec/arch/loongarch/kexec-loongarch.c
loongarch_KEXEC_SRCS += kexec/arch/loongarch/kexec-elf-loongarch.c
loongarch_KEXEC_SRCS += kexec/arch/loongarch/kexec-elf-rel-loongarch.c
loongarch_KEXEC_SRCS += kexec/arch/loongarch/crashdump-loongarch.c

loongarch_DT_OPS += kexec/dt-ops.c

loongarch_MEM_REGIONS = kexec/mem_regions.c

loongarch_CPPFLAGS += -I $(srcdir)/kexec/

loongarch_ADD_BUFFER =
loongarch_ADD_SEGMENT =
loongarch_VIRT_TO_PHYS =

dist += kexec/arch/loongarch/Makefile $(loongarch_KEXEC_SRCS)			\
	kexec/arch/loongarch/kexec-loongarch.h					\
	kexec/arch/loongarch/crashdump-loongarch.h				\
	kexec/arch/loongarch/include/arch/options.h

ifdef HAVE_LIBFDT
LIBS += -lfdt
else
include $(srcdir)/kexec/libfdt/Makefile.libfdt
libfdt_SRCS += $(LIBFDT_SRCS:%=kexec/libfdt/%)
loongarch_CPPFLAGS += -I$(srcdir)/kexec/libfdt
loongarch_KEXEC_SRCS += $(libfdt_SRCS)
endif
