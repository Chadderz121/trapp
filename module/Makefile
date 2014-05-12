ccflags-y += -std=gnu99

obj-m += module_trapp.o
obj-m += module_trapp_bad.o
module_trapp-objs := trapp_module.o checkfn_c.o checkfn_asm.o
module_trapp_bad-objs := trapp_module_bad.o checkfn_c.o checkfn_asm_bad.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(CURDIR) clean

/dev/trapp:
	mknod /dev/trapp c 248 0

insert: /dev/trapp module_trapp.ko
	insmod module_trapp.ko

remove:
	rmmod module_trapp.ko

insert_bad: /dev/trapp module_trapp_bad.ko
	insmod module_trapp_bad.ko

remove_bad:
	rmmod module_trapp_bad.ko
