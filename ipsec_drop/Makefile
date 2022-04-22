obj-m := ipsec_drop.o
ipsec_drop-y := main.o
CFLAGS_ipsec_drop.o += -DDEBUG
#DEPENDS:=
KVERSION := $(shall uname -r)

all:
	$(MAKE) -C /lib/modules/$(KVERSION)/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(KVERSION)/build M=$(PWD) clean

install:
	cp ipsec_drop.ko /lib/modules/$(shell uname -r)/extra
	depmod
	/usr/src/linux-headers-$(shell uname -r)/scripts/sign-file sha256 ./cert/priv.key ./cert/pubkey.der $(shell modinfo -n ipsec_drop)

signature:
	/usr/src/linux-headers-$(shell uname -r)/scripts/sign-file sha256 ./cert/priv.key ./cert/pubkey.der $(shell modinfo -n ipsec_drop)
