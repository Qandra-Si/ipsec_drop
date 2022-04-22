# Что понадобится?

```bash
sudo apt install net-tools ifupdown sendip
# для редактирования настроек сетевых интерфейсов
sudo apt install ethtool
# для редактирования настроек сетевых интерфейсов из терминала с пом. nmtui-edit
sudo apt install network-manager
# среда разработки
sudo apt install emacs-nox build-essential libtool libtalloc-dev shtool autoconf automake pkg-config make gcc
# сборка пакета
sudo apt install dkms debhelper
```

Запуск и настройка:

```bash
# проверяем параметры сетевой карты
sudo ethtool -k enp0s25
```

Сборка

```bash
make
sudo make install
#... также тожно подписать модуль, чтобы не ругался dmesg
```

Если при подключении модуля произойдёт ошибка `Lockdown: insmod: unsigned module loading is restricted` (см. dmesg), то надо:
- либо отключить в BIOS Secure Boot
- либо подписать модуль (см. Makefile)

Пример с записью см. на этой странице https://wiki.wireshark.org/SampleCaptures#sample-captures (ищи ipv4_cipso_option.pcap (libpcap) A few IP packets with CIPSO option).

Также обращай внимание на то, что в RFC-1108 сказано, что используются ip-опции!

Отправка ip-пакета с произвольным ip-option содержимым:

```bash
sudo sendip -p ipv4 -ip 1 -ifd 1 -is 192.168.250.139 -d 0x080038d241aa0001ec7062620000000067dc080000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637 -ionum 82ab02 192.168.250.149
sudo sendip -p ipv4 -ip 1 -ifd 1 -is 192.168.250.139 -d 0x080038d241aa0001ec7062620000000067dc080000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637 -ionum 82ab02 -ionum 82ab02 192.168.250.149
```

Сборка пакета: https://wiki.ubuntu.com/Kernel/Dev/DKMSPackaging

```bash
sudo cp main.c /usr/src/ipsec_drop-0.1
sudo cp Makefile /usr/src/ipsec_drop-0.1
sudo cp dkms.conf /usr/src/ipsec_drop-0.1
sudo dkms add -m ipsec_drop -v 0.1
sudo dkms build -m ipsec_drop -v 0.1
#sudo dkms install -m ipsec_drop -v 0.1
sudo dkms mkdeb -m ipsec_drop -v 0.1
ls -al /var/lib/dkms/ipsec_drop/0.1/deb/ipsec-drop-dkms_0.1_amd64.deb
#sudo dkms remove -m ipsec_drop -v 0.1 --all
```