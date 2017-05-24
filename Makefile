O = adapter.o commands.o core.o interface.o interfaces.o jtag/aice/aice_interface.o jtag/aice/aice_transport.o jtag/aice/aice_port.o jtag/aice/aice_pipe.o jtag/aice/aice_usb.o helper/binarybuffer.o helper/command.o helper/configuration.o jtag/drivers/driver.o jtag/drivers/ftdi.o jtag/drivers/mpsse.o jtag/drivers/osbdm.o jtag/drivers/opendous.o jtag/drivers/libusb1_common.o transport/transport.o target/adi_v5_swd.o stubs.o svf/svf.o xsvf/xsvf.o jimtcl/jim.o jimtcl/jim-format.o helper/log.o helper/time_support_common.o helper/jim-nvp.o helper/jep106.o tcl.o jimtcl/jim-eventloop.o target/nds32_reg.o jimtcl/utf8.o

CFLAGS =-g -I. -Ijtag -Ihelper -Ijimtcl -Ijtag/drivers/libjaylink -DHAVE_CONFIG_H -I/usr/include/libusb-1.0 -DBUILD_ULINK=0

jtag_digilent: $O
	$(CC) -o $@ $(CFLAGS) $O -lusb-1.0
