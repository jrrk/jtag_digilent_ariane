O = dump.o adapter.o commands.o core.o interface.o interfaces.o jtag/aice/aice_interface.o jtag/aice/aice_transport.o jtag/aice/aice_port.o jtag/aice/aice_pipe.o jtag/aice/aice_usb.o helper/binarybuffer.o helper/command.o helper/configuration.o jtag/drivers/driver.o jtag/drivers/ftdi.o jtag/drivers/mpsse.o jtag/drivers/osbdm.o jtag/drivers/opendous.o jtag/drivers/libusb1_common.o jtag/drivers/remote_bitbang.o jtag/drivers/bitbang.o jtag/drivers/jtag_vpi.o transport/transport.o target/adi_v5_swd.o main.o svf/svf.o xsvf/xsvf.o jimtcl/jim.o jimtcl/jim-format.o helper/log.o helper/time_support_common.o helper/jim-nvp.o helper/jep106.o tcl.o jimtcl/jim-eventloop.o target/nds32_reg.o jimtcl/utf8.o

P = breakpoints.cpp bridge.cpp cache.cpp debug_if.cpp fpga_if.cpp rsp.cpp
X = breakpoints.o bridge.o cache.o debug_if.o fpga_if.o rsp.o

CFLAGS =-g -Wall -I. -Ijtag -Ihelper -Ijimtcl -Ijtag/drivers/libjaylink -DHAVE_CONFIG_H -I/usr/include/libusb-1.0 -DBUILD_ULINK=0 # -DVERBOSE # -DSVF_VERBOSE

jtag_digilent_ariane: $O $P
	$(CXX) -c -DFPGA -g $P
	$(CXX) -o $@ $(CFLAGS) $O $X -lusb-1.0 -lstdc++
