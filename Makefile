O = regnum.o dump.o adapter.o commands.o core.o interface.o interfaces.o jtag/aice/aice_interface.o jtag/aice/aice_transport.o jtag/aice/aice_port.o jtag/aice/aice_pipe.o jtag/aice/aice_usb.o helper/binarybuffer.o helper/command.o helper/configuration.o jtag/drivers/driver.o jtag/drivers/ftdi.o jtag/drivers/mpsse.o jtag/drivers/osbdm.o jtag/drivers/opendous.o jtag/drivers/libusb1_common.o jtag/drivers/remote_bitbang.o jtag/drivers/bitbang.o jtag/drivers/jtag_vpi.o transport/transport.o target/adi_v5_swd.o main.o svf/svf.o xsvf/xsvf.o jimtcl/jim.o jimtcl/jim-format.o helper/log.o helper/time_support_common.o helper/jim-nvp.o helper/jep106.o tcl.o jimtcl/jim-eventloop.o target/nds32_reg.o jimtcl/utf8.o riscv_rocketpipe.o

P = breakpoints.cpp bridge.cpp cache.cpp debug_if.cpp fpga_if.cpp rsp.cpp
X = breakpoints.o bridge.o cache.o debug_if.o fpga_if.o rsp.o

CFLAGS =-std=gnu99 -g -Wall -I. -Ijtag -Ihelper -Ijimtcl -Ijtag/drivers/libjaylink -DHAVE_CONFIG_H -I/usr/include/libusb-1.0 -I/usr/local/share/verilator/include/vltstd -I../l3riscv/src/sml -DBUILD_ULINK=0 # -DVERBOSE # -DSVF_VERBOSE
CXXFLAGS =

jtag_digilent_ariane: $O $P
	$(CXX) -c $(CXXFLAGS) -DFPGA -g $P
	$(CXX) -o $@ $(CFLAGS) $O $X -lbfd -lusb-1.0 -L../l3riscv -Xlinker -rpath=../l3riscv -ll3riscv -lstdc++ # -lefence

riscv_rocketpipe.o: ../ariane/tb/riscv_rocketpipe.c
	$(CC) -c $(CFLAGS) -g $< -o $@
