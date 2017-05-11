simv: tap_tb.v ../jtag_dummy/jtag_rom.v
	vcs -gui -full64 +lint=TFIPC-L +lint=PCWM tap_tb.v ../jtag_dummy/jtag_rom.v -y /opt/Xilinx/Vivado/2016.2/data/verilog/src/retarget +libext+.v -y /opt/Xilinx/Vivado/2016.2/data/verilog/src/unisims +libext+.v /opt/Xilinx/Vivado/2016.2/data/verilog/src/glbl.v |& tee logfile
