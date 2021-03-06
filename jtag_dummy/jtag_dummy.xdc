# on board single-end clock, 100MHz
set_property PACKAGE_PIN E3 [get_ports clk_p]
set_property IOSTANDARD LVCMOS33 [get_ports clk_p]

# Reset "CPU_RESET" active low
set_property IOSTANDARD LVCMOS33 [get_ports rst_top]
set_property PACKAGE_PIN C12 [get_ports rst_top]
#set_property IOSTANDARD LVCMOS33 [get_ports rst_top]
#set_property LOC J15 [get_ports rst_top]; # mapped to switch 0

## Switches

set_property PACKAGE_PIN J15 [get_ports {i_dip[0]}]
set_property IOSTANDARD LVCMOS33 [get_ports {i_dip[0]}]
set_property PACKAGE_PIN L16 [get_ports {i_dip[1]}]
set_property IOSTANDARD LVCMOS33 [get_ports {i_dip[1]}]
set_property PACKAGE_PIN M13 [get_ports {i_dip[2]}]
set_property IOSTANDARD LVCMOS33 [get_ports {i_dip[2]}]
set_property PACKAGE_PIN R15 [get_ports {i_dip[3]}]
set_property IOSTANDARD LVCMOS33 [get_ports {i_dip[3]}]
set_property PACKAGE_PIN R17 [get_ports {i_dip[4]}]
set_property IOSTANDARD LVCMOS33 [get_ports {i_dip[4]}]
set_property PACKAGE_PIN T18 [get_ports {i_dip[5]}]
set_property IOSTANDARD LVCMOS33 [get_ports {i_dip[5]}]
set_property PACKAGE_PIN U18 [get_ports {i_dip[6]}]
set_property IOSTANDARD LVCMOS33 [get_ports {i_dip[6]}]
set_property PACKAGE_PIN R13 [get_ports {i_dip[7]}]
set_property IOSTANDARD LVCMOS33 [get_ports {i_dip[7]}]
# SW8 and SW9 are in the same bank of the DDR2 interface, which requires 1.8 V
set_property PACKAGE_PIN T8 [get_ports {i_dip[8]}]
set_property IOSTANDARD LVCMOS18 [get_ports {i_dip[8]}]
set_property PACKAGE_PIN U8 [get_ports {i_dip[9]}]
set_property IOSTANDARD LVCMOS18 [get_ports {i_dip[9]}]
set_property PACKAGE_PIN R16 [get_ports {i_dip[10]}]
set_property IOSTANDARD LVCMOS33 [get_ports {i_dip[10]}]
set_property PACKAGE_PIN T13 [get_ports {i_dip[11]}]
set_property IOSTANDARD LVCMOS33 [get_ports {i_dip[11]}]
set_property PACKAGE_PIN H6 [get_ports {i_dip[12]}]
set_property IOSTANDARD LVCMOS33 [get_ports {i_dip[12]}]
set_property PACKAGE_PIN U12 [get_ports {i_dip[13]}]
set_property IOSTANDARD LVCMOS33 [get_ports {i_dip[13]}]
set_property PACKAGE_PIN U11 [get_ports {i_dip[14]}]
set_property IOSTANDARD LVCMOS33 [get_ports {i_dip[14]}]
set_property PACKAGE_PIN V10 [get_ports {i_dip[15]}]
set_property IOSTANDARD LVCMOS33 [get_ports {i_dip[15]}]

## o_leds

set_property -dict { PACKAGE_PIN H17   IOSTANDARD LVCMOS33 } [get_ports { LED[0] }]; #IO_L18P_T2_A24_15 Sch=led[0]
set_property -dict { PACKAGE_PIN K15   IOSTANDARD LVCMOS33 } [get_ports { LED[1] }]; #IO_L24P_T3_RS1_15 Sch=led[1]
set_property -dict { PACKAGE_PIN J13   IOSTANDARD LVCMOS33 } [get_ports { LED[2] }]; #IO_L17N_T2_A25_15 Sch=led[2]
set_property -dict { PACKAGE_PIN N14   IOSTANDARD LVCMOS33 } [get_ports { LED[3] }]; #IO_L8P_T1_D11_14 Sch=led[3]
set_property -dict { PACKAGE_PIN R18   IOSTANDARD LVCMOS33 } [get_ports { LED[4] }]; #IO_L7P_T1_D09_14 Sch=led[4]
set_property -dict { PACKAGE_PIN V17   IOSTANDARD LVCMOS33 } [get_ports { LED[5] }]; #IO_L18N_T2_A11_D27_14 Sch=led[5]
set_property -dict { PACKAGE_PIN U17   IOSTANDARD LVCMOS33 } [get_ports { LED[6] }]; #IO_L17P_T2_A14_D30_14 Sch=led[6]
set_property -dict { PACKAGE_PIN U16   IOSTANDARD LVCMOS33 } [get_ports { LED[7] }]; #IO_L18P_T2_A12_D28_14 Sch=led[7]
set_property -dict { PACKAGE_PIN V16   IOSTANDARD LVCMOS33 } [get_ports { LED[8] }]; #IO_L16N_T2_A15_D31_14 Sch=led[8]
set_property -dict { PACKAGE_PIN T15   IOSTANDARD LVCMOS33 } [get_ports { LED[9] }]; #IO_L14N_T2_SRCC_14 Sch=led[9]
set_property -dict { PACKAGE_PIN U14   IOSTANDARD LVCMOS33 } [get_ports { LED[10] }]; #IO_L22P_T3_A05_D21_14 Sch=led[10]
set_property -dict { PACKAGE_PIN T16   IOSTANDARD LVCMOS33 } [get_ports { LED[11] }]; #IO_L15N_T2_DQS_DOUT_CSO_B_14 Sch=led[11]
set_property -dict { PACKAGE_PIN V15   IOSTANDARD LVCMOS33 } [get_ports { LED[12] }]; #IO_L16P_T2_CSI_B_14 Sch=led[12]
set_property -dict { PACKAGE_PIN V14   IOSTANDARD LVCMOS33 } [get_ports { LED[13] }]; #IO_L22N_T3_A04_D20_14 Sch=led[13]
set_property -dict { PACKAGE_PIN V12   IOSTANDARD LVCMOS33 } [get_ports { LED[14] }]; #IO_L20N_T3_A07_D23_14 Sch=led[14]
set_property -dict { PACKAGE_PIN V11   IOSTANDARD LVCMOS33 } [get_ports { LED[15] }]; #IO_L21N_T3_DQS_A06_D22_14 Sch=led[15]

set_property -dict { PACKAGE_PIN R12   IOSTANDARD LVCMOS33 } [get_ports { LED16_B }]; #IO_L5P_T0_D06_14 Sch=led16_b
set_property -dict { PACKAGE_PIN M16   IOSTANDARD LVCMOS33 } [get_ports { LED16_G }]; #IO_L10P_T1_D14_14 Sch=led16_g
set_property -dict { PACKAGE_PIN N15   IOSTANDARD LVCMOS33 } [get_ports { LED16_R }]; #IO_L11P_T1_SRCC_14 Sch=led16_r
set_property -dict { PACKAGE_PIN G14   IOSTANDARD LVCMOS33 } [get_ports { LED17_B }]; #IO_L15N_T2_DQS_ADV_B_15 Sch=led17_b
set_property -dict { PACKAGE_PIN R11   IOSTANDARD LVCMOS33 } [get_ports { LED17_G }]; #IO_0_14 Sch=led17_g
set_property -dict { PACKAGE_PIN N16   IOSTANDARD LVCMOS33 } [get_ports { LED17_R }]; #IO_L11N_T1_SRCC_14 Sch=led17_r

set_property BITSTREAM.CONFIG.SPI_BUSWIDTH 4 [current_design]
create_clock -period 100.000 -name jtag_clk -waveform {0.000 50.000} [get_pins jtag_buf/O]
