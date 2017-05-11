`timescale 1ns / 1ps
`default_nettype none

module jtag_dummy(input wire clk_p, input wire rst_top,
output wire [15:0] LED, input wire [15:0] i_dip,
output wire LED16_B, output wire LED16_G, output wire LED16_R,
output wire LED17_B, output wire LED17_G, output wire LED17_R);

wire CAPTURE, DRCK, RESET, RUNTEST, SEL, SHIFT, TDI, TDO, TMS, UPDATE, TCK, TCK_unbuf;

BUFG jtag_buf(.I(TCK_unbuf), .O(TCK));

   // BSCANE2: Boundary-Scan User Instruction
   //          Artix-7
   // Xilinx HDL Language Template, version 2017.1

   BSCANE2 #(
      .JTAG_CHAIN(1)  // Value for USER command.
   )
   BSCANE2_inst (
      .CAPTURE(CAPTURE), // 1-bit output: CAPTURE output from TAP controller.
      .DRCK(DRCK),       // 1-bit output: Gated TCK output. When SEL is asserted, DRCK toggles when CAPTURE or
                         // SHIFT are asserted.

      .RESET(RESET),     // 1-bit output: Reset output for TAP controller.
      .RUNTEST(RUNTEST), // 1-bit output: Output asserted when TAP controller is in Run Test/Idle state.
      .SEL(SEL),         // 1-bit output: USER instruction active output.
      .SHIFT(SHIFT),     // 1-bit output: SHIFT output from TAP controller.
      .TCK(TCK_unbuf),   // 1-bit output: Test Clock output. Fabric connection to TAP Clock pin.
      .TDI(TDI),         // 1-bit output: Test Data Input (TDI) output from TAP controller.
      .TMS(TMS),         // 1-bit output: Test Mode Select output. Fabric connection to TAP.
      .UPDATE(UPDATE),   // 1-bit output: UPDATE output from TAP controller
      .TDO(TDO)    // 1-bit input: Test Data Output (TDO) input for USER function.
   );

jtag_rom rom1(
.clk_p(clk_p),
.LED(LED),
.i_dip(i_dip),
.LED16_B(LED16_B),
.LED16_G(LED16_G),
.LED16_R(LED16_R),
.LED17_B(LED17_B),
.LED17_G(LED17_G),
.LED17_R(LED17_R),
.TDO(TDO),	 
.CAPTURE(CAPTURE), 
.RESET(RESET), 
.RUNTEST(RUNTEST), 
.SEL(SEL), 
.SHIFT(SHIFT), 
.TDI(TDI), 
.TMS(TMS), 
.UPDATE(UPDATE), 
.TCK(TCK)
);
				
endmodule
