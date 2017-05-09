`timescale 1ns / 1ps
//////////////////////////////////////////////////////////////////////////////////
// Company: 
// Engineer: 
// 
// Create Date: 09.05.2017 20:41:26
// Design Name: 
// Module Name: jtag_dummy
// Project Name: 
// Target Devices: 
// Tool Versions: 
// Description: 
// 
// Dependencies: 
// 
// Revision:
// Revision 0.01 - File Created
// Additional Comments:
// 
//////////////////////////////////////////////////////////////////////////////////


module jtag_dummy(input clk_p, output reg [11:0] o_led, input [15:0] i_dip);

reg TDO;
reg [15:0] SR;

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
      .TCK(TCK),         // 1-bit output: Test Clock output. Fabric connection to TAP Clock pin.
      .TDI(TDI),         // 1-bit output: Test Data Input (TDI) output from TAP controller.
      .TMS(TMS),         // 1-bit output: Test Mode Select output. Fabric connection to TAP.
      .UPDATE(UPDATE),   // 1-bit output: UPDATE output from TAP controller
      .TDO(TDO)          // 1-bit input: Test Data Output (TDO) input for USER function.
   );

always @(posedge DRCK)
    begin
    if (SHIFT)
        {TDO,SR[15:0]} = {SR[15:0],TDI};
    if (CAPTURE)
        SR = i_dip;
//    if (UPDATE)
        o_led = SR;
    end
   // End of BSCANE2_inst instantiation
				
				
endmodule
