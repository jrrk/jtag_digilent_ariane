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


module jtag_dummy(input clk_p, input rst_top,
output [15:0] LED, input [15:0] i_dip,
output reg LED16_B, output reg LED16_G, output reg LED16_R,
output reg LED17_B, output reg LED17_G, output reg LED17_R);

parameter wid = 42;
parameter dataw = 32;

reg [wid-1:0] SR;

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
      .TDO(SR[0])    // 1-bit input: Test Data Output (TDO) input for USER function.
   );

BUFG jtag_buf(.I(TCK), .O(jtag_clk));
wire [31:0] DO, DOB;
wire [3:0] DOP;
reg [8:0] ADDR;
reg [31:0] DI;
wire [3:0] DIP = 4'b0;
reg EN;
wire CLK = jtag_clk;
reg  WE;
wire SSR = 1'b0;
reg [5:0] CNT, CNT2, OFF;

always @(posedge jtag_clk)
    begin
    if (!rst_top)
        begin
        {LED16_R,LED16_G,LED16_B} = 0;
        {LED17_R,LED17_G,LED17_B} = 0;
        CNT = 0;
        OFF = 0;
        SR = 0;
        WE = 0;
        EN = 0;
        DI = 0;
        end
    else if (SEL)
        begin
        EN = 1'b0;
        if (CAPTURE)
            begin
            CNT2 = CNT;
            CNT = 0;
            WE = 1'b0;
            EN = 1'b1;
            LED16_R = ~LED16_R;
            SR = {ADDR,DO};
            end
        if (SHIFT)
            begin
            SR = {TDI,SR[wid-1:1]};
            CNT = CNT + 1;
            if (CNT == wid)
                    begin
                    OFF = OFF + 1;
                    ADDR = ADDR + 1;
                    DI = SR[dataw-1:0];
                    EN = 1'b1;
                    CNT = 0;
                    end
            end
        if (UPDATE)
            begin
            ADDR = SR[wid-2:dataw];
            WE = SR[wid-1];
            EN = 1'b1;
            CNT2 = CNT;
            CNT = 0;
            LED17_R = ~LED17_R;
            if (WE)
                begin
                DI = SR[dataw-1:0];
                end            
            else
                begin
                
                end
            end
        end
    end
   // End of BSCANE2_inst instantiation

   RAMB16_S36_S36 #(
        // The following INIT_xx declarations specify the initial contents of the RAM
        .INIT_00(256'hC036BE7C001466DB207ED90C06000071C071C0000CB264FFFFFFFFF8D07FFFFF),
        .INIT_01(256'h000000000000000000000000000000000000007D8A00049CC40733ED71827F9E),
        .INIT_02(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_03(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_04(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_05(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_06(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_07(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_08(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_09(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_0A(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_0B(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_0C(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_0D(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_0E(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_0F(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_10(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_11(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_12(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_13(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_14(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_15(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_16(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_17(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_18(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_19(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_1A(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_1B(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_1C(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_1D(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_1E(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_1F(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_20(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_21(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_22(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_23(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_24(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_25(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_26(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_27(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_28(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_29(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_2A(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_2B(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_2C(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_2D(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_2E(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_2F(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_30(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_31(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_32(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_33(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_34(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_35(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_36(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_37(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_38(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_39(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_3A(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_3B(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_3C(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_3D(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_3E(256'h0000000000000000000000000000000000000000000000000000000000000000),
        .INIT_3F(256'h0000000000000000000000000000000000000000000000000000000000000000))
     RAMB16_inst (
       .CLKA(~jtag_clk),      // Port A Clock
       .DOA(DO),  // Port A 1-bit Data wire
       .DOPA(DOP),
       .ADDRA(ADDR),    // Port A 14-bit Address wire
       .DIA(DI),   // Port A 32-bit Data wire
       .DIPA(DIP),   // Port A 32-bit Data wire
       .ENA(EN),    // Port A RAM Enable wire
       .SSRA(SSR),     // Port A Synchronous Set/Reset wire
       .WEA(WE),         // Port A Write Enable wire
       .CLKB(clk_p),      // Port A Clock
       .DOB(DOB),  // Port A 1-bit Data wire
       .DOPB(),
       .ADDRB(i_dip[9:1]),    // Port A 14-bit Address wire
       .DIB(32'b0),   // Port A 32-bit Data wire
       .DIPB(4'b0),   // Port A 32-bit Data wire
       .ENB(1'b1),    // Port A RAM Enable wire
       .SSRB(1'b0),     // Port A Synchronous Set/Reset wire
       .WEB(1'b0)         // Port A Write Enable wire
   ); // 

assign LED = i_dip[15] ? {WE,CNT2,OFF} : (i_dip[0] ? DOB[31:16] : DOB[15:0]);
				
endmodule
