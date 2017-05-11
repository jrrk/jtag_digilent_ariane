module jtag_rom(input wire clk_p,
output reg [15:0] LED, input wire [15:0] i_dip,
output reg LED16_B, output reg LED16_G, output reg LED16_R,
output reg LED17_B, output reg LED17_G, output reg LED17_R,
input wire CAPTURE, RESET, RUNTEST, SEL, SHIFT, TDI, TMS, UPDATE, TCK,
output wire TDO);

parameter wid = 64;
parameter dataw = 32;

reg [wid-1:0] SR;

wire [31:0] DO, DOB;
wire [3:0] DOP;
reg [30:0] ADDR;
reg [31:0] DI;
wire [3:0] DIP = 4'b0;
reg  RD, WR;
wire SSR = 1'b0;
reg [7:0] CNT, CNT2;

wire [15:0] dummy = 16'HDEAD;
wire [15:0] dummy2 = 16'HBEEF;
   
   
assign TDO = RD ? dummy[0] : SR[0];

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
       .CLKA(~TCK),      // Port A Clock
       .DOA(DO),  // Port A 1-bit Data wire
       .DOPA(DOP),
       .ADDRA(ADDR[8:0]),    // Port A 14-bit Address wire
       .DIA(DI),   // Port A 32-bit Data wire
       .DIPA(DIP),   // Port A 32-bit Data wire
       .ENA((RD|WR)&(0 == &ADDR[30:9])),    // Port A RAM Enable wire
       .SSRA(SSR),     // Port A Synchronous Set/Reset wire
       .WEA(WR),         // Port A Write Enable wire
       .CLKB(clk_p),      // Port A Clock
       .DOB(DOB),  // Port A 1-bit Data wire
       .DOPB(),
       .ADDRB(i_dip[9:1]),    // Port A 14-bit Address wire
       .DIB(32'b0),   // Port A 32-bit Data wire
       .DIPB(4'b0),   // Port A 32-bit Data wire
       .ENB(1'b1),    // Port A RAM Enable wire
       .SSRB(1'b0),     // Port A Synchronous Set/Reset wire
       .WEB(1'b0)         // Port A Write Enable wire
   );
   
always @(posedge TCK)
       begin
       if (RESET)
           begin
           {LED16_R,LED16_G,LED16_B} = 0;
           {LED17_R,LED17_G,LED17_B} = 0;
           CNT = 0;
           SR = 0;
           WR = 0;
           RD = 0;
           DI = 0;
           ADDR = 0;
           end
       else if (SEL)
           begin
           if (CAPTURE)
               begin
               CNT2 = CNT;
               CNT = 0;
               WR = 1'b0;
               RD = 1'b0;
               SR = {dummy[15:0],1'b0,ADDR[30:0],dummy2[15:0]};
               LED16_R = ~LED16_R;
               end
           if (UPDATE)
               begin
                  DI = SR[dataw-1:0];
                  ADDR = SR[wid-2:dataw];
                  WR = SR[wid-1];
                  RD = ~SR[wid-1];
                  CNT2 = CNT;
                  CNT = 0;
                  LED17_R = ~LED17_R;
               end
           if (SHIFT)
             begin
                if (RD)
                  begin
                     SR = {TDI,ADDR[15:0],DO,dummy[15:1]};
                     RD = 1'b0;
                     ADDR = ADDR+1;
                  end
                else
                  begin
                     WR = 1'b0;
                     SR = {TDI,SR[wid-1:1]};
                  end
                CNT = CNT + 1;
                if (CNT == wid)
                  begin
                     DI = SR[dataw-1:0];
                     if (SR[wid-1])
                        ADDR = SR[wid-2:dataw];
                     WR = SR[wid-1];
                     RD = ~SR[wid-1];
                     CNT2 = CNT;
                     CNT = 0;
                     LED17_R = ~LED17_R;
                  end
               end
           end
       end
      // End of BSCANE2_inst instantiation

always @(*) casez({i_dip[15:13],i_dip[0]})
    4'b0000: LED = DOB[15:0];
    4'b0001: LED = DOB[31:16];
    4'b1000: LED = DI[15:0];
    4'b1001: LED = DI[31:16];
    4'b1010: LED = ADDR[15:0];
    4'b1011: LED = ADDR[30:16];
    4'b110?: LED = {CNT2,CNT};
    4'b111?: LED = {CAPTURE, RESET, RUNTEST, SEL, SHIFT, TDI, TMS, UPDATE};
    endcase

endmodule // unmatched end(function|task|module|primitive|interface|package|class|clocking)
