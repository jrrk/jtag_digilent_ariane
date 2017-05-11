`timescale 1ns / 1ps
`default_nettype none

module tap_tb();

   reg clk_p;
   wire [15:0] LED;
   reg [15:0]  i_dip;
   wire        LED16_B;
   wire        LED16_G;
   wire        LED16_R;
   wire        LED17_B; 
   wire        LED17_G;
   wire        LED17_R;

   reg CAPTURE, RESET, RUNTEST, SEL, SHIFT, TDI, TMS, UPDATE;
   reg [63:0] readout, readout2;
   reg [5:0]  rcnt;
   
   wire TDO, TCK;

always
  begin
     #500 clk_p = 0;
     #500 clk_p = 1;
  end

initial
  begin
     i_dip = 16'HA000;
     CAPTURE = 0;
     RUNTEST = 0;
     RESET = 1;
     SEL = 1;
     SHIFT = 0;
     TDI = 0;
     TMS = 0;
     UPDATE = 0;
     #10000
       RESET = 0;
     @(negedge TCK)
       CAPTURE = 1;
     @(negedge TCK)
       CAPTURE = 0;
     @(negedge TCK)
       SHIFT = 1;
     
  end // initial begin

always @(negedge TCK) if (SEL)
  begin
     if (CAPTURE)
       begin
	  rcnt = 0;
	  readout = 0;
       end
     else if (SHIFT)
       begin
	  if (rcnt == 63)
	    readout2 = readout;
	  readout = {TDO,readout[63:1]};
	  rcnt = rcnt + 1;
       end
  end
   
assign TCK = clk_p;   

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
