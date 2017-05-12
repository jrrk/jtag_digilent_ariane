module jtag_addr(output wire WR, output wire [31:0] ADDR,
input wire CAPTURE, RESET, RUNTEST, SEL, SHIFT, TDI, TMS, UPDATE, TCK,
output wire TDO);

parameter wid = 33;

reg [wid-1:0] SR;

reg [31:0] ADDR;
reg [7:0] CNT, CNT2;
reg 	  WR;
   
wire [15:0] dummy = 16'HDEAD;
wire [15:0] dummy2 = 16'HBEEF;   
   
assign TDO = SR[0];
   
always @(posedge TCK)
       begin
       if (RESET)
           begin
           SR = 0;
           WR = 0;
           ADDR = 0;
           end
       else if (SEL)
           begin
           if (CAPTURE)
               begin
               SR = {WR,ADDR};
               end
           if (UPDATE)
               begin
                  {WR,ADDR} = SR;
               end
           if (SHIFT)
             begin
                SR = {TDI,SR[wid-1:1]};
               end
           end
       end

endmodule
