module jtag_addr(output reg INC, output reg WR, output reg [31:0] ADDR,
input wire CAPTURE, RESET, RUNTEST, SEL, SHIFT, TDI, TMS, UPDATE, TCK,
output wire TDO);

parameter wid = 34;

reg [wid-1:0] SR;

assign TDO = SR[0];
   
always @(posedge TCK)
       begin
       if (RESET)
           begin
           SR = 0;
           WR = 0;
	   INC = 0;
           ADDR = 0;
           end
       else if (SEL)
           begin
           if (CAPTURE)
               begin
               SR = {INC,WR,ADDR};
               end
           if (UPDATE)
               begin
                  {INC,WR,ADDR} = SR;
               end
           if (SHIFT)
             begin
                SR = {TDI,SR[wid-1:1]};
               end
           end
       end

endmodule
