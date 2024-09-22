.include "asm_setup.S"
.extern DWCi_Auth_SendRequest
.global DWCi_Auth_SendRequest_Replaced

# Having SP's REPLACED system would simplify this

DWCi_Auth_SendRequest_Replaced:
stwu r1, -0x1B0(r1)
b DWCi_Auth_SendRequest+4
