let keccak1eo_mc = define_assert_from_elf "keccak1eo_mc" "/data/ecesena/firedancer/src/ballet/keccak256/proof/keccak1eo_proofobj.o"
[
  0x55;                    (* PUSH (% rbp) *)
  0x53;                    (* PUSH (% rbx) *)
  0x48; 0x89; 0xe5;        (* MOV (% rbp) (% rsp) *)
  0x48; 0x83; 0xe4; 0xe0;  (* AND (% rsp) (Imm8 (word 224)) *)
  0x48; 0x81; 0xec; 0x18; 0x01; 0x00; 0x00;
                           (* SUB (% rsp) (Imm32 (word 280)) *)
  0x48; 0x8d; 0x96; 0xc0; 0x00; 0x00; 0x00;
                           (* LEA (% rdx) (%% (rsi,192)) *)
  0x66; 0x0f; 0x1f; 0x84; 0x00; 0x00; 0x00; 0x00; 0x00;
                           (* NOP_N (Memop Word (%%% (rax,0,rax))) *)
  0x8b; 0x07;              (* MOV (% eax) (Memop Doubleword (%% (rdi,0))) *)
  0x33; 0x47; 0x14;        (* XOR (% eax) (Memop Doubleword (%% (rdi,20))) *)
  0x33; 0x47; 0x28;        (* XOR (% eax) (Memop Doubleword (%% (rdi,40))) *)
  0x33; 0x47; 0x3c;        (* XOR (% eax) (Memop Doubleword (%% (rdi,60))) *)
  0x33; 0x47; 0x50;        (* XOR (% eax) (Memop Doubleword (%% (rdi,80))) *)
  0x89; 0x84; 0x24; 0xc8; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,200))) (% eax) *)
  0x8b; 0x47; 0x04;        (* MOV (% eax) (Memop Doubleword (%% (rdi,4))) *)
  0x33; 0x47; 0x18;        (* XOR (% eax) (Memop Doubleword (%% (rdi,24))) *)
  0x33; 0x47; 0x2c;        (* XOR (% eax) (Memop Doubleword (%% (rdi,44))) *)
  0x33; 0x47; 0x40;        (* XOR (% eax) (Memop Doubleword (%% (rdi,64))) *)
  0x33; 0x47; 0x54;        (* XOR (% eax) (Memop Doubleword (%% (rdi,84))) *)
  0x89; 0x84; 0x24; 0xcc; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,204))) (% eax) *)
  0x8b; 0x47; 0x08;        (* MOV (% eax) (Memop Doubleword (%% (rdi,8))) *)
  0x33; 0x47; 0x1c;        (* XOR (% eax) (Memop Doubleword (%% (rdi,28))) *)
  0x33; 0x47; 0x30;        (* XOR (% eax) (Memop Doubleword (%% (rdi,48))) *)
  0x33; 0x47; 0x44;        (* XOR (% eax) (Memop Doubleword (%% (rdi,68))) *)
  0x33; 0x47; 0x58;        (* XOR (% eax) (Memop Doubleword (%% (rdi,88))) *)
  0x89; 0x84; 0x24; 0xd0; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,208))) (% eax) *)
  0x8b; 0x47; 0x0c;        (* MOV (% eax) (Memop Doubleword (%% (rdi,12))) *)
  0x33; 0x47; 0x20;        (* XOR (% eax) (Memop Doubleword (%% (rdi,32))) *)
  0x33; 0x47; 0x34;        (* XOR (% eax) (Memop Doubleword (%% (rdi,52))) *)
  0x33; 0x47; 0x48;        (* XOR (% eax) (Memop Doubleword (%% (rdi,72))) *)
  0x33; 0x47; 0x5c;        (* XOR (% eax) (Memop Doubleword (%% (rdi,92))) *)
  0x89; 0x84; 0x24; 0xd4; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,212))) (% eax) *)
  0x8b; 0x47; 0x10;        (* MOV (% eax) (Memop Doubleword (%% (rdi,16))) *)
  0x33; 0x47; 0x24;        (* XOR (% eax) (Memop Doubleword (%% (rdi,36))) *)
  0x33; 0x47; 0x38;        (* XOR (% eax) (Memop Doubleword (%% (rdi,56))) *)
  0x33; 0x47; 0x4c;        (* XOR (% eax) (Memop Doubleword (%% (rdi,76))) *)
  0x33; 0x47; 0x60;        (* XOR (% eax) (Memop Doubleword (%% (rdi,96))) *)
  0x89; 0x84; 0x24; 0xd8; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,216))) (% eax) *)
  0x8b; 0x47; 0x64;        (* MOV (% eax) (Memop Doubleword (%% (rdi,100))) *)
  0x33; 0x47; 0x78;        (* XOR (% eax) (Memop Doubleword (%% (rdi,120))) *)
  0x33; 0x87; 0x8c; 0x00; 0x00; 0x00;
                           (* XOR (% eax) (Memop Doubleword (%% (rdi,140))) *)
  0x33; 0x87; 0xa0; 0x00; 0x00; 0x00;
                           (* XOR (% eax) (Memop Doubleword (%% (rdi,160))) *)
  0x33; 0x87; 0xb4; 0x00; 0x00; 0x00;
                           (* XOR (% eax) (Memop Doubleword (%% (rdi,180))) *)
  0x89; 0x84; 0x24; 0xdc; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,220))) (% eax) *)
  0x8b; 0x47; 0x68;        (* MOV (% eax) (Memop Doubleword (%% (rdi,104))) *)
  0x33; 0x47; 0x7c;        (* XOR (% eax) (Memop Doubleword (%% (rdi,124))) *)
  0x33; 0x87; 0x90; 0x00; 0x00; 0x00;
                           (* XOR (% eax) (Memop Doubleword (%% (rdi,144))) *)
  0x33; 0x87; 0xa4; 0x00; 0x00; 0x00;
                           (* XOR (% eax) (Memop Doubleword (%% (rdi,164))) *)
  0x33; 0x87; 0xb8; 0x00; 0x00; 0x00;
                           (* XOR (% eax) (Memop Doubleword (%% (rdi,184))) *)
  0x89; 0x84; 0x24; 0xe0; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,224))) (% eax) *)
  0x8b; 0x47; 0x6c;        (* MOV (% eax) (Memop Doubleword (%% (rdi,108))) *)
  0x33; 0x87; 0x80; 0x00; 0x00; 0x00;
                           (* XOR (% eax) (Memop Doubleword (%% (rdi,128))) *)
  0x33; 0x87; 0x94; 0x00; 0x00; 0x00;
                           (* XOR (% eax) (Memop Doubleword (%% (rdi,148))) *)
  0x33; 0x87; 0xa8; 0x00; 0x00; 0x00;
                           (* XOR (% eax) (Memop Doubleword (%% (rdi,168))) *)
  0x33; 0x87; 0xbc; 0x00; 0x00; 0x00;
                           (* XOR (% eax) (Memop Doubleword (%% (rdi,188))) *)
  0x89; 0x84; 0x24; 0xe4; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,228))) (% eax) *)
  0x8b; 0x47; 0x70;        (* MOV (% eax) (Memop Doubleword (%% (rdi,112))) *)
  0x33; 0x87; 0x84; 0x00; 0x00; 0x00;
                           (* XOR (% eax) (Memop Doubleword (%% (rdi,132))) *)
  0x33; 0x87; 0x98; 0x00; 0x00; 0x00;
                           (* XOR (% eax) (Memop Doubleword (%% (rdi,152))) *)
  0x33; 0x87; 0xac; 0x00; 0x00; 0x00;
                           (* XOR (% eax) (Memop Doubleword (%% (rdi,172))) *)
  0x33; 0x87; 0xc0; 0x00; 0x00; 0x00;
                           (* XOR (% eax) (Memop Doubleword (%% (rdi,192))) *)
  0x89; 0x84; 0x24; 0xe8; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,232))) (% eax) *)
  0x8b; 0x47; 0x74;        (* MOV (% eax) (Memop Doubleword (%% (rdi,116))) *)
  0x33; 0x87; 0x88; 0x00; 0x00; 0x00;
                           (* XOR (% eax) (Memop Doubleword (%% (rdi,136))) *)
  0x33; 0x87; 0x9c; 0x00; 0x00; 0x00;
                           (* XOR (% eax) (Memop Doubleword (%% (rdi,156))) *)
  0x33; 0x87; 0xb0; 0x00; 0x00; 0x00;
                           (* XOR (% eax) (Memop Doubleword (%% (rdi,176))) *)
  0x33; 0x87; 0xc4; 0x00; 0x00; 0x00;
                           (* XOR (% eax) (Memop Doubleword (%% (rdi,196))) *)
  0x89; 0x84; 0x24; 0xec; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,236))) (% eax) *)
  0x8b; 0x84; 0x24; 0xe0; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,224))) *)
  0x89; 0xc1;              (* MOV (% ecx) (% eax) *)
  0xd1; 0xe0;              (* SHL (% eax) (Imm8 (word 1)) *)
  0xc1; 0xe9; 0x1f;        (* SHR (% ecx) (Imm8 (word 31)) *)
  0x09; 0xc8;              (* OR (% eax) (% ecx) *)
  0x33; 0x84; 0x24; 0xd8; 0x00; 0x00; 0x00;
                           (* XOR (% eax) (Memop Doubleword (%% (rsp,216))) *)
  0x89; 0x84; 0x24; 0xf0; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,240))) (% eax) *)
  0x8b; 0x84; 0x24; 0xec; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,236))) *)
  0x33; 0x84; 0x24; 0xcc; 0x00; 0x00; 0x00;
                           (* XOR (% eax) (Memop Doubleword (%% (rsp,204))) *)
  0x89; 0x84; 0x24; 0x04; 0x01; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,260))) (% eax) *)
  0x8b; 0x84; 0x24; 0xe4; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,228))) *)
  0x89; 0xc1;              (* MOV (% ecx) (% eax) *)
  0xd1; 0xe0;              (* SHL (% eax) (Imm8 (word 1)) *)
  0xc1; 0xe9; 0x1f;        (* SHR (% ecx) (Imm8 (word 31)) *)
  0x09; 0xc8;              (* OR (% eax) (% ecx) *)
  0x33; 0x84; 0x24; 0xc8; 0x00; 0x00; 0x00;
                           (* XOR (% eax) (Memop Doubleword (%% (rsp,200))) *)
  0x89; 0x84; 0x24; 0xf4; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,244))) (% eax) *)
  0x8b; 0x84; 0x24; 0xdc; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,220))) *)
  0x33; 0x84; 0x24; 0xd0; 0x00; 0x00; 0x00;
                           (* XOR (% eax) (Memop Doubleword (%% (rsp,208))) *)
  0x89; 0x84; 0x24; 0x08; 0x01; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,264))) (% eax) *)
  0x8b; 0x84; 0x24; 0xe8; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,232))) *)
  0x89; 0xc1;              (* MOV (% ecx) (% eax) *)
  0xd1; 0xe0;              (* SHL (% eax) (Imm8 (word 1)) *)
  0xc1; 0xe9; 0x1f;        (* SHR (% ecx) (Imm8 (word 31)) *)
  0x09; 0xc8;              (* OR (% eax) (% ecx) *)
  0x33; 0x84; 0x24; 0xcc; 0x00; 0x00; 0x00;
                           (* XOR (% eax) (Memop Doubleword (%% (rsp,204))) *)
  0x89; 0x84; 0x24; 0xf8; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,248))) (% eax) *)
  0x8b; 0x84; 0x24; 0xe0; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,224))) *)
  0x33; 0x84; 0x24; 0xd4; 0x00; 0x00; 0x00;
                           (* XOR (% eax) (Memop Doubleword (%% (rsp,212))) *)
  0x89; 0x84; 0x24; 0x0c; 0x01; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,268))) (% eax) *)
  0x8b; 0x84; 0x24; 0xec; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,236))) *)
  0x89; 0xc1;              (* MOV (% ecx) (% eax) *)
  0xd1; 0xe0;              (* SHL (% eax) (Imm8 (word 1)) *)
  0xc1; 0xe9; 0x1f;        (* SHR (% ecx) (Imm8 (word 31)) *)
  0x09; 0xc8;              (* OR (% eax) (% ecx) *)
  0x33; 0x84; 0x24; 0xd0; 0x00; 0x00; 0x00;
                           (* XOR (% eax) (Memop Doubleword (%% (rsp,208))) *)
  0x89; 0x84; 0x24; 0xfc; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,252))) (% eax) *)
  0x8b; 0x84; 0x24; 0xe4; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,228))) *)
  0x33; 0x84; 0x24; 0xd8; 0x00; 0x00; 0x00;
                           (* XOR (% eax) (Memop Doubleword (%% (rsp,216))) *)
  0x89; 0x84; 0x24; 0x10; 0x01; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,272))) (% eax) *)
  0x8b; 0x84; 0x24; 0xdc; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,220))) *)
  0x89; 0xc1;              (* MOV (% ecx) (% eax) *)
  0xd1; 0xe0;              (* SHL (% eax) (Imm8 (word 1)) *)
  0xc1; 0xe9; 0x1f;        (* SHR (% ecx) (Imm8 (word 31)) *)
  0x09; 0xc8;              (* OR (% eax) (% ecx) *)
  0x33; 0x84; 0x24; 0xd4; 0x00; 0x00; 0x00;
                           (* XOR (% eax) (Memop Doubleword (%% (rsp,212))) *)
  0x89; 0x84; 0x24; 0x00; 0x01; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,256))) (% eax) *)
  0x8b; 0x84; 0x24; 0xe8; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,232))) *)
  0x33; 0x84; 0x24; 0xc8; 0x00; 0x00; 0x00;
                           (* XOR (% eax) (Memop Doubleword (%% (rsp,200))) *)
  0x89; 0x84; 0x24; 0x14; 0x01; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,276))) (% eax) *)
  0x8b; 0x84; 0x24; 0xf0; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,240))) *)
  0x89; 0x84; 0x24; 0xc8; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,200))) (% eax) *)
  0x8b; 0x84; 0x24; 0x04; 0x01; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,260))) *)
  0x89; 0x84; 0x24; 0xdc; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,220))) (% eax) *)
  0x8b; 0x84; 0x24; 0xf4; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,244))) *)
  0x89; 0x84; 0x24; 0xcc; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,204))) (% eax) *)
  0x8b; 0x84; 0x24; 0x08; 0x01; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,264))) *)
  0x89; 0x84; 0x24; 0xe0; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,224))) (% eax) *)
  0x8b; 0x84; 0x24; 0xf8; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,248))) *)
  0x89; 0x84; 0x24; 0xd0; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,208))) (% eax) *)
  0x8b; 0x84; 0x24; 0x0c; 0x01; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,268))) *)
  0x89; 0x84; 0x24; 0xe4; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,228))) (% eax) *)
  0x8b; 0x84; 0x24; 0xfc; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,252))) *)
  0x89; 0x84; 0x24; 0xd4; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,212))) (% eax) *)
  0x8b; 0x84; 0x24; 0x10; 0x01; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,272))) *)
  0x89; 0x84; 0x24; 0xe8; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,232))) (% eax) *)
  0x8b; 0x84; 0x24; 0x00; 0x01; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,256))) *)
  0x89; 0x84; 0x24; 0xd8; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,216))) (% eax) *)
  0x8b; 0x84; 0x24; 0x14; 0x01; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,276))) *)
  0x89; 0x84; 0x24; 0xec; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,236))) (% eax) *)
  0x8b; 0x84; 0x24; 0xc8; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,200))) *)
  0x33; 0x07;              (* XOR (% eax) (Memop Doubleword (%% (rdi,0))) *)
  0x8b; 0x8c; 0x24; 0xdc; 0x00; 0x00; 0x00;
                           (* MOV (% ecx) (Memop Doubleword (%% (rsp,220))) *)
  0x33; 0x4f; 0x64;        (* XOR (% ecx) (Memop Doubleword (%% (rdi,100))) *)
  0x89; 0x04; 0x24;        (* MOV (Memop Doubleword (%% (rsp,0))) (% eax) *)
  0x89; 0x4c; 0x24; 0x64;  (* MOV (Memop Doubleword (%% (rsp,100))) (% ecx) *)
  0x8b; 0x84; 0x24; 0xcc; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,204))) *)
  0x33; 0x47; 0x04;        (* XOR (% eax) (Memop Doubleword (%% (rdi,4))) *)
  0x8b; 0x8c; 0x24; 0xe0; 0x00; 0x00; 0x00;
                           (* MOV (% ecx) (Memop Doubleword (%% (rsp,224))) *)
  0x33; 0x4f; 0x68;        (* XOR (% ecx) (Memop Doubleword (%% (rdi,104))) *)
  0x89; 0xcb;              (* MOV (% ebx) (% ecx) *)
  0xd1; 0xe1;              (* SHL (% ecx) (Imm8 (word 1)) *)
  0xc1; 0xeb; 0x1f;        (* SHR (% ebx) (Imm8 (word 31)) *)
  0x09; 0xd9;              (* OR (% ecx) (% ebx) *)
  0x89; 0x4c; 0x24; 0x28;  (* MOV (Memop Doubleword (%% (rsp,40))) (% ecx) *)
  0x89; 0x84; 0x24; 0x8c; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,140))) (% eax) *)
  0x8b; 0x84; 0x24; 0xc8; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,200))) *)
  0x33; 0x47; 0x28;        (* XOR (% eax) (Memop Doubleword (%% (rdi,40))) *)
  0x8b; 0x8c; 0x24; 0xdc; 0x00; 0x00; 0x00;
                           (* MOV (% ecx) (Memop Doubleword (%% (rsp,220))) *)
  0x33; 0x8f; 0x8c; 0x00; 0x00; 0x00;
                           (* XOR (% ecx) (Memop Doubleword (%% (rdi,140))) *)
  0x89; 0xcb;              (* MOV (% ebx) (% ecx) *)
  0xc1; 0xe1; 0x02;        (* SHL (% ecx) (Imm8 (word 2)) *)
  0xc1; 0xeb; 0x1e;        (* SHR (% ebx) (Imm8 (word 30)) *)
  0x09; 0xd9;              (* OR (% ecx) (% ebx) *)
  0x89; 0x4c; 0x24; 0x1c;  (* MOV (Memop Doubleword (%% (rsp,28))) (% ecx) *)
  0x89; 0xc3;              (* MOV (% ebx) (% eax) *)
  0xd1; 0xe0;              (* SHL (% eax) (Imm8 (word 1)) *)
  0xc1; 0xeb; 0x1f;        (* SHR (% ebx) (Imm8 (word 31)) *)
  0x09; 0xd8;              (* OR (% eax) (% ebx) *)
  0x89; 0x84; 0x24; 0x80; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,128))) (% eax) *)
  0x8b; 0x84; 0x24; 0xd0; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,208))) *)
  0x33; 0x47; 0x1c;        (* XOR (% eax) (Memop Doubleword (%% (rdi,28))) *)
  0x8b; 0x8c; 0x24; 0xe4; 0x00; 0x00; 0x00;
                           (* MOV (% ecx) (Memop Doubleword (%% (rsp,228))) *)
  0x33; 0x8f; 0x80; 0x00; 0x00; 0x00;
                           (* XOR (% ecx) (Memop Doubleword (%% (rdi,128))) *)
  0x89; 0xc3;              (* MOV (% ebx) (% eax) *)
  0xc1; 0xe0; 0x03;        (* SHL (% eax) (Imm8 (word 3)) *)
  0xc1; 0xeb; 0x1d;        (* SHR (% ebx) (Imm8 (word 29)) *)
  0x09; 0xd8;              (* OR (% eax) (% ebx) *)
  0x89; 0x44; 0x24; 0x2c;  (* MOV (Memop Doubleword (%% (rsp,44))) (% eax) *)
  0x89; 0xcb;              (* MOV (% ebx) (% ecx) *)
  0xc1; 0xe1; 0x03;        (* SHL (% ecx) (Imm8 (word 3)) *)
  0xc1; 0xeb; 0x1d;        (* SHR (% ebx) (Imm8 (word 29)) *)
  0x09; 0xd9;              (* OR (% ecx) (% ebx) *)
  0x89; 0x8c; 0x24; 0x90; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,144))) (% ecx) *)
  0x8b; 0x84; 0x24; 0xcc; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,204))) *)
  0x33; 0x47; 0x2c;        (* XOR (% eax) (Memop Doubleword (%% (rdi,44))) *)
  0x8b; 0x8c; 0x24; 0xe0; 0x00; 0x00; 0x00;
                           (* MOV (% ecx) (Memop Doubleword (%% (rsp,224))) *)
  0x33; 0x8f; 0x90; 0x00; 0x00; 0x00;
                           (* XOR (% ecx) (Memop Doubleword (%% (rdi,144))) *)
  0x89; 0xc3;              (* MOV (% ebx) (% eax) *)
  0xc1; 0xe0; 0x05;        (* SHL (% eax) (Imm8 (word 5)) *)
  0xc1; 0xeb; 0x1b;        (* SHR (% ebx) (Imm8 (word 27)) *)
  0x09; 0xd8;              (* OR (% eax) (% ebx) *)
  0x89; 0x44; 0x24; 0x44;  (* MOV (Memop Doubleword (%% (rsp,68))) (% eax) *)
  0x89; 0xcb;              (* MOV (% ebx) (% ecx) *)
  0xc1; 0xe1; 0x05;        (* SHL (% ecx) (Imm8 (word 5)) *)
  0xc1; 0xeb; 0x1b;        (* SHR (% ebx) (Imm8 (word 27)) *)
  0x09; 0xd9;              (* OR (% ecx) (% ebx) *)
  0x89; 0x8c; 0x24; 0xa8; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,168))) (% ecx) *)
  0x8b; 0x84; 0x24; 0xd0; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,208))) *)
  0x33; 0x47; 0x44;        (* XOR (% eax) (Memop Doubleword (%% (rdi,68))) *)
  0x8b; 0x8c; 0x24; 0xe4; 0x00; 0x00; 0x00;
                           (* MOV (% ecx) (Memop Doubleword (%% (rsp,228))) *)
  0x33; 0x8f; 0xa8; 0x00; 0x00; 0x00;
                           (* XOR (% ecx) (Memop Doubleword (%% (rdi,168))) *)
  0x89; 0xcb;              (* MOV (% ebx) (% ecx) *)
  0xc1; 0xe1; 0x08;        (* SHL (% ecx) (Imm8 (word 8)) *)
  0xc1; 0xeb; 0x18;        (* SHR (% ebx) (Imm8 (word 24)) *)
  0x09; 0xd9;              (* OR (% ecx) (% ebx) *)
  0x89; 0x4c; 0x24; 0x48;  (* MOV (Memop Doubleword (%% (rsp,72))) (% ecx) *)
  0x89; 0xc3;              (* MOV (% ebx) (% eax) *)
  0xc1; 0xe0; 0x07;        (* SHL (% eax) (Imm8 (word 7)) *)
  0xc1; 0xeb; 0x19;        (* SHR (% ebx) (Imm8 (word 25)) *)
  0x09; 0xd8;              (* OR (% eax) (% ebx) *)
  0x89; 0x84; 0x24; 0xac; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,172))) (% eax) *)
  0x8b; 0x84; 0x24; 0xd4; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,212))) *)
  0x33; 0x47; 0x48;        (* XOR (% eax) (Memop Doubleword (%% (rdi,72))) *)
  0x8b; 0x8c; 0x24; 0xe8; 0x00; 0x00; 0x00;
                           (* MOV (% ecx) (Memop Doubleword (%% (rsp,232))) *)
  0x33; 0x8f; 0xac; 0x00; 0x00; 0x00;
                           (* XOR (% ecx) (Memop Doubleword (%% (rdi,172))) *)
  0x89; 0xcb;              (* MOV (% ebx) (% ecx) *)
  0xc1; 0xe1; 0x0b;        (* SHL (% ecx) (Imm8 (word 11)) *)
  0xc1; 0xeb; 0x15;        (* SHR (% ebx) (Imm8 (word 21)) *)
  0x09; 0xd9;              (* OR (% ecx) (% ebx) *)
  0x89; 0x4c; 0x24; 0x0c;  (* MOV (Memop Doubleword (%% (rsp,12))) (% ecx) *)
  0x89; 0xc3;              (* MOV (% ebx) (% eax) *)
  0xc1; 0xe0; 0x0a;        (* SHL (% eax) (Imm8 (word 10)) *)
  0xc1; 0xeb; 0x16;        (* SHR (% ebx) (Imm8 (word 22)) *)
  0x09; 0xd8;              (* OR (% eax) (% ebx) *)
  0x89; 0x44; 0x24; 0x70;  (* MOV (Memop Doubleword (%% (rsp,112))) (% eax) *)
  0x8b; 0x84; 0x24; 0xd4; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,212))) *)
  0x33; 0x47; 0x0c;        (* XOR (% eax) (Memop Doubleword (%% (rdi,12))) *)
  0x8b; 0x8c; 0x24; 0xe8; 0x00; 0x00; 0x00;
                           (* MOV (% ecx) (Memop Doubleword (%% (rsp,232))) *)
  0x33; 0x4f; 0x70;        (* XOR (% ecx) (Memop Doubleword (%% (rdi,112))) *)
  0x89; 0xc3;              (* MOV (% ebx) (% eax) *)
  0xc1; 0xe0; 0x0e;        (* SHL (% eax) (Imm8 (word 14)) *)
  0xc1; 0xeb; 0x12;        (* SHR (% ebx) (Imm8 (word 18)) *)
  0x09; 0xd8;              (* OR (% eax) (% ebx) *)
  0x89; 0x44; 0x24; 0x14;  (* MOV (Memop Doubleword (%% (rsp,20))) (% eax) *)
  0x89; 0xcb;              (* MOV (% ebx) (% ecx) *)
  0xc1; 0xe1; 0x0e;        (* SHL (% ecx) (Imm8 (word 14)) *)
  0xc1; 0xeb; 0x12;        (* SHR (% ebx) (Imm8 (word 18)) *)
  0x09; 0xd9;              (* OR (% ecx) (% ebx) *)
  0x89; 0x4c; 0x24; 0x78;  (* MOV (Memop Doubleword (%% (rsp,120))) (% ecx) *)
  0x8b; 0x84; 0x24; 0xc8; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,200))) *)
  0x33; 0x47; 0x14;        (* XOR (% eax) (Memop Doubleword (%% (rdi,20))) *)
  0x8b; 0x8c; 0x24; 0xdc; 0x00; 0x00; 0x00;
                           (* MOV (% ecx) (Memop Doubleword (%% (rsp,220))) *)
  0x33; 0x4f; 0x78;        (* XOR (% ecx) (Memop Doubleword (%% (rdi,120))) *)
  0x89; 0xc3;              (* MOV (% ebx) (% eax) *)
  0xc1; 0xe0; 0x12;        (* SHL (% eax) (Imm8 (word 18)) *)
  0xc1; 0xeb; 0x0e;        (* SHR (% ebx) (Imm8 (word 14)) *)
  0x09; 0xd8;              (* OR (% eax) (% ebx) *)
  0x89; 0x44; 0x24; 0x40;  (* MOV (Memop Doubleword (%% (rsp,64))) (% eax) *)
  0x89; 0xcb;              (* MOV (% ebx) (% ecx) *)
  0xc1; 0xe1; 0x12;        (* SHL (% ecx) (Imm8 (word 18)) *)
  0xc1; 0xeb; 0x0e;        (* SHR (% ebx) (Imm8 (word 14)) *)
  0x09; 0xd9;              (* OR (% ecx) (% ebx) *)
  0x89; 0x8c; 0x24; 0xa4; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,164))) (% ecx) *)
  0x8b; 0x84; 0x24; 0xcc; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,204))) *)
  0x33; 0x47; 0x40;        (* XOR (% eax) (Memop Doubleword (%% (rdi,64))) *)
  0x8b; 0x8c; 0x24; 0xe0; 0x00; 0x00; 0x00;
                           (* MOV (% ecx) (Memop Doubleword (%% (rsp,224))) *)
  0x33; 0x8f; 0xa4; 0x00; 0x00; 0x00;
                           (* XOR (% ecx) (Memop Doubleword (%% (rdi,164))) *)
  0x89; 0xcb;              (* MOV (% ebx) (% ecx) *)
  0xc1; 0xe1; 0x17;        (* SHL (% ecx) (Imm8 (word 23)) *)
  0xc1; 0xeb; 0x09;        (* SHR (% ebx) (Imm8 (word 9)) *)
  0x09; 0xd9;              (* OR (% ecx) (% ebx) *)
  0x89; 0x4c; 0x24; 0x20;  (* MOV (Memop Doubleword (%% (rsp,32))) (% ecx) *)
  0x89; 0xc3;              (* MOV (% ebx) (% eax) *)
  0xc1; 0xe0; 0x16;        (* SHL (% eax) (Imm8 (word 22)) *)
  0xc1; 0xeb; 0x0a;        (* SHR (% ebx) (Imm8 (word 10)) *)
  0x09; 0xd8;              (* OR (% eax) (% ebx) *)
  0x89; 0x84; 0x24; 0x84; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,132))) (% eax) *)
  0x8b; 0x84; 0x24; 0xd4; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,212))) *)
  0x33; 0x47; 0x20;        (* XOR (% eax) (Memop Doubleword (%% (rdi,32))) *)
  0x8b; 0x8c; 0x24; 0xe8; 0x00; 0x00; 0x00;
                           (* MOV (% ecx) (Memop Doubleword (%% (rsp,232))) *)
  0x33; 0x8f; 0x84; 0x00; 0x00; 0x00;
                           (* XOR (% ecx) (Memop Doubleword (%% (rdi,132))) *)
  0x89; 0xcb;              (* MOV (% ebx) (% ecx) *)
  0xc1; 0xe1; 0x1c;        (* SHL (% ecx) (Imm8 (word 28)) *)
  0xc1; 0xeb; 0x04;        (* SHR (% ebx) (Imm8 (word 4)) *)
  0x09; 0xd9;              (* OR (% ecx) (% ebx) *)
  0x89; 0x4c; 0x24; 0x54;  (* MOV (Memop Doubleword (%% (rsp,84))) (% ecx) *)
  0x89; 0xc3;              (* MOV (% ebx) (% eax) *)
  0xc1; 0xe0; 0x1b;        (* SHL (% eax) (Imm8 (word 27)) *)
  0xc1; 0xeb; 0x05;        (* SHR (% ebx) (Imm8 (word 5)) *)
  0x09; 0xd8;              (* OR (% eax) (% ebx) *)
  0x89; 0x84; 0x24; 0xb8; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,184))) (% eax) *)
  0x8b; 0x84; 0x24; 0xcc; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,204))) *)
  0x33; 0x47; 0x54;        (* XOR (% eax) (Memop Doubleword (%% (rdi,84))) *)
  0x8b; 0x8c; 0x24; 0xe0; 0x00; 0x00; 0x00;
                           (* MOV (% ecx) (Memop Doubleword (%% (rsp,224))) *)
  0x33; 0x8f; 0xb8; 0x00; 0x00; 0x00;
                           (* XOR (% ecx) (Memop Doubleword (%% (rdi,184))) *)
  0x89; 0xc3;              (* MOV (% ebx) (% eax) *)
  0xd1; 0xe0;              (* SHL (% eax) (Imm8 (word 1)) *)
  0xc1; 0xeb; 0x1f;        (* SHR (% ebx) (Imm8 (word 31)) *)
  0x09; 0xd8;              (* OR (% eax) (% ebx) *)
  0x89; 0x44; 0x24; 0x60;  (* MOV (Memop Doubleword (%% (rsp,96))) (% eax) *)
  0x89; 0xcb;              (* MOV (% ebx) (% ecx) *)
  0xd1; 0xe1;              (* SHL (% ecx) (Imm8 (word 1)) *)
  0xc1; 0xeb; 0x1f;        (* SHR (% ebx) (Imm8 (word 31)) *)
  0x09; 0xd9;              (* OR (% ecx) (% ebx) *)
  0x89; 0x8c; 0x24; 0xc4; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,196))) (% ecx) *)
  0x8b; 0x84; 0x24; 0xd8; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,216))) *)
  0x33; 0x47; 0x60;        (* XOR (% eax) (Memop Doubleword (%% (rdi,96))) *)
  0x8b; 0x8c; 0x24; 0xec; 0x00; 0x00; 0x00;
                           (* MOV (% ecx) (Memop Doubleword (%% (rsp,236))) *)
  0x33; 0x8f; 0xc4; 0x00; 0x00; 0x00;
                           (* XOR (% ecx) (Memop Doubleword (%% (rdi,196))) *)
  0x89; 0xc3;              (* MOV (% ebx) (% eax) *)
  0xc1; 0xe0; 0x07;        (* SHL (% eax) (Imm8 (word 7)) *)
  0xc1; 0xeb; 0x19;        (* SHR (% ebx) (Imm8 (word 25)) *)
  0x09; 0xd8;              (* OR (% eax) (% ebx) *)
  0x89; 0x44; 0x24; 0x10;  (* MOV (Memop Doubleword (%% (rsp,16))) (% eax) *)
  0x89; 0xcb;              (* MOV (% ebx) (% ecx) *)
  0xc1; 0xe1; 0x07;        (* SHL (% ecx) (Imm8 (word 7)) *)
  0xc1; 0xeb; 0x19;        (* SHR (% ebx) (Imm8 (word 25)) *)
  0x09; 0xd9;              (* OR (% ecx) (% ebx) *)
  0x89; 0x4c; 0x24; 0x74;  (* MOV (Memop Doubleword (%% (rsp,116))) (% ecx) *)
  0x8b; 0x84; 0x24; 0xd8; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,216))) *)
  0x33; 0x47; 0x10;        (* XOR (% eax) (Memop Doubleword (%% (rdi,16))) *)
  0x8b; 0x8c; 0x24; 0xec; 0x00; 0x00; 0x00;
                           (* MOV (% ecx) (Memop Doubleword (%% (rsp,236))) *)
  0x33; 0x4f; 0x74;        (* XOR (% ecx) (Memop Doubleword (%% (rdi,116))) *)
  0x89; 0xcb;              (* MOV (% ebx) (% ecx) *)
  0xc1; 0xe1; 0x0e;        (* SHL (% ecx) (Imm8 (word 14)) *)
  0xc1; 0xeb; 0x12;        (* SHR (% ebx) (Imm8 (word 18)) *)
  0x09; 0xd9;              (* OR (% ecx) (% ebx) *)
  0x89; 0x4c; 0x24; 0x3c;  (* MOV (Memop Doubleword (%% (rsp,60))) (% ecx) *)
  0x89; 0xc3;              (* MOV (% ebx) (% eax) *)
  0xc1; 0xe0; 0x0d;        (* SHL (% eax) (Imm8 (word 13)) *)
  0xc1; 0xeb; 0x13;        (* SHR (% ebx) (Imm8 (word 19)) *)
  0x09; 0xd8;              (* OR (% eax) (% ebx) *)
  0x89; 0x84; 0x24; 0xa0; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,160))) (% eax) *)
  0x8b; 0x84; 0x24; 0xc8; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,200))) *)
  0x33; 0x47; 0x3c;        (* XOR (% eax) (Memop Doubleword (%% (rdi,60))) *)
  0x8b; 0x8c; 0x24; 0xdc; 0x00; 0x00; 0x00;
                           (* MOV (% ecx) (Memop Doubleword (%% (rsp,220))) *)
  0x33; 0x8f; 0xa0; 0x00; 0x00; 0x00;
                           (* XOR (% ecx) (Memop Doubleword (%% (rdi,160))) *)
  0x89; 0xcb;              (* MOV (% ebx) (% ecx) *)
  0xc1; 0xe1; 0x15;        (* SHL (% ecx) (Imm8 (word 21)) *)
  0xc1; 0xeb; 0x0b;        (* SHR (% ebx) (Imm8 (word 11)) *)
  0x09; 0xd9;              (* OR (% ecx) (% ebx) *)
  0x89; 0x4c; 0x24; 0x5c;  (* MOV (Memop Doubleword (%% (rsp,92))) (% ecx) *)
  0x89; 0xc3;              (* MOV (% ebx) (% eax) *)
  0xc1; 0xe0; 0x14;        (* SHL (% eax) (Imm8 (word 20)) *)
  0xc1; 0xeb; 0x0c;        (* SHR (% ebx) (Imm8 (word 12)) *)
  0x09; 0xd8;              (* OR (% eax) (% ebx) *)
  0x89; 0x84; 0x24; 0xc0; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,192))) (% eax) *)
  0x8b; 0x84; 0x24; 0xd4; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,212))) *)
  0x33; 0x47; 0x5c;        (* XOR (% eax) (Memop Doubleword (%% (rdi,92))) *)
  0x8b; 0x8c; 0x24; 0xe8; 0x00; 0x00; 0x00;
                           (* MOV (% ecx) (Memop Doubleword (%% (rsp,232))) *)
  0x33; 0x8f; 0xc0; 0x00; 0x00; 0x00;
                           (* XOR (% ecx) (Memop Doubleword (%% (rdi,192))) *)
  0x89; 0xc3;              (* MOV (% ebx) (% eax) *)
  0xc1; 0xe0; 0x1c;        (* SHL (% eax) (Imm8 (word 28)) *)
  0xc1; 0xeb; 0x04;        (* SHR (% ebx) (Imm8 (word 4)) *)
  0x09; 0xd8;              (* OR (% eax) (% ebx) *)
  0x89; 0x44; 0x24; 0x4c;  (* MOV (Memop Doubleword (%% (rsp,76))) (% eax) *)
  0x89; 0xcb;              (* MOV (% ebx) (% ecx) *)
  0xc1; 0xe1; 0x1c;        (* SHL (% ecx) (Imm8 (word 28)) *)
  0xc1; 0xeb; 0x04;        (* SHR (% ebx) (Imm8 (word 4)) *)
  0x09; 0xd9;              (* OR (% ecx) (% ebx) *)
  0x89; 0x8c; 0x24; 0xb0; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,176))) (% ecx) *)
  0x8b; 0x84; 0x24; 0xd8; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,216))) *)
  0x33; 0x47; 0x4c;        (* XOR (% eax) (Memop Doubleword (%% (rdi,76))) *)
  0x8b; 0x8c; 0x24; 0xec; 0x00; 0x00; 0x00;
                           (* MOV (% ecx) (Memop Doubleword (%% (rsp,236))) *)
  0x33; 0x8f; 0xb0; 0x00; 0x00; 0x00;
                           (* XOR (% ecx) (Memop Doubleword (%% (rdi,176))) *)
  0x89; 0xc3;              (* MOV (% ebx) (% eax) *)
  0xc1; 0xe0; 0x04;        (* SHL (% eax) (Imm8 (word 4)) *)
  0xc1; 0xeb; 0x1c;        (* SHR (% ebx) (Imm8 (word 28)) *)
  0x09; 0xd8;              (* OR (% eax) (% ebx) *)
  0x89; 0x44; 0x24; 0x34;  (* MOV (Memop Doubleword (%% (rsp,52))) (% eax) *)
  0x89; 0xcb;              (* MOV (% ebx) (% ecx) *)
  0xc1; 0xe1; 0x04;        (* SHL (% ecx) (Imm8 (word 4)) *)
  0xc1; 0xeb; 0x1c;        (* SHR (% ebx) (Imm8 (word 28)) *)
  0x09; 0xd9;              (* OR (% ecx) (% ebx) *)
  0x89; 0x8c; 0x24; 0x98; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,152))) (% ecx) *)
  0x8b; 0x84; 0x24; 0xd4; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,212))) *)
  0x33; 0x47; 0x34;        (* XOR (% eax) (Memop Doubleword (%% (rdi,52))) *)
  0x8b; 0x8c; 0x24; 0xe8; 0x00; 0x00; 0x00;
                           (* MOV (% ecx) (Memop Doubleword (%% (rsp,232))) *)
  0x33; 0x8f; 0x98; 0x00; 0x00; 0x00;
                           (* XOR (% ecx) (Memop Doubleword (%% (rdi,152))) *)
  0x89; 0xcb;              (* MOV (% ebx) (% ecx) *)
  0xc1; 0xe1; 0x0d;        (* SHL (% ecx) (Imm8 (word 13)) *)
  0xc1; 0xeb; 0x13;        (* SHR (% ebx) (Imm8 (word 19)) *)
  0x09; 0xd9;              (* OR (% ecx) (% ebx) *)
  0x89; 0x4c; 0x24; 0x30;  (* MOV (Memop Doubleword (%% (rsp,48))) (% ecx) *)
  0x89; 0xc3;              (* MOV (% ebx) (% eax) *)
  0xc1; 0xe0; 0x0c;        (* SHL (% eax) (Imm8 (word 12)) *)
  0xc1; 0xeb; 0x14;        (* SHR (% ebx) (Imm8 (word 20)) *)
  0x09; 0xd8;              (* OR (% eax) (% ebx) *)
  0x89; 0x84; 0x24; 0x94; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,148))) (% eax) *)
  0x8b; 0x84; 0x24; 0xd0; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,208))) *)
  0x33; 0x47; 0x30;        (* XOR (% eax) (Memop Doubleword (%% (rdi,48))) *)
  0x8b; 0x8c; 0x24; 0xe4; 0x00; 0x00; 0x00;
                           (* MOV (% ecx) (Memop Doubleword (%% (rsp,228))) *)
  0x33; 0x8f; 0x94; 0x00; 0x00; 0x00;
                           (* XOR (% ecx) (Memop Doubleword (%% (rdi,148))) *)
  0x89; 0xcb;              (* MOV (% ebx) (% ecx) *)
  0xc1; 0xe1; 0x16;        (* SHL (% ecx) (Imm8 (word 22)) *)
  0xc1; 0xeb; 0x0a;        (* SHR (% ebx) (Imm8 (word 10)) *)
  0x09; 0xd9;              (* OR (% ecx) (% ebx) *)
  0x89; 0x4c; 0x24; 0x08;  (* MOV (Memop Doubleword (%% (rsp,8))) (% ecx) *)
  0x89; 0xc3;              (* MOV (% ebx) (% eax) *)
  0xc1; 0xe0; 0x15;        (* SHL (% eax) (Imm8 (word 21)) *)
  0xc1; 0xeb; 0x0b;        (* SHR (% ebx) (Imm8 (word 11)) *)
  0x09; 0xd8;              (* OR (% eax) (% ebx) *)
  0x89; 0x44; 0x24; 0x6c;  (* MOV (Memop Doubleword (%% (rsp,108))) (% eax) *)
  0x8b; 0x84; 0x24; 0xd0; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,208))) *)
  0x33; 0x47; 0x08;        (* XOR (% eax) (Memop Doubleword (%% (rdi,8))) *)
  0x8b; 0x8c; 0x24; 0xe4; 0x00; 0x00; 0x00;
                           (* MOV (% ecx) (Memop Doubleword (%% (rsp,228))) *)
  0x33; 0x4f; 0x6c;        (* XOR (% ecx) (Memop Doubleword (%% (rdi,108))) *)
  0x89; 0xc3;              (* MOV (% ebx) (% eax) *)
  0xc1; 0xe0; 0x1f;        (* SHL (% eax) (Imm8 (word 31)) *)
  0xd1; 0xeb;              (* SHR (% ebx) (Imm8 (word 1)) *)
  0x09; 0xd8;              (* OR (% eax) (% ebx) *)
  0x89; 0x44; 0x24; 0x50;  (* MOV (Memop Doubleword (%% (rsp,80))) (% eax) *)
  0x89; 0xcb;              (* MOV (% ebx) (% ecx) *)
  0xc1; 0xe1; 0x1f;        (* SHL (% ecx) (Imm8 (word 31)) *)
  0xd1; 0xeb;              (* SHR (% ebx) (Imm8 (word 1)) *)
  0x09; 0xd9;              (* OR (% ecx) (% ebx) *)
  0x89; 0x8c; 0x24; 0xb4; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,180))) (% ecx) *)
  0x8b; 0x84; 0x24; 0xc8; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,200))) *)
  0x33; 0x47; 0x50;        (* XOR (% eax) (Memop Doubleword (%% (rdi,80))) *)
  0x8b; 0x8c; 0x24; 0xdc; 0x00; 0x00; 0x00;
                           (* MOV (% ecx) (Memop Doubleword (%% (rsp,220))) *)
  0x33; 0x8f; 0xb4; 0x00; 0x00; 0x00;
                           (* XOR (% ecx) (Memop Doubleword (%% (rdi,180))) *)
  0x89; 0xc3;              (* MOV (% ebx) (% eax) *)
  0xc1; 0xe0; 0x09;        (* SHL (% eax) (Imm8 (word 9)) *)
  0xc1; 0xeb; 0x17;        (* SHR (% ebx) (Imm8 (word 23)) *)
  0x09; 0xd8;              (* OR (% eax) (% ebx) *)
  0x89; 0x44; 0x24; 0x38;  (* MOV (Memop Doubleword (%% (rsp,56))) (% eax) *)
  0x89; 0xcb;              (* MOV (% ebx) (% ecx) *)
  0xc1; 0xe1; 0x09;        (* SHL (% ecx) (Imm8 (word 9)) *)
  0xc1; 0xeb; 0x17;        (* SHR (% ebx) (Imm8 (word 23)) *)
  0x09; 0xd9;              (* OR (% ecx) (% ebx) *)
  0x89; 0x8c; 0x24; 0x9c; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,156))) (% ecx) *)
  0x8b; 0x84; 0x24; 0xd8; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,216))) *)
  0x33; 0x47; 0x38;        (* XOR (% eax) (Memop Doubleword (%% (rdi,56))) *)
  0x8b; 0x8c; 0x24; 0xec; 0x00; 0x00; 0x00;
                           (* MOV (% ecx) (Memop Doubleword (%% (rsp,236))) *)
  0x33; 0x8f; 0x9c; 0x00; 0x00; 0x00;
                           (* XOR (% ecx) (Memop Doubleword (%% (rdi,156))) *)
  0x89; 0xcb;              (* MOV (% ebx) (% ecx) *)
  0xc1; 0xe1; 0x14;        (* SHL (% ecx) (Imm8 (word 20)) *)
  0xc1; 0xeb; 0x0c;        (* SHR (% ebx) (Imm8 (word 12)) *)
  0x09; 0xd9;              (* OR (% ecx) (% ebx) *)
  0x89; 0x4c; 0x24; 0x58;  (* MOV (Memop Doubleword (%% (rsp,88))) (% ecx) *)
  0x89; 0xc3;              (* MOV (% ebx) (% eax) *)
  0xc1; 0xe0; 0x13;        (* SHL (% eax) (Imm8 (word 19)) *)
  0xc1; 0xeb; 0x0d;        (* SHR (% ebx) (Imm8 (word 13)) *)
  0x09; 0xd8;              (* OR (% eax) (% ebx) *)
  0x89; 0x84; 0x24; 0xbc; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,188))) (% eax) *)
  0x8b; 0x84; 0x24; 0xd0; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,208))) *)
  0x33; 0x47; 0x58;        (* XOR (% eax) (Memop Doubleword (%% (rdi,88))) *)
  0x8b; 0x8c; 0x24; 0xe4; 0x00; 0x00; 0x00;
                           (* MOV (% ecx) (Memop Doubleword (%% (rsp,228))) *)
  0x33; 0x8f; 0xbc; 0x00; 0x00; 0x00;
                           (* XOR (% ecx) (Memop Doubleword (%% (rdi,188))) *)
  0x89; 0xcb;              (* MOV (% ebx) (% ecx) *)
  0xc1; 0xe1; 0x1f;        (* SHL (% ecx) (Imm8 (word 31)) *)
  0xd1; 0xeb;              (* SHR (% ebx) (Imm8 (word 1)) *)
  0x09; 0xd9;              (* OR (% ecx) (% ebx) *)
  0x89; 0x4c; 0x24; 0x24;  (* MOV (Memop Doubleword (%% (rsp,36))) (% ecx) *)
  0x89; 0xc3;              (* MOV (% ebx) (% eax) *)
  0xc1; 0xe0; 0x1e;        (* SHL (% eax) (Imm8 (word 30)) *)
  0xc1; 0xeb; 0x02;        (* SHR (% ebx) (Imm8 (word 2)) *)
  0x09; 0xd8;              (* OR (% eax) (% ebx) *)
  0x89; 0x84; 0x24; 0x88; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rsp,136))) (% eax) *)
  0x8b; 0x84; 0x24; 0xd8; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,216))) *)
  0x33; 0x47; 0x24;        (* XOR (% eax) (Memop Doubleword (%% (rdi,36))) *)
  0x8b; 0x8c; 0x24; 0xec; 0x00; 0x00; 0x00;
                           (* MOV (% ecx) (Memop Doubleword (%% (rsp,236))) *)
  0x33; 0x8f; 0x88; 0x00; 0x00; 0x00;
                           (* XOR (% ecx) (Memop Doubleword (%% (rdi,136))) *)
  0x89; 0xc3;              (* MOV (% ebx) (% eax) *)
  0xc1; 0xe0; 0x0a;        (* SHL (% eax) (Imm8 (word 10)) *)
  0xc1; 0xeb; 0x16;        (* SHR (% ebx) (Imm8 (word 22)) *)
  0x09; 0xd8;              (* OR (% eax) (% ebx) *)
  0x89; 0x44; 0x24; 0x18;  (* MOV (Memop Doubleword (%% (rsp,24))) (% eax) *)
  0x89; 0xcb;              (* MOV (% ebx) (% ecx) *)
  0xc1; 0xe1; 0x0a;        (* SHL (% ecx) (Imm8 (word 10)) *)
  0xc1; 0xeb; 0x16;        (* SHR (% ebx) (Imm8 (word 22)) *)
  0x09; 0xd9;              (* OR (% ecx) (% ebx) *)
  0x89; 0x4c; 0x24; 0x7c;  (* MOV (Memop Doubleword (%% (rsp,124))) (% ecx) *)
  0x8b; 0x84; 0x24; 0xcc; 0x00; 0x00; 0x00;
                           (* MOV (% eax) (Memop Doubleword (%% (rsp,204))) *)
  0x33; 0x47; 0x18;        (* XOR (% eax) (Memop Doubleword (%% (rdi,24))) *)
  0x8b; 0x8c; 0x24; 0xe0; 0x00; 0x00; 0x00;
                           (* MOV (% ecx) (Memop Doubleword (%% (rsp,224))) *)
  0x33; 0x4f; 0x7c;        (* XOR (% ecx) (Memop Doubleword (%% (rdi,124))) *)
  0x89; 0xc3;              (* MOV (% ebx) (% eax) *)
  0xc1; 0xe0; 0x16;        (* SHL (% eax) (Imm8 (word 22)) *)
  0xc1; 0xeb; 0x0a;        (* SHR (% ebx) (Imm8 (word 10)) *)
  0x09; 0xd8;              (* OR (% eax) (% ebx) *)
  0x89; 0x44; 0x24; 0x04;  (* MOV (Memop Doubleword (%% (rsp,4))) (% eax) *)
  0x89; 0xcb;              (* MOV (% ebx) (% ecx) *)
  0xc1; 0xe1; 0x16;        (* SHL (% ecx) (Imm8 (word 22)) *)
  0xc1; 0xeb; 0x0a;        (* SHR (% ebx) (Imm8 (word 10)) *)
  0x09; 0xd9;              (* OR (% ecx) (% ebx) *)
  0x89; 0x4c; 0x24; 0x68;  (* MOV (Memop Doubleword (%% (rsp,104))) (% ecx) *)
  0x44; 0x8b; 0x04; 0x24;  (* MOV (% r8d) (Memop Doubleword (%% (rsp,0))) *)
  0x44; 0x8b; 0x6c; 0x24; 0x64;
                           (* MOV (% r13d) (Memop Doubleword (%% (rsp,100))) *)
  0x44; 0x8b; 0x4c; 0x24; 0x04;
                           (* MOV (% r9d) (Memop Doubleword (%% (rsp,4))) *)
  0x44; 0x8b; 0x74; 0x24; 0x68;
                           (* MOV (% r14d) (Memop Doubleword (%% (rsp,104))) *)
  0x44; 0x8b; 0x54; 0x24; 0x08;
                           (* MOV (% r10d) (Memop Doubleword (%% (rsp,8))) *)
  0x44; 0x8b; 0x7c; 0x24; 0x6c;
                           (* MOV (% r15d) (Memop Doubleword (%% (rsp,108))) *)
  0x44; 0x8b; 0x5c; 0x24; 0x0c;
                           (* MOV (% r11d) (Memop Doubleword (%% (rsp,12))) *)
  0x8b; 0x5c; 0x24; 0x70;  (* MOV (% ebx) (Memop Doubleword (%% (rsp,112))) *)
  0x44; 0x8b; 0x64; 0x24; 0x10;
                           (* MOV (% r12d) (Memop Doubleword (%% (rsp,16))) *)
  0x8b; 0x4c; 0x24; 0x74;  (* MOV (% ecx) (Memop Doubleword (%% (rsp,116))) *)
  0x44; 0x89; 0xc8;        (* MOV (% eax) (% r9d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xd0;        (* AND (% eax) (% r10d) *)
  0x44; 0x31; 0xc0;        (* XOR (% eax) (% r8d) *)
  0x89; 0x07;              (* MOV (Memop Doubleword (%% (rdi,0))) (% eax) *)
  0x44; 0x89; 0xf0;        (* MOV (% eax) (% r14d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xf8;        (* AND (% eax) (% r15d) *)
  0x44; 0x31; 0xe8;        (* XOR (% eax) (% r13d) *)
  0x89; 0x47; 0x64;        (* MOV (Memop Doubleword (%% (rdi,100))) (% eax) *)
  0x44; 0x89; 0xd0;        (* MOV (% eax) (% r10d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xd8;        (* AND (% eax) (% r11d) *)
  0x44; 0x31; 0xc8;        (* XOR (% eax) (% r9d) *)
  0x89; 0x47; 0x04;        (* MOV (Memop Doubleword (%% (rdi,4))) (% eax) *)
  0x44; 0x89; 0xf8;        (* MOV (% eax) (% r15d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x21; 0xd8;              (* AND (% eax) (% ebx) *)
  0x44; 0x31; 0xf0;        (* XOR (% eax) (% r14d) *)
  0x89; 0x47; 0x68;        (* MOV (Memop Doubleword (%% (rdi,104))) (% eax) *)
  0x44; 0x89; 0xd8;        (* MOV (% eax) (% r11d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xe0;        (* AND (% eax) (% r12d) *)
  0x44; 0x31; 0xd0;        (* XOR (% eax) (% r10d) *)
  0x89; 0x47; 0x08;        (* MOV (Memop Doubleword (%% (rdi,8))) (% eax) *)
  0x89; 0xd8;              (* MOV (% eax) (% ebx) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x21; 0xc8;              (* AND (% eax) (% ecx) *)
  0x44; 0x31; 0xf8;        (* XOR (% eax) (% r15d) *)
  0x89; 0x47; 0x6c;        (* MOV (Memop Doubleword (%% (rdi,108))) (% eax) *)
  0x44; 0x89; 0xe0;        (* MOV (% eax) (% r12d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xc0;        (* AND (% eax) (% r8d) *)
  0x44; 0x31; 0xd8;        (* XOR (% eax) (% r11d) *)
  0x89; 0x47; 0x0c;        (* MOV (Memop Doubleword (%% (rdi,12))) (% eax) *)
  0x89; 0xc8;              (* MOV (% eax) (% ecx) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xe8;        (* AND (% eax) (% r13d) *)
  0x31; 0xd8;              (* XOR (% eax) (% ebx) *)
  0x89; 0x47; 0x70;        (* MOV (Memop Doubleword (%% (rdi,112))) (% eax) *)
  0x44; 0x89; 0xc0;        (* MOV (% eax) (% r8d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xc8;        (* AND (% eax) (% r9d) *)
  0x44; 0x31; 0xe0;        (* XOR (% eax) (% r12d) *)
  0x89; 0x47; 0x10;        (* MOV (Memop Doubleword (%% (rdi,16))) (% eax) *)
  0x44; 0x89; 0xe8;        (* MOV (% eax) (% r13d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xf0;        (* AND (% eax) (% r14d) *)
  0x31; 0xc8;              (* XOR (% eax) (% ecx) *)
  0x89; 0x47; 0x74;        (* MOV (Memop Doubleword (%% (rdi,116))) (% eax) *)
  0x44; 0x8b; 0x44; 0x24; 0x14;
                           (* MOV (% r8d) (Memop Doubleword (%% (rsp,20))) *)
  0x44; 0x8b; 0x6c; 0x24; 0x78;
                           (* MOV (% r13d) (Memop Doubleword (%% (rsp,120))) *)
  0x44; 0x8b; 0x4c; 0x24; 0x18;
                           (* MOV (% r9d) (Memop Doubleword (%% (rsp,24))) *)
  0x44; 0x8b; 0x74; 0x24; 0x7c;
                           (* MOV (% r14d) (Memop Doubleword (%% (rsp,124))) *)
  0x44; 0x8b; 0x54; 0x24; 0x1c;
                           (* MOV (% r10d) (Memop Doubleword (%% (rsp,28))) *)
  0x44; 0x8b; 0xbc; 0x24; 0x80; 0x00; 0x00; 0x00;
                           (* MOV (% r15d) (Memop Doubleword (%% (rsp,128))) *)
  0x44; 0x8b; 0x5c; 0x24; 0x20;
                           (* MOV (% r11d) (Memop Doubleword (%% (rsp,32))) *)
  0x8b; 0x9c; 0x24; 0x84; 0x00; 0x00; 0x00;
                           (* MOV (% ebx) (Memop Doubleword (%% (rsp,132))) *)
  0x44; 0x8b; 0x64; 0x24; 0x24;
                           (* MOV (% r12d) (Memop Doubleword (%% (rsp,36))) *)
  0x8b; 0x8c; 0x24; 0x88; 0x00; 0x00; 0x00;
                           (* MOV (% ecx) (Memop Doubleword (%% (rsp,136))) *)
  0x44; 0x89; 0xc8;        (* MOV (% eax) (% r9d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xd0;        (* AND (% eax) (% r10d) *)
  0x44; 0x31; 0xc0;        (* XOR (% eax) (% r8d) *)
  0x89; 0x47; 0x14;        (* MOV (Memop Doubleword (%% (rdi,20))) (% eax) *)
  0x44; 0x89; 0xf0;        (* MOV (% eax) (% r14d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xf8;        (* AND (% eax) (% r15d) *)
  0x44; 0x31; 0xe8;        (* XOR (% eax) (% r13d) *)
  0x89; 0x47; 0x78;        (* MOV (Memop Doubleword (%% (rdi,120))) (% eax) *)
  0x44; 0x89; 0xd0;        (* MOV (% eax) (% r10d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xd8;        (* AND (% eax) (% r11d) *)
  0x44; 0x31; 0xc8;        (* XOR (% eax) (% r9d) *)
  0x89; 0x47; 0x18;        (* MOV (Memop Doubleword (%% (rdi,24))) (% eax) *)
  0x44; 0x89; 0xf8;        (* MOV (% eax) (% r15d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x21; 0xd8;              (* AND (% eax) (% ebx) *)
  0x44; 0x31; 0xf0;        (* XOR (% eax) (% r14d) *)
  0x89; 0x47; 0x7c;        (* MOV (Memop Doubleword (%% (rdi,124))) (% eax) *)
  0x44; 0x89; 0xd8;        (* MOV (% eax) (% r11d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xe0;        (* AND (% eax) (% r12d) *)
  0x44; 0x31; 0xd0;        (* XOR (% eax) (% r10d) *)
  0x89; 0x47; 0x1c;        (* MOV (Memop Doubleword (%% (rdi,28))) (% eax) *)
  0x89; 0xd8;              (* MOV (% eax) (% ebx) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x21; 0xc8;              (* AND (% eax) (% ecx) *)
  0x44; 0x31; 0xf8;        (* XOR (% eax) (% r15d) *)
  0x89; 0x87; 0x80; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rdi,128))) (% eax) *)
  0x44; 0x89; 0xe0;        (* MOV (% eax) (% r12d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xc0;        (* AND (% eax) (% r8d) *)
  0x44; 0x31; 0xd8;        (* XOR (% eax) (% r11d) *)
  0x89; 0x47; 0x20;        (* MOV (Memop Doubleword (%% (rdi,32))) (% eax) *)
  0x89; 0xc8;              (* MOV (% eax) (% ecx) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xe8;        (* AND (% eax) (% r13d) *)
  0x31; 0xd8;              (* XOR (% eax) (% ebx) *)
  0x89; 0x87; 0x84; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rdi,132))) (% eax) *)
  0x44; 0x89; 0xc0;        (* MOV (% eax) (% r8d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xc8;        (* AND (% eax) (% r9d) *)
  0x44; 0x31; 0xe0;        (* XOR (% eax) (% r12d) *)
  0x89; 0x47; 0x24;        (* MOV (Memop Doubleword (%% (rdi,36))) (% eax) *)
  0x44; 0x89; 0xe8;        (* MOV (% eax) (% r13d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xf0;        (* AND (% eax) (% r14d) *)
  0x31; 0xc8;              (* XOR (% eax) (% ecx) *)
  0x89; 0x87; 0x88; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rdi,136))) (% eax) *)
  0x44; 0x8b; 0x44; 0x24; 0x28;
                           (* MOV (% r8d) (Memop Doubleword (%% (rsp,40))) *)
  0x44; 0x8b; 0xac; 0x24; 0x8c; 0x00; 0x00; 0x00;
                           (* MOV (% r13d) (Memop Doubleword (%% (rsp,140))) *)
  0x44; 0x8b; 0x4c; 0x24; 0x2c;
                           (* MOV (% r9d) (Memop Doubleword (%% (rsp,44))) *)
  0x44; 0x8b; 0xb4; 0x24; 0x90; 0x00; 0x00; 0x00;
                           (* MOV (% r14d) (Memop Doubleword (%% (rsp,144))) *)
  0x44; 0x8b; 0x54; 0x24; 0x30;
                           (* MOV (% r10d) (Memop Doubleword (%% (rsp,48))) *)
  0x44; 0x8b; 0xbc; 0x24; 0x94; 0x00; 0x00; 0x00;
                           (* MOV (% r15d) (Memop Doubleword (%% (rsp,148))) *)
  0x44; 0x8b; 0x5c; 0x24; 0x34;
                           (* MOV (% r11d) (Memop Doubleword (%% (rsp,52))) *)
  0x8b; 0x9c; 0x24; 0x98; 0x00; 0x00; 0x00;
                           (* MOV (% ebx) (Memop Doubleword (%% (rsp,152))) *)
  0x44; 0x8b; 0x64; 0x24; 0x38;
                           (* MOV (% r12d) (Memop Doubleword (%% (rsp,56))) *)
  0x8b; 0x8c; 0x24; 0x9c; 0x00; 0x00; 0x00;
                           (* MOV (% ecx) (Memop Doubleword (%% (rsp,156))) *)
  0x44; 0x89; 0xc8;        (* MOV (% eax) (% r9d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xd0;        (* AND (% eax) (% r10d) *)
  0x44; 0x31; 0xc0;        (* XOR (% eax) (% r8d) *)
  0x89; 0x47; 0x28;        (* MOV (Memop Doubleword (%% (rdi,40))) (% eax) *)
  0x44; 0x89; 0xf0;        (* MOV (% eax) (% r14d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xf8;        (* AND (% eax) (% r15d) *)
  0x44; 0x31; 0xe8;        (* XOR (% eax) (% r13d) *)
  0x89; 0x87; 0x8c; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rdi,140))) (% eax) *)
  0x44; 0x89; 0xd0;        (* MOV (% eax) (% r10d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xd8;        (* AND (% eax) (% r11d) *)
  0x44; 0x31; 0xc8;        (* XOR (% eax) (% r9d) *)
  0x89; 0x47; 0x2c;        (* MOV (Memop Doubleword (%% (rdi,44))) (% eax) *)
  0x44; 0x89; 0xf8;        (* MOV (% eax) (% r15d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x21; 0xd8;              (* AND (% eax) (% ebx) *)
  0x44; 0x31; 0xf0;        (* XOR (% eax) (% r14d) *)
  0x89; 0x87; 0x90; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rdi,144))) (% eax) *)
  0x44; 0x89; 0xd8;        (* MOV (% eax) (% r11d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xe0;        (* AND (% eax) (% r12d) *)
  0x44; 0x31; 0xd0;        (* XOR (% eax) (% r10d) *)
  0x89; 0x47; 0x30;        (* MOV (Memop Doubleword (%% (rdi,48))) (% eax) *)
  0x89; 0xd8;              (* MOV (% eax) (% ebx) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x21; 0xc8;              (* AND (% eax) (% ecx) *)
  0x44; 0x31; 0xf8;        (* XOR (% eax) (% r15d) *)
  0x89; 0x87; 0x94; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rdi,148))) (% eax) *)
  0x44; 0x89; 0xe0;        (* MOV (% eax) (% r12d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xc0;        (* AND (% eax) (% r8d) *)
  0x44; 0x31; 0xd8;        (* XOR (% eax) (% r11d) *)
  0x89; 0x47; 0x34;        (* MOV (Memop Doubleword (%% (rdi,52))) (% eax) *)
  0x89; 0xc8;              (* MOV (% eax) (% ecx) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xe8;        (* AND (% eax) (% r13d) *)
  0x31; 0xd8;              (* XOR (% eax) (% ebx) *)
  0x89; 0x87; 0x98; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rdi,152))) (% eax) *)
  0x44; 0x89; 0xc0;        (* MOV (% eax) (% r8d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xc8;        (* AND (% eax) (% r9d) *)
  0x44; 0x31; 0xe0;        (* XOR (% eax) (% r12d) *)
  0x89; 0x47; 0x38;        (* MOV (Memop Doubleword (%% (rdi,56))) (% eax) *)
  0x44; 0x89; 0xe8;        (* MOV (% eax) (% r13d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xf0;        (* AND (% eax) (% r14d) *)
  0x31; 0xc8;              (* XOR (% eax) (% ecx) *)
  0x89; 0x87; 0x9c; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rdi,156))) (% eax) *)
  0x44; 0x8b; 0x44; 0x24; 0x3c;
                           (* MOV (% r8d) (Memop Doubleword (%% (rsp,60))) *)
  0x44; 0x8b; 0xac; 0x24; 0xa0; 0x00; 0x00; 0x00;
                           (* MOV (% r13d) (Memop Doubleword (%% (rsp,160))) *)
  0x44; 0x8b; 0x4c; 0x24; 0x40;
                           (* MOV (% r9d) (Memop Doubleword (%% (rsp,64))) *)
  0x44; 0x8b; 0xb4; 0x24; 0xa4; 0x00; 0x00; 0x00;
                           (* MOV (% r14d) (Memop Doubleword (%% (rsp,164))) *)
  0x44; 0x8b; 0x54; 0x24; 0x44;
                           (* MOV (% r10d) (Memop Doubleword (%% (rsp,68))) *)
  0x44; 0x8b; 0xbc; 0x24; 0xa8; 0x00; 0x00; 0x00;
                           (* MOV (% r15d) (Memop Doubleword (%% (rsp,168))) *)
  0x44; 0x8b; 0x5c; 0x24; 0x48;
                           (* MOV (% r11d) (Memop Doubleword (%% (rsp,72))) *)
  0x8b; 0x9c; 0x24; 0xac; 0x00; 0x00; 0x00;
                           (* MOV (% ebx) (Memop Doubleword (%% (rsp,172))) *)
  0x44; 0x8b; 0x64; 0x24; 0x4c;
                           (* MOV (% r12d) (Memop Doubleword (%% (rsp,76))) *)
  0x8b; 0x8c; 0x24; 0xb0; 0x00; 0x00; 0x00;
                           (* MOV (% ecx) (Memop Doubleword (%% (rsp,176))) *)
  0x44; 0x89; 0xc8;        (* MOV (% eax) (% r9d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xd0;        (* AND (% eax) (% r10d) *)
  0x44; 0x31; 0xc0;        (* XOR (% eax) (% r8d) *)
  0x89; 0x47; 0x3c;        (* MOV (Memop Doubleword (%% (rdi,60))) (% eax) *)
  0x44; 0x89; 0xf0;        (* MOV (% eax) (% r14d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xf8;        (* AND (% eax) (% r15d) *)
  0x44; 0x31; 0xe8;        (* XOR (% eax) (% r13d) *)
  0x89; 0x87; 0xa0; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rdi,160))) (% eax) *)
  0x44; 0x89; 0xd0;        (* MOV (% eax) (% r10d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xd8;        (* AND (% eax) (% r11d) *)
  0x44; 0x31; 0xc8;        (* XOR (% eax) (% r9d) *)
  0x89; 0x47; 0x40;        (* MOV (Memop Doubleword (%% (rdi,64))) (% eax) *)
  0x44; 0x89; 0xf8;        (* MOV (% eax) (% r15d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x21; 0xd8;              (* AND (% eax) (% ebx) *)
  0x44; 0x31; 0xf0;        (* XOR (% eax) (% r14d) *)
  0x89; 0x87; 0xa4; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rdi,164))) (% eax) *)
  0x44; 0x89; 0xd8;        (* MOV (% eax) (% r11d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xe0;        (* AND (% eax) (% r12d) *)
  0x44; 0x31; 0xd0;        (* XOR (% eax) (% r10d) *)
  0x89; 0x47; 0x44;        (* MOV (Memop Doubleword (%% (rdi,68))) (% eax) *)
  0x89; 0xd8;              (* MOV (% eax) (% ebx) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x21; 0xc8;              (* AND (% eax) (% ecx) *)
  0x44; 0x31; 0xf8;        (* XOR (% eax) (% r15d) *)
  0x89; 0x87; 0xa8; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rdi,168))) (% eax) *)
  0x44; 0x89; 0xe0;        (* MOV (% eax) (% r12d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xc0;        (* AND (% eax) (% r8d) *)
  0x44; 0x31; 0xd8;        (* XOR (% eax) (% r11d) *)
  0x89; 0x47; 0x48;        (* MOV (Memop Doubleword (%% (rdi,72))) (% eax) *)
  0x89; 0xc8;              (* MOV (% eax) (% ecx) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xe8;        (* AND (% eax) (% r13d) *)
  0x31; 0xd8;              (* XOR (% eax) (% ebx) *)
  0x89; 0x87; 0xac; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rdi,172))) (% eax) *)
  0x44; 0x89; 0xc0;        (* MOV (% eax) (% r8d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xc8;        (* AND (% eax) (% r9d) *)
  0x44; 0x31; 0xe0;        (* XOR (% eax) (% r12d) *)
  0x89; 0x47; 0x4c;        (* MOV (Memop Doubleword (%% (rdi,76))) (% eax) *)
  0x44; 0x89; 0xe8;        (* MOV (% eax) (% r13d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xf0;        (* AND (% eax) (% r14d) *)
  0x31; 0xc8;              (* XOR (% eax) (% ecx) *)
  0x89; 0x87; 0xb0; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rdi,176))) (% eax) *)
  0x44; 0x8b; 0x44; 0x24; 0x50;
                           (* MOV (% r8d) (Memop Doubleword (%% (rsp,80))) *)
  0x44; 0x8b; 0xac; 0x24; 0xb4; 0x00; 0x00; 0x00;
                           (* MOV (% r13d) (Memop Doubleword (%% (rsp,180))) *)
  0x44; 0x8b; 0x4c; 0x24; 0x54;
                           (* MOV (% r9d) (Memop Doubleword (%% (rsp,84))) *)
  0x44; 0x8b; 0xb4; 0x24; 0xb8; 0x00; 0x00; 0x00;
                           (* MOV (% r14d) (Memop Doubleword (%% (rsp,184))) *)
  0x44; 0x8b; 0x54; 0x24; 0x58;
                           (* MOV (% r10d) (Memop Doubleword (%% (rsp,88))) *)
  0x44; 0x8b; 0xbc; 0x24; 0xbc; 0x00; 0x00; 0x00;
                           (* MOV (% r15d) (Memop Doubleword (%% (rsp,188))) *)
  0x44; 0x8b; 0x5c; 0x24; 0x5c;
                           (* MOV (% r11d) (Memop Doubleword (%% (rsp,92))) *)
  0x8b; 0x9c; 0x24; 0xc0; 0x00; 0x00; 0x00;
                           (* MOV (% ebx) (Memop Doubleword (%% (rsp,192))) *)
  0x44; 0x8b; 0x64; 0x24; 0x60;
                           (* MOV (% r12d) (Memop Doubleword (%% (rsp,96))) *)
  0x8b; 0x8c; 0x24; 0xc4; 0x00; 0x00; 0x00;
                           (* MOV (% ecx) (Memop Doubleword (%% (rsp,196))) *)
  0x44; 0x89; 0xc8;        (* MOV (% eax) (% r9d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xd0;        (* AND (% eax) (% r10d) *)
  0x44; 0x31; 0xc0;        (* XOR (% eax) (% r8d) *)
  0x89; 0x47; 0x50;        (* MOV (Memop Doubleword (%% (rdi,80))) (% eax) *)
  0x44; 0x89; 0xf0;        (* MOV (% eax) (% r14d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xf8;        (* AND (% eax) (% r15d) *)
  0x44; 0x31; 0xe8;        (* XOR (% eax) (% r13d) *)
  0x89; 0x87; 0xb4; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rdi,180))) (% eax) *)
  0x44; 0x89; 0xd0;        (* MOV (% eax) (% r10d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xd8;        (* AND (% eax) (% r11d) *)
  0x44; 0x31; 0xc8;        (* XOR (% eax) (% r9d) *)
  0x89; 0x47; 0x54;        (* MOV (Memop Doubleword (%% (rdi,84))) (% eax) *)
  0x44; 0x89; 0xf8;        (* MOV (% eax) (% r15d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x21; 0xd8;              (* AND (% eax) (% ebx) *)
  0x44; 0x31; 0xf0;        (* XOR (% eax) (% r14d) *)
  0x89; 0x87; 0xb8; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rdi,184))) (% eax) *)
  0x44; 0x89; 0xd8;        (* MOV (% eax) (% r11d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xe0;        (* AND (% eax) (% r12d) *)
  0x44; 0x31; 0xd0;        (* XOR (% eax) (% r10d) *)
  0x89; 0x47; 0x58;        (* MOV (Memop Doubleword (%% (rdi,88))) (% eax) *)
  0x89; 0xd8;              (* MOV (% eax) (% ebx) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x21; 0xc8;              (* AND (% eax) (% ecx) *)
  0x44; 0x31; 0xf8;        (* XOR (% eax) (% r15d) *)
  0x89; 0x87; 0xbc; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rdi,188))) (% eax) *)
  0x44; 0x89; 0xe0;        (* MOV (% eax) (% r12d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xc0;        (* AND (% eax) (% r8d) *)
  0x44; 0x31; 0xd8;        (* XOR (% eax) (% r11d) *)
  0x89; 0x47; 0x5c;        (* MOV (Memop Doubleword (%% (rdi,92))) (% eax) *)
  0x89; 0xc8;              (* MOV (% eax) (% ecx) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xe8;        (* AND (% eax) (% r13d) *)
  0x31; 0xd8;              (* XOR (% eax) (% ebx) *)
  0x89; 0x87; 0xc0; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rdi,192))) (% eax) *)
  0x44; 0x89; 0xc0;        (* MOV (% eax) (% r8d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xc8;        (* AND (% eax) (% r9d) *)
  0x44; 0x31; 0xe0;        (* XOR (% eax) (% r12d) *)
  0x89; 0x47; 0x60;        (* MOV (Memop Doubleword (%% (rdi,96))) (% eax) *)
  0x44; 0x89; 0xe8;        (* MOV (% eax) (% r13d) *)
  0xf7; 0xd0;              (* NOT (% eax) *)
  0x44; 0x21; 0xf0;        (* AND (% eax) (% r14d) *)
  0x31; 0xc8;              (* XOR (% eax) (% ecx) *)
  0x89; 0x87; 0xc4; 0x00; 0x00; 0x00;
                           (* MOV (Memop Doubleword (%% (rdi,196))) (% eax) *)
  0x8b; 0x06;              (* MOV (% eax) (Memop Doubleword (%% (rsi,0))) *)
  0x31; 0x07;              (* XOR (Memop Doubleword (%% (rdi,0))) (% eax) *)
  0x8b; 0x46; 0x04;        (* MOV (% eax) (Memop Doubleword (%% (rsi,4))) *)
  0x31; 0x47; 0x64;        (* XOR (Memop Doubleword (%% (rdi,100))) (% eax) *)
  0x48; 0x83; 0xc6; 0x08;  (* ADD (% rsi) (Imm8 (word 8)) *)
  0x48; 0x39; 0xd6;        (* CMP (% rsi) (% rdx) *)
  0x0f; 0x85; 0x60; 0xf4; 0xff; 0xff;
                           (* JNE (Imm32 (word 4294964320)) *)
  0x48; 0x89; 0xec;        (* MOV (% rsp) (% rbp) *)
  0x5b;                    (* POP (% rbx) *)
  0x5d;                    (* POP (% rbp) *)
  0xc3                     (* RET *)
];;
