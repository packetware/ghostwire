#![no_std]

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FiveTuple {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub protocol: u8,
    pub padding: [u8; 3], // 3 bytes (to align to 4-byte boundary)
    pub src_port: u16,
    pub dst_port: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Flow {
    pub start_time: u64,
    pub end_time: u64,
    pub bytes: u64,
    pub packets: u64,
    pub action: u32,
    pub reason: u32,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Punch {
    pub action: u8,  // 1 for allow, 0 for block
    pub padding: [u8; 7], // 7 bytes (to align to 8-byte boundary)
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Connection {
    pub expires: u64,   // expiration timestamp
}


#[cfg(feature = "user")]
unsafe impl aya::Pod for FiveTuple {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for Flow {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for Punch {}