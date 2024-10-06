use aya_ebpf::programs::{
    TcContext,
    XdpContext,
};

/// Get the pointer from an index to the end the desired type length for an XDP packet. This will help us break up the packet into the different
/// headers and payloads.
pub fn xdp_ptr_at_fallible<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    // get the reference at the beginning of the packet
    let start = ctx.data();
    // get the length of the packet
    let end = ctx.data_end();
    // the length of the desired type
    let length = core::mem::size_of::<T>();

    // make sure we don't exceed the bounds of the packet
    if start + offset + length > end {
        return Err(());
    }

    // return the reference to the data, parsing the bytes as the desired type
    Ok((start + offset) as *const T)
}

/// Get the pointer from an index to the end the desired type length for a traffic control packet. This will help us break up the packet into the different
/// headers and payloads.
pub fn tc_ptr_at_fallible<T>(ctx: &TcContext, offset: usize) -> Result<*const T, ()> {
    // get the reference at the beginning of the packet
    let start = ctx.data();
    // get the length of the packet
    let end = ctx.data_end();
    // the length of the desired type
    let length = core::mem::size_of::<T>();

    // make sure we don't exceed the bounds of the packet
    if start + offset + length > end {
        return Err(());
    }

    // return the reference to the data, parsing the bytes as the desired type
    Ok((start + offset) as *const T)
}
