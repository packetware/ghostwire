#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{
        xdp_action,
        TC_ACT_SHOT,
    },
    macros::{
        classifier,
        map,
        xdp,
    },
    maps::{
        HashMap,
        LruHashMap,
    },
    programs::{
        TcContext,
        XdpContext,
    },
};
use ghostwire_common::{
    Rule,
    RuleAnalytics,
};

mod handlers;
mod utils;

use crate::handlers::{
    egress::ghostwire_egress_fallible,
    ingress::ghostwire_ingress_fallible,
};

#[map]
/// The map which holds the firewall rules. Key is the index.
pub static RULES: HashMap<u32, Rule> = HashMap::<u32, Rule>::with_max_entries(100, 0);

#[map]
/// The map which holds the ratelimiting metrics for ratelimiting-based rules. Key is a combination
/// of IP address and rule ID.
pub static RATELIMITING: LruHashMap<u64, u128> =
    LruHashMap::<u64, u128>::with_max_entries(1_000_000, 0);

#[map]
/// The map which holds the analytics for each firewall rule. Key is the rule ID.
pub static RULE_ANALYTICS: HashMap<u32, RuleAnalytics> =
    HashMap::<u32, RuleAnalytics>::with_max_entries(1024, 0);

#[map]
/// The holepunched connections (leaving the server). Key is source IP + source port + destination
/// IP + destination port. Value is the time the last time there was traffic over this connection.
pub static HOLEPUNCHED: LruHashMap<u64, u64> =
    LruHashMap::<u64, u64>::with_max_entries(1_000_000, 0);

#[map]
/// Whenever an action is completed IN XDP, like DROP, PASS, or ABORT, report that in this map. Designed
/// to be an overall statistic
pub static XDP_ACTION_ANALYTICS: HashMap<u32, u128> =
    HashMap::<u32, u128>::with_max_entries(100, 0);

#[map]
/// Whenever an action is completed, like TC_ACT_SHOT or TC_ACT_PIPE report that in this map. Designed
/// to be an overall statistic
pub static TC_ACTION_ANALYTICS: HashMap<i32, u128> = HashMap::<i32, u128>::with_max_entries(100, 0);

#[xdp]
/// The infallible XDP hook for all incoming traffic.
pub fn ghostwire_xdp(ctx: XdpContext) -> u32 {
    unsafe {
        let result = match ghostwire_ingress_fallible(ctx) {
            Ok(ret) => ret,
            Err(_) => xdp_action::XDP_ABORTED,
        };

        // increment the analytics
        match XDP_ACTION_ANALYTICS.get_ptr_mut(&result) {
            Some(val) => *val += 1,
            None => {
                let _ = XDP_ACTION_ANALYTICS.insert(&result, &1, 0);
            }
        }

        result
    }
}

#[classifier]
/// The infallible TC hook for all outgoing traffic.
pub fn ghostwire_tc(tc: TcContext) -> i32 {
    unsafe {
        let result = match ghostwire_egress_fallible(tc) {
            Ok(ret) => ret,
            Err(_) => TC_ACT_SHOT,
        };

        // increment the analytics
        match TC_ACTION_ANALYTICS.get_ptr_mut(&result) {
            Some(val) => *val += 1,
            None => {
                let _ = TC_ACTION_ANALYTICS.insert(&result, &1, 0);
            }
        }

        result
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
