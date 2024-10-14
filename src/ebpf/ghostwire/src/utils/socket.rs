use super::ebpf::{
    load_ebpf,
    unload_ebpf,
};
use crate::OVERALL_STATE;
use ghostwire_common::{
    RuleKey,
    RuleValue,
};
use ghostwire_types::{
    ClientMessage,
    ClientReqType,
    Rule,
    ServerMessage,
};
use std::{
    io::{
        Read,
        Write,
    },
    os::unix::net::{
        UnixListener,
        UnixStream,
    },
};
use aya::maps::lpm_trie::{LpmTrie, Key};
use aya::Pod;
use aya::maps::MapData;
use std::borrow::Borrow;

/// Listen on the socket for client requests from the CLI
pub async fn socket_server() -> anyhow::Result<()> {
    // delete a socket that could exist currently
    let _ = std::fs::remove_file("/tmp/ghostwire.sock");

    let listener = UnixListener::bind("/tmp/ghostwire.sock").expect("Failed to bind socket");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(e) = handle_stream(stream).await {
                    tracing::error!("Failed to handle stream: {:?}", e);
                };
            }
            Err(err) => {
                tracing::error!("Failed to accept connection: {:?}", err);
            }
        }
    }

    Ok(())
}

/// Run the listener and handle new messages
async fn handle_stream(mut stream: UnixStream) -> anyhow::Result<()> {
    let mut buffer = [0; 1024];

    match stream.read(&mut buffer) {
        Ok(size) => {
            let received_data = &buffer[..size];
            match serde_json::from_slice::<ClientMessage>(received_data) {
                Ok(message) => {
                    handle_server_request(message, stream).await?;
                }
                Err(err) => {
                    anyhow::bail!("Failed to parse JSON: {}", err);
                }
            }
        }
        Err(err) => {
            anyhow::bail!("Failed to read from socket: {}", err);
        }
    }

    Ok(())
}

/// Handle a message from the socket client.
async fn handle_server_request(
    message: ClientMessage,
    mut stream: UnixStream,
) -> anyhow::Result<()> {
    let resp = match handle_server_request_fallible(message).await {
        Ok(t) => t,
        Err(e) => ServerMessage {
            request_success: false,
            message: format!("{}", e),
        },
    };

    let response_data = serde_json::to_vec(&resp)?;
    stream.write_all(&response_data)?;

    Ok(())
}

/// Once parsed to a ClientMessage, handle the request
async fn handle_server_request_fallible(message: ClientMessage) -> anyhow::Result<ServerMessage> {
    match message.req_type {
        ClientReqType::STATUS => handle_status_request().await,
        ClientReqType::RULES => {
            handle_load(
                message.rules.ok_or(anyhow::anyhow!(
                    "request to change rules didn't include rules"
                ))?,
                message.interface.ok_or(anyhow::anyhow!(
                    "request to change rules didn't include the interface"
                ))?,
            )
            .await
        }
        ClientReqType::ENABLE => {
            handle_enable(message.interface.ok_or(anyhow::anyhow!(
                "enable message didn't include the interface"
            ))?)
            .await
        }
        ClientReqType::DISABLE => handle_disable().await,
    }
}

/// Handle a status request from the client
async fn handle_status_request() -> anyhow::Result<ServerMessage> {
    let overall_status = OVERALL_STATE.read().await;

    Ok(ServerMessage {
        request_success: true,
        message: overall_status.fmt().await,
    })
}

/// Handle the modification of rules. The client will send the full list of rules, to which we will
/// replace the map.
async fn handle_load(rules: Vec<Rule>, interface: String) -> anyhow::Result<ServerMessage> {
    // Find if the firewall is enabled.
    let enabled;

    {
        enabled = OVERALL_STATE.read().await.enabled;
    }

    if !enabled {
        handle_enable(interface).await?;
    }

    let overall_status = OVERALL_STATE.read().await;

    match &overall_status.state {
        Some(state) => {
            let mut map = state.rule_map.write().await;

            let keys = collect_lpm_trie_keys(&map)?; 

            // Currently, a rule update is a full replacement.
            for key in keys.iter() {
                map.remove(key)?;
            }

            // Insert the new rules.
            for (i, rule) in rules.iter().enumerate() {
                let (key, value) = convert_rule(*rule, i as u32);
                map.insert(&key, value, 0)?;
            }

            Ok(ServerMessage {
                request_success: true,
                message: "Rules updated".to_string(),
            })
        }
        None => {
            anyhow::bail!("Firewall is not enabled");
        }
    }
}

/// Handle the enabling of the firewall.
async fn handle_enable(interface: String) -> anyhow::Result<ServerMessage> {
    {
        let overall_status = OVERALL_STATE.read().await;

        if overall_status.enabled || overall_status.state.is_some() {
            anyhow::bail!("Firewall is already enabled");
        }
    }

    load_ebpf(vec![], interface).await?;

    {
        let mut overall_status = OVERALL_STATE.write().await;

        overall_status.enabled = true;
    }

    Ok(ServerMessage {
        request_success: true,
        message: "Firewall enabled".to_string(),
    })
}

/// Handle the disabling of the firewall.
async fn handle_disable() -> anyhow::Result<ServerMessage> {
    {
        let overall_status = OVERALL_STATE.read().await;

        if !overall_status.enabled || overall_status.state.is_none() {
            anyhow::bail!("Firewall is already disabled");
        }
    }

    unload_ebpf().await;

    {
        let mut overall_status = OVERALL_STATE.write().await;

        overall_status.enabled = false;
    }

    Ok(ServerMessage {
        request_success: true,
        message: "Firewall disabled".to_string(),
    })
}

/// Convert a rule from the common format to
fn convert_rule(rule: Rule, id: u32) -> (Key<RuleKey>, RuleValue) {
    (
        Key::new(
            rule.prefix_length,
            RuleKey {
                source_ip_range: rule.source_ip_range,
                destination_ip_range: rule.destination_ip_range,
                protocol: rule.protocol_number,
                port_number: rule.port_number,
            },
        ),
        RuleValue {
            id,
            ratelimit: rule.ratelimit.unwrap_or(0),
        }
    )
}

/// Collect all keys from an LpmTrie
fn collect_lpm_trie_keys<T, K, V>(trie: &LpmTrie<T, K, V>) -> anyhow::Result<Vec<Key<K>>>
where
    K: Clone + Pod,
    T: Borrow<MapData>,
    V: Pod,
{
    let mut collected_keys = Vec::new();

    for key_result in trie.keys() {
        match key_result {
            Ok(key) => collected_keys.push(key.clone()),            
            Err(e) => return Err(e.into()),        
        }
    }

    Ok(collected_keys) // Return collected keys if no error occurs
}
