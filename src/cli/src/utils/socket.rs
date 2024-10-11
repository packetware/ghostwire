use ghostwire_types::{ClientMessage, ServerMessage};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

/// Send a message to the firewall, erroring if unsuccessful
pub fn send_message(client_message: ClientMessage) -> anyhow::Result<String> {
    // Connect to the socket.
    let mut stream = UnixStream::connect("/tmp/ghostwire.sock")?;

    // Serialize the client message.
    let serialized = serde_json::to_string(&client_message)?;

    // Send the message over the wire.
    stream.write_all(serialized.as_bytes())?;

    let mut buffer = [0; 1024];

    // Read the response.
    let bytes_read = stream.read(&mut buffer)?;

    let response = std::str::from_utf8(&buffer[..bytes_read])?;

    // Deserialize the response.
    let server_response: ServerMessage = serde_json::from_str(response)?;

    if server_response.request_success {
        Ok(server_response.message)
    } else {
        anyhow::bail!(
            "The server responded with an error: {}",
            server_response.message
        )
    }
}
