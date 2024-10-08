use ghostwire_types::{ClientMessage, ServerMessage};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

/// Send a message to the firewall, erroring if unsuccessful
pub fn send_message(client_message: ClientMessage) -> anyhow::Result<()> {
    // create the stream
    let mut stream = UnixStream::connect("/tmp/ghostwire.sock")?;

    // serialize the client message
    let serialized = serde_json::to_string(&client_message)?;

    // send the message over the wire
    stream.write_all(serialized.as_bytes())?;

    // wait for the server to ACK
    let mut buffer = [0; 1024];

    // read the response
    let bytes_read = stream.read(&mut buffer)?;

    // convert the response to a string
    let response = std::str::from_utf8(&buffer[..bytes_read])?;

    // deserialize the response
    let server_message: ServerMessage = serde_json::from_str(response)?;

    // if successful, return Ok
    if server_message.request_success {
        Ok(())
    } else {
        anyhow::bail!(
            "The server responded with an error: {}",
            server_message
                .message
                .unwrap_or("No message provided".to_string())
        )
    }
}
