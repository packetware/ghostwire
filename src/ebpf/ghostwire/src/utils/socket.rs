use crate::utils::state::State;
use ghostwire_types::{
    ClientMessage,
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

impl State {
    /// Listen on the socket for client requests from the CLI
    pub async fn listen(&self) -> anyhow::Result<()> {
        // delete a socket that could exist currently
        let _ = std::fs::remove_file("/tmp/ghostwire.sock");

        let listener = UnixListener::bind("/tmp/ghostwire.sock").expect("Failed to bind socket");

        self.handle_listener(listener)
            .expect("Failed to handle listener");
    }

    /// Run the listener and handle new messages
    fn handle_listener(&self, listener: UnixListener) -> anyhow::Result<()> {
        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    let mut buffer = [0; 1024];
                    match stream.read(&mut buffer) {
                        Ok(size) => {
                            let received_data = &buffer[..size];
                            match serde_json::from_slice::<ClientMessage>(received_data) {
                                Ok(message) => {
                                    self.handle_server_request(message, stream)?;
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
                }
                Err(err) => {
                    anyhow::bail!("failed to accept connection: {}", err);
                }
            }
        }

        Ok(())
    }

    /// Once parsed to a ClientMessage, handle the request
    fn handle_server_request(
        &self,
        message: ClientMessage,
        mut stream: UnixStream,
    ) -> anyhow::Result<()> {
        println!("Received: {:?}", message);

        // print the output
        let successful_response = ServerMessage {
            request_success: true,
            message: None,
        };

        // serialize and send over the stream
        let response_data = serde_json::to_vec(&successful_response)?;
        stream.write_all(&response_data)?;

        Ok(())
    }
}
