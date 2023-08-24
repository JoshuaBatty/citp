extern crate citp;
use citp::protocol::{WriteToBytes, SizeBytes, ReadFromBytes};
use citp::protocol::{pinf, caex, sdmx};
use std::net::UdpSocket;
use std::net::Ipv4Addr;
use std::ffi::CString;
use std::net::TcpStream;
use std::io::prelude::*;

pub const CITP_HEADER_LEN: usize = 55;
pub const CONTENT_TYPE_LEN: usize = 4;

#[derive(Debug)]
enum State {
    Init,
    Connect,
    Request,
    Stream,
}

fn main() {    
    let mut state = State::Init;

    let multicast_port = format!("{}",citp::protocol::pinf::MULTICAST_PORT);
    let socket = UdpSocket::bind(format!("0.0.0.0:{}",multicast_port)).expect("Cant bind to UDP Socket!");
    let mut buf = [0u8; 65535];
    let addr = citp::protocol::pinf::OLD_MULTICAST_ADDR;
    let multi_addr = Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
    let inter = Ipv4Addr::new(0,0,0,0);

    let mut tcp_stream: Option<TcpStream> = None;

    loop {
        println!("state = {:?}", state);

        match state {
            State::Init => {
                match socket.join_multicast_v4(&multi_addr,&inter) {
                    Ok(_) => {
                        println!("UDP Multicast Joined!");
                        state = State::Connect;
                    },
                    Err(err) => eprint!("join_multicast_v4 {:?}", err),
                }
            }
            State::Connect => {
                match socket.recv_from(&mut buf) {
                    Ok((len, remote_addr)) => {
                        // - Read the full base **Header** first.
                        let data = &buf[..len];
                        let header = citp::protocol::Header::read_from_bytes(data).unwrap();
                        let header_size = header.size_bytes();
                        
                        match &header.content_type.to_le_bytes() {
                            pinf::Header::CONTENT_TYPE => {
                                if let pinf::PLoc::CONTENT_TYPE = &layer_two_content_type(&data, header_size).to_le_bytes() {
                                    println!("PINF PLoc");
    
                                    let ploc = citp::protocol::pinf::PLoc::read_from_bytes(&data[header_size+CONTENT_TYPE_LEN..]).unwrap();
                                    println!("ploc = {:#?}", ploc);
    
                                    let name = ploc.name.to_str().unwrap().to_owned();
                                    let tcp_addr = format!("{}:{}", extract_ip_address(&name), ploc.listening_tcp_port);
                                    println!("ip_address = {}", tcp_addr);
    
                                    //Use the remote_addr to connect to the socket
                                    // only if it isn't already connected
                                    match socket.connect(remote_addr) {
                                        Ok(_) => (),
                                        Err(err) => eprint!("couldn't connect to TCP socket addr {:?}", err),
                                    }
    
                                    let mut stream = TcpStream::connect(tcp_addr).expect("Could not connect to server");
                                    let message = connect_to_capture();
                                    message.write_to_bytes(&mut stream).expect("Failed to write to server");
                                    tcp_stream = Some(stream);
                                    println!("WE MADE A SUCCESFUL TCP CONNECTION!");
    
                                    state = State::Request;
                                }
                            }
                            _ => println!("Unrecognized UDP Header Content Type"),
                        }
                    }
                    Err(err) => {
                        println!("client: had a problem: {}", err);
                    }
                }
            }
            State::Request => {
                //- Regularly send a CITP/PINF/PLoc message with no listening port.
    
                // Return the number of bytes writte so we can take the correct amount of bytes from the slice
                let ploc = send_peer_loction();
                let mut ploc_buf = [0u8; 65535];
                match ploc.write_to_bytes(&mut ploc_buf[..]) {
                    Ok(_) => {
                        socket.send(&ploc_buf[..ploc.pinf_header.citp_header.message_size as usize]).expect("Can't send buffer over UDP Socket");
                    },
                    Err(_) => {
                        eprintln!("error writing ploc to bytes");
                    }
                }

                let mut caex_buf = [0u8; 65535];
                // Return the number of bytes writte so we can take the correct amount of bytes from the slice
                let feed_list = send_laser_feed_list();
                match feed_list.write_to_bytes(&mut caex_buf[..]) {
                    Ok (_) => {
                        socket.send(&caex_buf[..feed_list.caex_header.citp_header.message_size as usize]).expect("Can't send buffer over UDP Socket");
                    }
                    Err(_) => {
                        eprintln!("error writing feed list to bytes");
                    }
                }


                
                if let Some(ref mut stream) = tcp_stream {
                    let mut tcp_buf = [0u8; 65535];
                    // Read not peek

                    let stream_length = stream.read(&mut tcp_buf).expect("read tcp stream failed");
                    println!("len = {}", stream_length);
                    println!("Request: {}", String::from_utf8_lossy(&tcp_buf[..]));

                    //let len = stream.peek(&mut tcp_buf).expect("peek failed");
                    let header = citp::protocol::Header::read_from_bytes(&tcp_buf[..stream_length]).unwrap();
                    let header_size = header.size_bytes();
                    println!("header size = {}", header_size);


                    //
                    

                    match &header.content_type.to_le_bytes() {
                        pinf::Header::CONTENT_TYPE => {
                            // - Read the header for the second layer.
                            // - Match on the `content_type` field of the second layer to determine what type to read.                        
                            if let pinf::PNam::CONTENT_TYPE = &layer_two_content_type(&tcp_buf, header_size).to_le_bytes() {
                                let pnam = citp::protocol::pinf::PNam::read_from_bytes(&tcp_buf[header_size+CONTENT_TYPE_LEN..]).unwrap();
                                println!("pnam = {:#?}", pnam);
                            }
                        }
                        _ => println!("Un recognized TCP Header Content Type"),
                    }

                    match &header.content_type {
                        &caex::GetLaserFeedList::CONTENT_TYPE => {
                            println!("CAEX GET LASER FEED LIST");
                        }
                        0x00020100 => {
                            println!("enter show");
                        }
                        _ => ()
                    }

                }


                match socket.recv_from(&mut buf) {
                    Ok((len, remote_addr)) => {
                        // - Read the full base **Header** first.
                        let data = &buf[..len];
                        let header = citp::protocol::Header::read_from_bytes(data).unwrap();
                        let header_size = header.size_bytes();
                        
                        match &header.content_type.to_le_bytes() {
                            _ => println!("Unrecognized UDP Header Content Type {}", header.content_type),
                        }
                    }
                    Err(err) => {
                        println!("client: had a problem: {}", err);
                    }
                }
            }
            State::Stream => {
                
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(16));   
    }
}

fn extract_ip_address(s: &String) -> String {
    let start_bytes = s.find("(").unwrap_or(0) + 1; 
    let end_bytes = s.find(")").unwrap_or(s.len());
    s[start_bytes..end_bytes].to_string()
}

fn layer_two_content_type(data: &[u8], header_size: usize) -> u32 {
    let slice = &data[header_size..header_size+CONTENT_TYPE_LEN];
    u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]])
}

fn pinf_header(pinf_message_size: usize) -> pinf::Header {
    pinf::Header {
        citp_header: citp::protocol::Header {
            cookie: u32::from_le_bytes(*b"CITP"),
            version_major: 1,
            version_minor: 0,
            kind: citp::protocol::Kind {
                request_index: 0,
            },
            message_size: (CITP_HEADER_LEN + CONTENT_TYPE_LEN + pinf_message_size) as u32,
            message_part_count: 1,
            message_part: 0,
            content_type: u32::from_le_bytes(*pinf::Header::CONTENT_TYPE),
        },
        content_type: u32::from_le_bytes(*pinf::PNam::CONTENT_TYPE),
    }
}

fn send_peer_loction()-> pinf::Message::<pinf::PLoc> {
    let ploc = pinf::PLoc {
        listening_tcp_port: 0,
        kind: CString::new("LightingConsole").expect("CString::new failed"),
        name: CString::new("Rusty Previz Tool").expect("CString::new failed"),
        state: CString::new("Firing ze lasers").expect("CString::new failed"),
    };

    pinf::Message {
        pinf_header: pinf_header(ploc.size_bytes()),
        message: ploc,
    }
}

fn caex_laser_header(caex_message_size: usize) -> caex::Header {
    caex::Header {
        citp_header: citp::protocol::Header {
            cookie: u32::from_le_bytes(*b"CAEX"),
            version_major: 1,
            version_minor: 0,
            kind: citp::protocol::Kind {
                request_index: 0,
            },
            message_size: (CITP_HEADER_LEN + CONTENT_TYPE_LEN + caex_message_size) as u32,
            message_part_count: 1,
            message_part: 0,
            content_type: u32::from_le_bytes(*b"CAEX"),
        },
        content_type: caex::LaserFeedList::CONTENT_TYPE
    }
}

fn send_laser_feed_list<'a>() -> caex::Message::<caex::LaserFeedList<'a>> {
    let feed_list = caex::LaserFeedList {
        source_key: 1,
        feed_count: 0,
        feed_names: std::borrow::Cow::from(Vec::new())
    };
    caex::Message {
        caex_header: caex_laser_header(feed_list.size_bytes()),
        message: feed_list
    }
}



fn connect_to_capture() -> pinf::Message::<pinf::PNam> {
    let pnam = pinf::PNam {
        name: CString::new("Rusty Previz Tool").expect("CString::new failed")
    };

    pinf::Message {
        pinf_header: pinf_header(pnam.size_bytes()),
        message: pnam,
    }
}
