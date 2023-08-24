extern crate citp;

use citp::protocol::{WriteToBytes, SizeBytes, ReadFromBytes};
use citp::protocol::{pinf, caex, sdmx};
use std::net::UdpSocket;
use std::net::Ipv4Addr;
use std::ffi::CString;
use std::net::TcpStream;
use std::io::{self, Write};

mod citp_tcp;
use citp_tcp::CitpTcp;

pub const CITP_HEADER_LEN: usize = 20;
pub const CONTENT_TYPE_LEN: usize = 4;

pub const NUM_LASERS: i32 = 1;

#[derive(Debug)]
enum State {
    Init,
    Connect,
    Request,
    Stream,
}

fn main() -> io::Result<()> {    
    let mut state = State::Init;

    let multicast_port = format!("{}",citp::protocol::pinf::MULTICAST_PORT);
    let socket = UdpSocket::bind(format!("0.0.0.0:{}",multicast_port)).expect("Cant bind to UDP Socket!");
    let mut buf = [0u8; 65535];
    let addr = citp::protocol::pinf::OLD_MULTICAST_ADDR;
    let multi_addr = Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
    let inter = Ipv4Addr::new(0,0,0,0);

    let mut citp_tcp_stream: Option<CitpTcp> = None;

    let header_size = std::mem::size_of::<citp::protocol::Header>();
    println!("HEADER SIZE = {}", header_size);

    let mut frame_num = 0;
    loop {
        //println!("state = {:?}", state);

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
                        let header = citp::protocol::Header::read_from_bytes(data)?;
                        let header_size = header.size_bytes();
                        
                        match &header.content_type.to_le_bytes() {
                            pinf::Header::CONTENT_TYPE => {
                                if let pinf::PLoc::CONTENT_TYPE = &layer_two_content_type(&data, header_size).to_le_bytes() {
                                    //println!("PINF PLoc");
    
                                    let ploc = citp::protocol::pinf::PLoc::read_from_bytes(&data[header_size+CONTENT_TYPE_LEN..])?;
                                    //println!("ploc = {:#?}", ploc);
    
                                    let name = ploc.name.to_str().unwrap().to_owned();
                                    let tcp_addr = format!("{}:{}", extract_ip_address(&name), ploc.listening_tcp_port);
                                    //println!("ip_address = {}", tcp_addr);
    
                                    //Use the remote_addr to connect to the socket
                                    // only if it isn't already connected
                                    match socket.connect(remote_addr) {
                                        Ok(_) => (),
                                        Err(err) => eprint!("couldn't connect to TCP socket addr {:?}", err),
                                    }

                                    let stream = TcpStream::connect(tcp_addr).expect("Could not connect to server"); 
                                    let mut citp_tcp = CitpTcp::new(stream)?;                                   
                                    let message = connect_to_capture();
                                    //println!("pnam = {:#?}", message);
                                    message.write_to_bytes(&mut citp_tcp.writer).expect("Failed to write to server");
                                    
                                    // Tell TCP to send the buffered data on the wire
                                    citp_tcp.writer.flush()?;
                                    citp_tcp_stream = Some(citp_tcp);
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
                        let len = ploc.pinf_header.citp_header.message_size as usize;
                        socket.send(&ploc_buf[..len]).expect("Can't send buffer over UDP Socket");
                    },
                    Err(_) => {
                        eprintln!("error writing ploc to bytes");
                    }
                }
                
                if let Some(ref mut stream) = citp_tcp_stream {
                    stream.read_message()?;
                    
                    let feed_list = send_laser_feed_list();
                    feed_list.write_to_bytes(&mut stream.writer).expect("Failed to write to server");
                    stream.writer.flush()?;
                }

                state = State::Stream;
            }
            State::Stream => {
                if let Some(ref mut stream) = citp_tcp_stream {
                    stream.read_message()?;
                    
                    // let feed_list = send_laser_feed_list();
                    // feed_list.write_to_bytes(&mut stream.writer).expect("Failed to write to server");
                    // stream.writer.flush()?;
                }

                for i in 0..NUM_LASERS {
                    let laser_frame = stream_laser_frame(frame_num, i as u8);
                    //eprintln!("laser_frame = {:#?}", laser_frame);
                    let mut frame_buf = [0u8; 65535];
                    laser_frame.write_to_bytes(&mut frame_buf[..]).expect("Failed to write to server");
                    let len = laser_frame.caex_header.citp_header.message_size as usize;
                    //eprintln!("buf = {:?}", &frame_buf[..len]);
                    socket.send(&frame_buf[..len]).expect("Can't send buffer over UDP Socket");
                }
                
                frame_num += 1;
                    
                match socket.recv_from(&mut buf) {
                    Ok((len, remote_addr)) => {
                        // - Read the full base **Header** first.
                        let data = &buf[..len];
                        let header = citp::protocol::Header::read_from_bytes(data).unwrap();
                        let header_size = header.size_bytes();
                        
                        // match &header.content_type.to_le_bytes() {
                        //     _ => println!("Unrecognized UDP Header Content Type {}", header.content_type),
                        // }
                    }
                    Err(err) => {
                        println!("client: had a problem: {}", err);
                    }
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(32));   
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

fn pinf_header(pinf_message_size: usize, content_type: u32) -> pinf::Header {
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
        content_type,
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
        pinf_header: pinf_header(ploc.size_bytes(), u32::from_le_bytes(*pinf::PLoc::CONTENT_TYPE)),
        message: ploc,
    }
}


fn connect_to_capture() -> pinf::Message::<pinf::PNam> {
    let pnam = pinf::PNam {
        name: CString::new("Rusty Laser Software").expect("CString::new failed")
    };

    pinf::Message {
        pinf_header: pinf_header(pnam.size_bytes(), u32::from_le_bytes(*pinf::PNam::CONTENT_TYPE)),
        message: pnam,
    }
}


fn caex_laser_header(caex_message_size: usize, content_type: u32) -> caex::Header {
    caex::Header {
        citp_header: citp::protocol::Header {
            cookie: u32::from_le_bytes(*b"CITP"),
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
        content_type
    }
}

const SOURCE_KEY: u32 = 1;


fn send_laser_feed_list<'a>() -> caex::Message::<caex::LaserFeedList<'a>> {
    let mut test_list = vec![];
    for i in 0..NUM_LASERS {
        let name = format!("nannou_laser {}", i);
        test_list.push(CString::new(name).unwrap());
    }

    let feed_list = caex::LaserFeedList {
        source_key: SOURCE_KEY,
        feed_count: test_list.len() as u8,
        feed_names: std::borrow::Cow::from(test_list)
    };
    caex::Message {
        caex_header: caex_laser_header(feed_list.size_bytes(), caex::LaserFeedList::CONTENT_TYPE),
        message: feed_list
    }
}

/// Map a value from a given range to a new given range.
pub fn map_range(val: f32, in_min: f32, in_max: f32, out_min: f32, out_max: f32) -> f32 {
    (val - in_min) / (in_max - in_min) * (out_max - out_min) + out_min
}

fn stream_laser_frame<'a>(frame_num: u32, feed_index: u8) -> caex::Message::<caex::LaserFeedFrame<'a>> {
    let tl = [-1.0, 1.0];
    let tr = [1.0, 1.0];
    let br = [1.0, -1.0];
    let bl = [-1.0, -1.0];
    let positions = [tl, tr, br, bl, tl];
    let points: Vec<_> = positions.iter().cloned().map(|p| {
        let scale = (feed_index as f32 + frame_num as f32 * 0.02).sin();
        let x = map_range(p[0] * scale,-1.0,1.0,0.0,4093.0);
        let y = map_range(p[1] * scale,-1.0,1.0,0.0,4093.0);
        let x_nibble = (x/256.0).floor() as u8 % 16;
        let y_nibble = (y/256.0).floor() as u8 % 16;
        let xy_high_nibbles = y_nibble * 16 + x_nibble;

        let lfo1 = (feed_index as f32 + frame_num as f32 * 0.04).sin().abs();
        let lfo2 = (feed_index as f32 + frame_num as f32 * 0.015).sin().abs();
        let lfo3 = (feed_index as f32 + frame_num as f32 * 0.02).cos().abs();

        let r = map_range(lfo1, 0.0, 1.0, 0.0, 31.0) as u8;
        let g = map_range(lfo2, 0.0, 1.0, 0.0, 63.0) as u8;
        let b = map_range(lfo3, 0.0, 1.0, 0.0, 31.0) as u8;

        let color = r as u16 | (g as u16).rotate_left(5) | (b as u16).rotate_left(11);

        caex::LaserPoint {
            x_low_byte: (x % 256.0) as u8,
            y_low_byte: (y % 256.0) as u8,
            xy_high_nibbles,
            color,
        }
    }).collect();

    let feed_frame = caex::LaserFeedFrame {
        source_key: SOURCE_KEY,
        feed_index,
        frame_sequence: frame_num,
        point_count: points.len() as u16,
        points: std::borrow::Cow::from(points),
    };
    caex::Message {
        caex_header: caex_laser_header(feed_frame.size_bytes(), caex::LaserFeedFrame::CONTENT_TYPE),
        message: feed_frame
    }
}



