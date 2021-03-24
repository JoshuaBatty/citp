extern crate citp;
use citp::protocol::{SizeBytes, ReadFromBytes};
use std::net::UdpSocket;
use std::net::Ipv4Addr;

fn main() {
    let multicast_port = format!("{}",citp::protocol::pinf::MULTICAST_PORT);
    let mut socket = UdpSocket::bind(format!("0.0.0.0:{}",multicast_port)).unwrap();
    let mut buf = [0u8; 65535];
    let addr = citp::protocol::pinf::OLD_MULTICAST_ADDR;
    let multi_addr = Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]);
    let inter = Ipv4Addr::new(0,0,0,0);
    socket.join_multicast_v4(&multi_addr,&inter);

    // loop {
    //     let (amt, src) = socket.recv_from(&mut buf).unwrap();
    //     println!("received {} bytes from {:?}", amt, src);
    // }

    let remote: std::net::SocketAddr = "172.18.35.81:19536".parse().unwrap();
    let mut stream = std::net::TcpStream::connect_timeout(&remote, std::time::Duration::from_secs(14))
                               .expect("Could not connect to server");

    loop {
        match socket.recv_from(&mut buf) {
            Ok((len, remote_addr)) => {
                let data = &buf[..len];

                let header = citp::protocol::Header::read_from_bytes(&data[..20]).unwrap();
                let header_size = header.size_bytes();
                println!("header_size = {:#?}", header_size);
                println!("header = {:#?}", header);

                let ploc = citp::protocol::pinf::PLoc::read_from_bytes(&data[header_size..]).unwrap();
                println!("ploc = {:#?}", ploc);

                let name = ploc.name.to_str().unwrap().to_owned();
                let tcp_addr = format!("{}:{}", extract_ip_address(&name), ploc.listening_tcp_port);

                println!("ip_address = {}", tcp_addr);

                let response = String::from_utf8_lossy(data);
    
                println!("client: got data: {}", response);

                let mut stream = std::net::TcpStream::connect(tcp_addr)
                               .expect("Could not connect to server");
            }
            Err(err) => {
                println!("client: had a problem: {}", err);
                assert!(false);
            }
        }
    }
}

fn extract_ip_address(s: &String) -> String {
    let start_bytes = s.find("(").unwrap_or(0) + 1; 
    let end_bytes = s.find(")").unwrap_or(s.len());
    s[start_bytes..end_bytes].to_string()
}

// fn connect_to_capture() -> citp::protocol::Header {
//     Header {
//         cookie: 1347701059,
//         version_major: 1,
//         version_minor: 0,
//         kind: 0,
//         message_size: 44,
//         message_part_count: 1,
//         message_part: 0,
//         content_type: 1179535696,
//     }
// }

