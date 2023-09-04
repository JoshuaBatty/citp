use std::io::{self, BufRead, Write};
use std::net::TcpStream;

use citp;
use citp::protocol::ReadFromBytes;
use citp::protocol::SizeBytes;
use citp::protocol::{caex, pinf, sdmx};

pub struct CitpTcp {
    // Our buffered reader & writers
    pub reader: io::BufReader<TcpStream>,
    pub writer: io::LineWriter<TcpStream>,
}

pub enum CaexState {
    Nack,
    GetLaserFeedList,
    LaserFeedList,
    LaserFeedControl,
    LaserFeedFrame,
    EnterShow,
    LeaveShow,
    FixtureListRequest,
    FixtureList,
    FixtureRemove,
    FixtureConsoleStatus,
}

impl CitpTcp {
    /// Encapsulate a TcpStream with buffered reader/writer functionality
    pub fn new(stream: TcpStream) -> io::Result<Self> {
        // Both BufReader and LineWriter need to own a stream
        // We can clone the stream to simulate splitting Tx & Rx with `try_clone()`
        let writer = io::LineWriter::new(stream.try_clone()?);
        let reader = io::BufReader::new(stream);
        Ok(Self { reader, writer })
    }

    /// Write the given message (appending a newline) to the TcpStream
    pub fn send_message(&mut self, message: &str) -> io::Result<()> {
        self.writer.write(&message.as_bytes())?;
        // This will also signal a `writer.flush()` for us; thanks LineWriter!
        self.writer.write(&['\n' as u8])?;
        Ok(())
    }

    /// Read a received message from the TcpStream
    pub fn read_message(&mut self) -> io::Result<Option<CaexState>> {

        let mut caex_state: Option<CaexState> = None;
        
        // let mut line = String::new();
        // // Use `BufRead::read_line()` to read a line from the TcpStream
        // self.reader.read_line(&mut line)?;
        // line.pop(); // Remove the trailing "\n"
        // Ok(line)

        eprintln!("TCP: read_message()");
        let len = self.reader.buffer().len();
        eprintln!("TCP: len = {}", len);
        // self.reader.consume(len);

        // Read current current data in the TcpStream
        //let mut received: Vec<u8> = self.reader.fill_buf()?.to_vec();

        let mut received: Vec<u8> = match self.reader.buffer().is_empty() {
            true => {
                eprintln!("TCP: buffer is empty");
                self.reader.fill_buf()?.to_vec()
            }
            false => {
                eprintln!("TCP: buffer is not empty");
                self.reader.buffer().to_vec()
            }
        };

        // Do some processing or validation to make sure the whole line is present?
        // ...

        println!("TCP: start of new message: received len = {}", received.len());
        let mut total_received_bytes_processed = 0;

        while !received.is_empty() {
            let mut message_size = 0;
            let header = citp::protocol::Header::read_from_bytes(&received[..]).unwrap();
            let header_size = header.size_bytes();
            let content_size = header.message_size as usize - header_size - super::CONTENT_TYPE_LEN;
            println!("header = {:#?}", header);
            println!("header_size = {:#?}", header_size);

            let read_offset = header_size + super::CONTENT_TYPE_LEN;
            let message_content_type = layer_two_content_type(&received, header_size).to_le_bytes();
            match &header.content_type.to_le_bytes() {
                pinf::Header::CONTENT_TYPE => {
                    // - Read the header for the second layer.
                    // - Match on the `content_type` field of the second layer to determine what type to read.
                    match &message_content_type {
                        pinf::PNam::CONTENT_TYPE => {
                            let pnam =
                                pinf::PNam::read_from_bytes(&received[read_offset..]).unwrap();
                            println!("pnam = {:#?}", pnam);
                            message_size = pnam.size_bytes();
                        }
                        pinf::PLoc::CONTENT_TYPE => {
                            let ploc =
                                pinf::PLoc::read_from_bytes(&received[read_offset..]).unwrap();
                            println!("ploc = {:#?}", ploc);
                            message_size = ploc.size_bytes();
                        }
                        _ => (),
                    }
                }
                sdmx::Header::CONTENT_TYPE => {
                    if let sdmx::Capa::CONTENT_TYPE = &message_content_type {
                        let capa = sdmx::Capa::read_from_bytes(&received[read_offset..]).unwrap();
                        //println!("capa = {:#?}", capa);
                        message_size = capa.size_bytes();
                    }
                }
                caex::Header::CONTENT_TYPE => {
                    match layer_two_content_type(&received, header_size) {
                        caex::Nack::CONTENT_TYPE => {
                            println!("NACK Message recieved!");
                        }
                        caex::GetLaserFeedList::CONTENT_TYPE => {
                            println!("GetLaserFeedList");
                            // message_size = 0;

                            caex_state = Some(CaexState::GetLaserFeedList);
                        }
                        caex::LaserFeedList::CONTENT_TYPE => {
                            println!("LaserFeedList");
                        }
                        caex::LaserFeedControl::CONTENT_TYPE => {
                            let feed_control =
                                caex::LaserFeedControl::read_from_bytes(&received[read_offset..])
                                    .unwrap();
                            println!("feed_control = {:#?}", feed_control);
                            message_size = feed_control.size_bytes();

                            caex_state = Some(CaexState::LaserFeedControl);
                        }
                        caex::LaserFeedFrame::CONTENT_TYPE => {
                            println!("LaserFeedFrame");
                        }
                        caex::EnterShow::CONTENT_TYPE => {
                            println!("EnterShow");
                            let enter_show =
                                caex::EnterShow::read_from_bytes(&received[read_offset..]).unwrap();
                            message_size = enter_show.size_bytes();
                            println!("enter_show = {:#?}", enter_show);

                            caex_state = Some(CaexState::EnterShow);
                        }
                        caex::LeaveShow::CONTENT_TYPE => {
                            println!("LeaveShow");

                            caex_state = Some(CaexState::LeaveShow);
                        }
                        caex::FixtureListRequest::CONTENT_TYPE => {
                            println!("FixtureListRequest");

                            caex_state = Some(CaexState::FixtureListRequest);
                        }
                        caex::FixtureList::CONTENT_TYPE => {
                            println!("FixtureList");
                            let fixture_list =
                                caex::FixtureList::read_from_bytes(&received[read_offset..]).unwrap();
                            message_size = fixture_list.size_bytes();
                            println!("fixture_list = {:#?}", fixture_list);
                        }
                        caex::FixtureRemove::CONTENT_TYPE => {
                            println!("FixtureRemove");
                        }
                        caex::FixtureConsoleStatus::CONTENT_TYPE => {
                            println!("FixtureConsoleStatus");
                        }
                        _ => (),
                    }
                }
                _ => {
                    println!(
                        "Un recognized TCP Header Content Type {}",
                        header.content_type
                    );
                    panic!("Un recognized TCP Header: {:#?}", header);
                    break;
                }
            }

            println!("TCP: header.message_size = {:#?} | received_len {}", header.message_size, received.len());

            // if received.len() <= header.message_size as usize {
            //     eprintln!("TCP: Break!");
            //     break;
            // }

            eprintln!("TCP: Draining {} bytes", header.message_size);
            total_received_bytes_processed += header.message_size as usize;
            received = received.drain(header.message_size as usize..).collect();
            break; // Try forcing only one message at a time.
            //let header = citp::protocol::Header::read_from_bytes(&message[..]).unwrap();
            //println!("header 2 = {:#?}", header);
        }

        // Mark the bytes read as consumed so the buffer will not return them in a subsequent read
        self.reader.consume(total_received_bytes_processed);//received.len());
        eprintln!("TCP: Consume {} bytes", received.len());

        Ok(caex_state)

        // String::from_utf8(received)
        //     .map(|msg| println!("{}", msg))
        //     .map_err(|_| {
        //         io::Error::new(
        //             io::ErrorKind::InvalidData,
        //             "Couldn't parse received string as utf8",
        //         )
        //     })
    }
}

fn layer_two_content_type(data: &[u8], header_size: usize) -> u32 {
    let slice = &data[header_size..header_size + super::CONTENT_TYPE_LEN];
    u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]])
}
