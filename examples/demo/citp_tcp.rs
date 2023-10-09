use citp::protocol::{ReadFromBytes, SizeBytes, caex, pinf, sdmx};
use std::{
    io::{self, BufRead, Write},
    net::TcpStream,
};

/// Represents a CITP TCP connection with buffered read/write functionality.
pub struct CitpTcp {
    pub reader: io::BufReader<TcpStream>,
    pub writer: io::LineWriter<TcpStream>,
}

/// Possible states of the CAEX protocol.
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
        let writer = io::LineWriter::new(stream.try_clone()?);
        let reader = io::BufReader::new(stream);
        Ok(Self { reader, writer })
    }

    /// Sends a given message (appending a newline) over the TCP stream.
    pub fn send_message(&mut self, message: &str) -> io::Result<()> {
        self.writer.write(&message.as_bytes())?;
        self.writer.write(&['\n' as u8])?; // This will also signal a `writer.flush()` for us; thanks LineWriter!
        Ok(())
    }

    /// Reads a received message from the TCP stream and returns the associated CAEX state.
    pub fn read_message(&mut self) -> io::Result<Option<CaexState>> {
        let mut caex_state: Option<CaexState> = None;
        // Read current current data in the TcpStream
        let mut received = self.reader.fill_buf()?.to_vec();

        // Do some processing or validation to make sure the whole line is present?
        // ...

        let mut total_received_bytes_processed = 0;

        while !received.is_empty() {
            let header = citp::protocol::Header::read_from_bytes(&received[..]).unwrap();
            let header_size = header.size_bytes();
            println!("header = {:#?}", header);
            println!("header_size = {:#?}", header_size);

            let read_offset = header_size + super::CONTENT_TYPE_LEN;
            let message_content_type = super::layer_two_content_type(&received, header_size).to_le_bytes();
            match &header.content_type.to_le_bytes() {
                pinf::Header::CONTENT_TYPE => {
                    // - Read the header for the second layer.
                    // - Match on the `content_type` field of the second layer to determine what type to read.
                    match &message_content_type {
                        pinf::PNam::CONTENT_TYPE => {
                            let pnam =
                                pinf::PNam::read_from_bytes(&received[read_offset..]).unwrap();
                            println!("PNam = {:#?}", pnam);
                        }
                        pinf::PLoc::CONTENT_TYPE => {
                            let ploc =
                                pinf::PLoc::read_from_bytes(&received[read_offset..]).unwrap();
                            println!("PLoc = {:#?}", ploc);
                        }
                        _ => (),
                    }
                }
                sdmx::Header::CONTENT_TYPE => {
                    if let sdmx::Capa::CONTENT_TYPE = &message_content_type {
                        let capa = sdmx::Capa::read_from_bytes(&received[read_offset..]).unwrap();
                        println!("sdmx Capa = {:#?}", capa);
                    }
                }
                caex::Header::CONTENT_TYPE => {
                    match super::layer_two_content_type(&received, header_size) {
                        caex::Nack::CONTENT_TYPE => {
                            println!("TCP: NACK Message recieved!");
                        }
                        caex::GetLaserFeedList::CONTENT_TYPE => {
                            println!("TCP: GetLaserFeedList");
                            caex_state = Some(CaexState::GetLaserFeedList);
                        }
                        caex::LaserFeedList::CONTENT_TYPE => {
                            println!("TCP: LaserFeedList");
                        }
                        caex::LaserFeedControl::CONTENT_TYPE => {
                            let feed_control =
                                caex::LaserFeedControl::read_from_bytes(&received[read_offset..])
                                    .unwrap();
                            println!("TCP: LaserFeedControl = {:#?}", feed_control);
                            caex_state = Some(CaexState::LaserFeedControl);
                        }
                        caex::LaserFeedFrame::CONTENT_TYPE => {
                            println!("TCP: LaserFeedFrame");
                        }
                        caex::EnterShow::CONTENT_TYPE => {
                            let enter_show =
                                caex::EnterShow::read_from_bytes(&received[read_offset..]).unwrap();
                            println!("TCP: EnterShow = {:#?}", enter_show);
                            caex_state = Some(CaexState::EnterShow);
                        }
                        caex::LeaveShow::CONTENT_TYPE => {
                            println!("TCP: LeaveShow");
                            caex_state = Some(CaexState::LeaveShow);
                        }
                        caex::FixtureListRequest::CONTENT_TYPE => {
                            println!("TCP: FixtureListRequest");
                            caex_state = Some(CaexState::FixtureListRequest);
                        }
                        caex::FixtureList::CONTENT_TYPE => {
                            let fixture_list =
                                caex::FixtureList::read_from_bytes(&received[read_offset..])
                                    .unwrap();
                            println!("TCP: FixtureList = {:#?}", fixture_list);
                        }
                        caex::FixtureRemove::CONTENT_TYPE => {
                            println!("TCP: FixtureRemove");
                        }
                        caex::FixtureConsoleStatus::CONTENT_TYPE => {
                            println!("TCP: FixtureConsoleStatus");
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
                }
            }

            println!(
                "TCP: header.message_size = {:#?} | received_len {}",
                header.message_size,
                received.len()
            );

            eprintln!("TCP: Draining {} bytes", header.message_size);
            total_received_bytes_processed += header.message_size as usize;
            received = received.drain(header.message_size as usize..).collect();
            break;
        }

        // Mark the bytes read as consumed so the buffer will not return them in a subsequent read
        self.reader.consume(total_received_bytes_processed);
        eprintln!("TCP: Consume {} bytes", received.len());

        Ok(caex_state)
    }
}
