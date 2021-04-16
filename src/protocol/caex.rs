use protocol::{self, LE, ReadBytesExt, ReadFromBytes, SizeBytes, WriteBytes, WriteBytesExt,
               WriteToBytes};
use std::borrow::Cow;
use std::ffi::CString;
use std::{io, mem};
extern crate ucs2;

use super::Ucs2;

/// The CAEX layer provides a standard, single, header used at the start of all CAEX packets.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Header {
    /// The CITP header. CITP ContentType is "CAEX".
    pub citp_header: protocol::Header,
    /// A cookie defining which CAEX message it is.
    pub content_type: u32,
}

/// Layout of CAEX messages.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Message<T> {
    /// The CAEX header - the base header with the CAEX content type.
    pub caex_header: Header,
    /// The data for the message.
    pub message: T,
}

/// ## CAEX / Show Synchronization Messages.
///
/// The Show Synchronization messages allow a peer to exchange patch, selection and fixture status information with Capture.
///
/// In order for the user experience to be smooth and seamless, it is necessary to communicate "show state"
/// information with Capture. The following are the rules of interaction:
/// - Capture will send EnterShow and LeaveShow messages as projects are opened and
///   closed, given that the user has enabled the "console link" with the peer. If "console link" is
///   disabled and then reenabled, Capture will act as if the project was closed and opened
///   again. Always keep track of whether Capture is currently in a show or not.
/// - When opening or creating a new show: send an EnterShow message to Capture.
/// - When opening or creating a new show and Capture is currently in a show: send a patch
///   information request to Capture.
/// - When closing a show: send a LeaveShow message to Capture.
/// - When in a show and Capture enters a show: send a patch information request to
///   Capture.
/// - If the user chooses to disable synchronization: act as if the user had closed the show.
/// - If the user chooses to reenable synchronization: act as if the user had just opened the
///   current show.
/// 
/// It is important that the peer, upon receving complete patch information when both the peer and Capture have
/// entered a show, provides the user with the means to determine whether the patch is in sync and/or requires
/// modification, as well as the option to disable the synchronization

/// This message is sent unsolicited by both Capture and the peer when a show/project is opened and/or the user
/// wishes to enable show synchronization
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct EnterShow {
    /// The name of the show.
    pub name: Ucs2,
}

/// This message is sent unsolicited by both Capture and the peer when a show/project is closed or when the user
/// wishes to disable show synchronization.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct LeaveShow {}

/// This message can be sent unsolicited by Capture or a peer in order to acquire the full patch list from the other side. The
/// expected response is a FixtureList message with Type = 0x00.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct FixtureListRequest {}

#[repr(u8)]
pub enum FixtureListMessageType {
    ExistingPatchList = 0x00,
    NewFixture = 0x01,
    ExchangeFixture = 0x02,
}

/// This message is sent unsolicited by both Capture and the peer whenever a fixture has been modified. All fields must always be
/// present, but it is important that the ChangedFields field indicates which have actually been modified.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct FixtureModify<'a> {
    /// The number of fixtures following.
    pub fixture_count: u16,
    /// Array of fixture identifiers.
    pub fixture_identifiers: Cow<'a, [u32]>,
}

#[derive(Clone, Debug, PartialEq)]
#[repr(C)]
pub struct FixtureInfo {
    /// A boolean 0x00 or 0x01 indicating whether the fixture is patched or not.
    pub patched: u8,
    /// The (0-based) universe index.
    pub universe: u8,
    /// The (0-based) DMX channel.
    pub universe_channel: u16,
    /// The unit number.
    pub unit: Ucs2,
    /// The channel number.
    pub channel: u16,
    /// The circuit number.
    pub circuit: Ucs2,
    /// Any notes.
    pub note: Ucs2,
    /// The 3D position
    pub position: [f32; 3],
    /// The 3D angle.
    pub angles: [f32; 3],
}

/// This message is sent unsolicited by both Capture and the peer whenever on or more fixture(s) have been removed.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct FixtureRemove<'a> {
    /// The number of fixture identifiers following.
    pub fixture_count: u16,
    /// Array of fixture identifiers.
    pub fixture_identifiers: Cow<'a, [u32]>,
}

/// This message is sent unsolicited by the peer to Capture in order to convey "live information" data that can be displayed by
/// Capture.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct FixtureConsoleStatus<'a> {
    /// The number of fixtures following.
    pub fixture_count: u16,
    /// Array of fixtures states.
    pub fixtures_state: Cow<'a, [FixtureState]>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct FixtureState {
    /// Console's fixture identifier.
    pub fixture_identifier: u32,
    /// The fixture has been locked from manipulation.
    pub locked: u8,
    /// The fixture has a clearable programmer state.
    pub clearable: u8,
}

impl EnterShow {
    pub const CONTENT_TYPE: u32 = 0x00020100;
}

impl LeaveShow {
    pub const CONTENT_TYPE: u32 = 0x00020101;
}

impl FixtureListRequest {
    pub const CONTENT_TYPE: u32 = 0x00020200;
}

impl<'a> FixtureRemove<'a> {
    pub const CONTENT_TYPE: u32 = 0x00020203;
}

impl<'a> FixtureConsoleStatus<'a> {
    pub const CONTENT_TYPE: u32 = 0x00020400;
}

/// ## CAEX / Laser Feed Messages.
///
/// A peer may serve laser feeds to Capture. Information to Capture about which feeds are available and information
/// from Capture about which feeds to transmit is sent over the TCP based CITP session. Actual feed frame data is
/// transmitted to the UDP based CITP multicast address.
/// In order for Capture to be able to correlate the feed frames with the appropriate session, a process instance
/// unique and random "source key" is to be generated by the laser controller

/// This message is sent by Capture upon connection to determine what laser feeds are available. Receving this
/// message is an indication of Capture's ability to understand CAEX laser feeds.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct GetLaserFeedList {}

/// This message can be sent to Capture both in response to a GetLaserFeedList message as well as unsolicited if
/// the list of available laser feeds has changed.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct LaserFeedList<'a> {
    /// The source key used in frame messages.
    pub source_key: u32,
    /// The number of laser feed listings that follow.
    pub feed_count: u8,
    /// The name of the feed.
    pub feed_names: Cow<'a, [CString]>,
}

/// This message is sent by Capture to indicate whether it wishes a laser feed to be transmitted or not. The frame rate
/// can be seen as an indication of the maximum frame rate meaningful to Capture.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct LaserFeedControl {
    /// The 0-based index of the feed.
    pub feed_index: u8,
    /// The frame rate requested, 0 to disable transmission
    pub frame_rate: u8,
}

/// This message is sent unsolicited to Capture, carrying feed frame data.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct LaserFeedFrame<'a> {
    /// The source key as in the LaserFeedList message.
    pub source_key: u32,
    /// The 0-based index of the feed.
    pub feed_index: u8,
    /// A 0-based sequence number for out of order data detection.
    pub frame_sequence: u32,
    /// The number of points that follow.
    pub point_count: u16,
    /// Array of laser points.
    pub points: Cow<'a, [LaserPoint]>,
}

/// Example of how a point in constructed
/// 
/// Point.X [0, 4093] = Point.XLowByte + (Point.XYHighNibbles & 0x0f) << 8
/// Point.Y [0, 4093] = Point.YLowByte + (Point.XYHighNibbles & 0xf0) << 4
/// Point.R [0, 31] = Point.Color & 0x001f
/// Point.G [0, 63] = (Point.Color & 0x07e0) >> 5
/// Point.B [0, 31] = (Point.Color & 0xf800) >> 11
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct LaserPoint {
    /// The low byte of the x coordinate.
    pub x_low_byte: u8,
    /// The low byte of the y coordinate.
    pub y_low_byte: u8,
    /// The high nibbles of the x and y coordinates.
    pub xy_high_nibbles: u8,
    /// The colour packed as R5 G6 B5.
    pub color: u16,
}

impl Header {
    pub const CONTENT_TYPE: &'static [u8; 4] = b"CAEX";
}

impl GetLaserFeedList {
    pub const CONTENT_TYPE: u32 = 0x00030100;
}

impl<'a> LaserFeedList<'a> {
    pub const CONTENT_TYPE: u32 = 0x00030101;
}

impl LaserFeedControl {
    pub const CONTENT_TYPE: u32 = 0x00030102;
}

impl<'a> LaserFeedFrame<'a> {
    pub const CONTENT_TYPE: u32 = 0x00030200;
}


impl WriteToBytes for Header {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_bytes(&self.citp_header)?;
        writer.write_u32::<LE>(self.content_type)?;
        Ok(())
    }
}

impl<T> WriteToBytes for Message<T>
where
    T: WriteToBytes,
{
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_bytes(&self.caex_header)?;
        writer.write_bytes(&self.message)?;
        Ok(())
    }
}

impl<'a> WriteToBytes for LaserFeedList<'a> {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u32::<LE>(self.source_key)?;
        writer.write_u8(self.feed_names.len() as _)?;
        for n in self.feed_names.iter() {
            let ucs2 = Ucs2::from_str(n.to_str().unwrap()).unwrap();
            ucs2.write_to_bytes(&mut writer)?;
        }
        Ok(())
    }
}

impl WriteToBytes for LaserFeedControl {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u8(self.feed_index)?;
        writer.write_u8(self.frame_rate)?;
        Ok(())
    }
}

impl<'a> WriteToBytes for LaserFeedFrame<'a> {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u32::<LE>(self.source_key)?;
        writer.write_u8(self.feed_index)?;
        writer.write_u32::<LE>(self.frame_sequence)?;
        writer.write_u16::<LE>(self.points.len() as _)?;
        for p in self.points.iter() {
            p.write_to_bytes(&mut writer)?;
        }
        Ok(())
    }
}

impl WriteToBytes for LaserPoint {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u8(self.x_low_byte)?;
        writer.write_u8(self.y_low_byte)?;
        writer.write_u8(self.xy_high_nibbles)?;
        writer.write_u16::<LE>(self.color)?;
        Ok(())
    }
}

impl ReadFromBytes for LaserFeedControl {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let feed_index = reader.read_u8()?;
        let frame_rate = reader.read_u8()?;
        let laser_feed_control = LaserFeedControl { feed_index, frame_rate };
        Ok(laser_feed_control)
    }
}

impl ReadFromBytes for EnterShow {
    fn read_from_bytes<R: ReadBytesExt>(reader: R) -> io::Result<Self> {
        let name = Ucs2::read_from_bytes(reader)?;
        Ok(EnterShow { name })
    }
}


impl<'a> SizeBytes for LaserFeedList<'a> {
    fn size_bytes(&self) -> usize {
        let mut feed_names_size = 0;
        for n in self.feed_names.iter() {
            let ucs2 = Ucs2::from_str(&n.to_str().unwrap()).unwrap();
            feed_names_size += ucs2.size_bytes();
        }
        mem::size_of::<u32>()
        + mem::size_of::<u8>()
        + feed_names_size
    }
}

impl SizeBytes for LaserFeedControl {
    fn size_bytes(&self) -> usize {
        mem::size_of::<u8>()
        + mem::size_of::<u8>()
    }
}

impl<'a> SizeBytes for LaserFeedFrame<'a> {
    fn size_bytes(&self) -> usize {
        let mut ps = 0;
        for p in self.points.iter() {
            ps += p.size_bytes();
        } 
        mem::size_of::<u32>()
        + mem::size_of::<u8>()
        + mem::size_of::<u32>()
        + mem::size_of::<u16>()
        + ps
    }
}

impl SizeBytes for LaserPoint {
    fn size_bytes(&self) -> usize {
        mem::size_of::<u8>()
        + mem::size_of::<u8>()
        + mem::size_of::<u8>()
        + mem::size_of::<u16>()
    }
}


