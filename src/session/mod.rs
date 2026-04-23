pub mod arq;
pub mod flow;
pub mod stream;

use std::collections::HashMap;
use crate::{
    crypto::{encoder::PacketEncoder, decoder::PacketDecoder},
    error::ApexError,
    packet::PktType,
    session::{
        arq::ArqTracker,
        flow::FlowWindow,
        stream::{Stream, StreamId, Priority, PRIORITY_DEFAULT},
    },
};

/// Events the session layer surfaces to the application.
#[derive(Debug)]
pub enum SessionEvent {
    NewStream(StreamId),
    DataAvailable(StreamId),
    StreamFinished(StreamId),
    Closed,
}

const DEFAULT_WINDOW: u64 = 1 << 20; // 1 MiB
const MAX_PAYLOAD: usize = 1400;    // conservative MTU

pub struct Session {
    pub id: u64,
    encoder: PacketEncoder,
    decoder: PacketDecoder,
    streams: HashMap<StreamId, Stream>,
    next_stream_id: StreamId,
    send_window: FlowWindow,
    recv_window: FlowWindow,
    arq: ArqTracker,
}

impl Session {
    pub fn new(id: u64, encoder: PacketEncoder, decoder: PacketDecoder) -> Self {
        Self {
            id,
            encoder,
            decoder,
            streams: HashMap::new(),
            next_stream_id: 1,
            send_window: FlowWindow::new(DEFAULT_WINDOW),
            recv_window: FlowWindow::new(DEFAULT_WINDOW),
            arq: ArqTracker::new(),
        }
    }

    // ── Stream management ────────────────────────────────────────────────────

    /// Open a locally-initiated stream.
    pub fn open_stream(&mut self) -> StreamId {
        self.open_stream_with_priority(PRIORITY_DEFAULT)
    }

    /// Open a stream with explicit priority (0 = highest, 7 = lowest).
    pub fn open_stream_with_priority(&mut self, priority: Priority) -> StreamId {
        let id = self.next_stream_id;
        self.next_stream_id += 2;
        let mut s = Stream::new(id);
        s.priority = priority;
        self.streams.insert(id, s);
        id
    }

    /// Accept a remotely-initiated stream (called when a Data frame arrives for an unknown id).
    fn get_or_create_stream(&mut self, id: StreamId) -> &mut Stream {
        self.streams.entry(id).or_insert_with(|| Stream::new(id))
    }

    // ── Sending ──────────────────────────────────────────────────────────────

    /// Write `data` into a stream's send buffer.
    pub fn send(&mut self, stream_id: StreamId, data: &[u8]) -> Result<(), ApexError> {
        self.send_window.reserve(data.len() as u64)?;
        let stream = self.streams.get_mut(&stream_id)
            .ok_or(ApexError::UnknownStream(stream_id))?;
        stream.write(data)?;
        Ok(())
    }

    /// Packetise pending stream data into wire packets. Returns encoded packets.
    /// Streams are drained in priority order (0 = highest). Within the same
    /// priority, streams are served round-robin by insertion order.
    pub fn flush(&mut self) -> Result<Vec<Vec<u8>>, ApexError> {
        let mut packets = Vec::new();
        // Collect and sort by priority (stable sort preserves insertion order within same priority)
        let mut stream_ids: Vec<StreamId> = self.streams.keys().copied().collect();
        stream_ids.sort_by_key(|id| self.streams[id].priority);

        for sid in stream_ids {
            loop {
                let stream = self.streams.get_mut(&sid).unwrap();
                let Some((offset, chunk)) = stream.poll_send(MAX_PAYLOAD - 14) else { break };

                // Frame: type(1) + flags(1) + len(2) + stream_id(4) + offset(8) = 16 bytes header
                let mut frame = Vec::with_capacity(16 + chunk.len());
                frame.push(0x01u8); // FrameType::Stream
                frame.push(0u8);    // flags
                frame.extend_from_slice(&(chunk.len() as u16).to_le_bytes());
                frame.extend_from_slice(&sid.to_le_bytes());
                frame.extend_from_slice(&offset.to_le_bytes());
                frame.extend_from_slice(&chunk);

                let mut out = vec![0u8; 32 + frame.len() + 16];
                let n = self.encoder.encode(PktType::Data, &frame, &mut out)?;
                out.truncate(n);

                self.arq.on_sent(0, bytes::Bytes::from(frame)); // pkt_num tracked by encoder
                packets.push(out);
            }
        }
        Ok(packets)
    }

    // ── Receiving ────────────────────────────────────────────────────────────

    /// Process an incoming wire packet. Returns events.
    pub fn receive_packet(&mut self, buf: &mut [u8]) -> Result<Vec<SessionEvent>, ApexError> {
        let (pkt_type, _pkt_num, payload) = self.decoder.decode(buf)?;
        let mut events = Vec::new();

        match pkt_type {
            PktType::Data => {
                let ev = self.handle_data_frame(payload.to_vec())?;
                events.extend(ev);
            }
            PktType::Ack => {
                self.handle_ack_frame(payload)?;
            }
            PktType::Close => {
                events.push(SessionEvent::Closed);
            }
            _ => {}
        }
        Ok(events)
    }

    fn handle_data_frame(&mut self, frame: Vec<u8>) -> Result<Vec<SessionEvent>, ApexError> {
        // Parse: type(1) + flags(1) + len(2) + stream_id(4) + offset(8) + data
        if frame.len() < 16 { return Ok(vec![]); }
        let data_len = u16::from_le_bytes([frame[2], frame[3]]) as usize;
        let stream_id = u32::from_le_bytes([frame[4], frame[5], frame[6], frame[7]]);
        let offset = u64::from_le_bytes(frame[8..16].try_into().unwrap());
        let is_fin = frame[1] & 0x01 != 0;

        if frame.len() < 16 + data_len { return Ok(vec![]); }
        let data = bytes::Bytes::copy_from_slice(&frame[16..16 + data_len]);

        let mut events = Vec::new();
        let is_new = !self.streams.contains_key(&stream_id);
        let stream = self.get_or_create_stream(stream_id);
        if is_new {
            events.push(SessionEvent::NewStream(stream_id));
        }
        stream.receive(offset, data, is_fin)?;
        events.push(SessionEvent::DataAvailable(stream_id));
        if is_fin || stream.is_recv_finished() {
            events.push(SessionEvent::StreamFinished(stream_id));
        }
        Ok(events)
    }

    fn handle_ack_frame(&mut self, frame: &[u8]) -> Result<(), ApexError> {
        if frame.len() < 8 { return Ok(()); }
        let acked_pkt = u64::from_le_bytes(frame[..8].try_into().unwrap());
        self.arq.on_ack(acked_pkt);
        Ok(())
    }

    // ── Read ─────────────────────────────────────────────────────────────────

    pub fn read(&mut self, stream_id: StreamId, out: &mut Vec<u8>, max: usize) -> Result<usize, ApexError> {
        let stream = self.streams.get_mut(&stream_id)
            .ok_or(ApexError::UnknownStream(stream_id))?;
        Ok(stream.read(out, max))
    }

    // ── Transport helpers ────────────────────────────────────────────────────

    /// Encode a single non-stream packet (e.g. Chaff, PathProbe) using session keys.
    pub fn encode_raw(&self, pkt_type: PktType, payload: &[u8], out: &mut [u8]) -> Result<usize, ApexError> {
        self.encoder.encode(pkt_type, payload, out)
    }

    pub fn arq_in_flight(&self) -> usize {
        self.arq.in_flight_count()
    }

    pub fn srtt_us(&self) -> u64 {
        self.arq.srtt().as_micros() as u64
    }

    /// Drain ARQ packets that have exceeded their RTO. Returns (pkt_num, data) pairs.
    pub fn drain_retransmits(&mut self) -> Vec<(u64, bytes::Bytes)> {
        self.arq.drain_expired()
    }
}
