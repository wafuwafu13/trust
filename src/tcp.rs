use std::io;
use std::io::prelude::*;

pub enum State {
    Closed,
    Listen,
    SynRcvd,
    Estab,
    FinWait1,
    FinWait2,
    Closing,
}

impl State {
    fn is_synchronized(&self) -> bool {
        match *self {
            State::SynRcvd => false,
            State::Estab | State::FinWait1 | State::FinWait2 | State::Closing => true,
        }
    }
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    ip: etherparse::Ipv4Header,
    tcp: etherparse::TcpHeader,
}

/// State of Send Sequence Space (RFC793 S3.2 F4)
///
///                   1         2          3          4
///              ----------|----------|----------|----------
///                     SND.UNA    SND.NXT    SND.UNA
///                                          +SND.WND
///
///        1 - old sequence numbers which have been acknowledged
///        2 - sequence numbers of unacknowledged data
///        3 - sequence numbers allowed for new data transmission
///        4 - future sequence numbers which are not yet allowed

struct SendSequenceSpace {
    /// send unacknowledged
    una: u32,
    /// send next
    nxt: u32,
    /// send window
    wnd: u16,
    /// send urgent pointer
    up: bool,
    /// segment sequence number used for last window update
    wl1: usize,
    /// segment acknowledgment number used for last window update
    wl2: usize,
    /// initial send sequence number
    iss: u32,
}

/// State of Receive Sequence Space (RFC793 S3.2 F5)
///
///
///                       1          2          3
///                   ----------|----------|----------
///                          RCV.NXT    RCV.NXT
///                                    +RCV.WND
///
///        1 - old sequence numbers which have been acknowledged
///        2 - sequence numbers allowed for new reception
///        3 - future sequence numbers which are not yet allowed

struct RecvSequenceSpace {
    // receive next
    nxt: u32,
    // receive window
    wnd: u16,
    // receive urgent pointer
    up: bool,
    // initial receive sequence number
    irs: u32,
}

impl Connection {
    pub fn accept<'a>(
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<Option<Self>> {
        let mut buf = [0u8; 1500];
        if !tcph.syn() {
            // only expected SYN packet
            return Ok(None);
        }

        let iss = 0;
        let wnd = 10;
        let mut c = Connection {
            state: State::SynRcvd,
            send: SendSequenceSpace {
                iss,
                una: iss,
                nxt: iss,
                wnd: wnd,
                up: false,
                wl1: 0,
                wl2: 0,
            },
            recv: RecvSequenceSpace {
                irs: tcph.sequence_number(),
                nxt: tcph.sequence_number() + 1,
                wnd: tcph.window_size(),
                up: false,
            },
            tcp: etherparse::TcpHeader::new(tcph.destination_port(), tcph.source_port(), iss, wnd),
            ip: etherparse::Ipv4Header::new(
                0,
                64,
                etherparse::IpTrafficClass::Tcp,
                [
                    iph.destination()[0],
                    iph.destination()[1],
                    iph.destination()[2],
                    iph.destination()[3],
                ],
                [
                    iph.source()[0],
                    iph.source()[1],
                    iph.source()[2],
                    iph.source()[3],
                ],
            ),
        };

        // need to start establishing a connection
        self.tcp.syn = true;
        self.tcp.ack = true;
        c.write(nic, &[])?;
        Ok(Some(c))
    }

    fn write(&mut self, nic: &mut tun_tap::Iface, payload: &[u8]) -> io::Result<usize> {
        let mut buf = [0u8; 1500];
        self.tcp.sequence_number = self.send.nxt;
        self.tcp.acknowledgment_number = self.recv.nxt;

        let size = std::cmp::min(
            buf.len(),
            self.tcp.header_len() + self.ip.header_len() as usize + payload.len(),
        );
        self.ip.set_payload_len(size);

        // the kernal is nice and does this for us
        // self.tcp.checksum = self.tcp
        //    .calc_checksum_ipv4(&c.ip, &[])
        //    .expect("faild to compute checksum");

        // write out the headers
        use std::io::Write;
        let mut unwritten = &mut buf[..];
        self.ip.write(&mut unwritten);
        self.tcp.write(&mut unwritten);
        let payload_bytes = unwritten.write(payload)?;
        let unwitten = unwitten.len();
        self.send.nxt.wrapping_add(payload_bytes as u32);
        if self.tcp.syn {
            self.send.nxt.wrapping_add(1);
            self.tcp.syn = false;
        }
        if self.tcp.fin {
            self.send.nxt.wrapping_add(1);
            self.tcp.fin = false;
        }

        nic.send(&bufi[..buf.len() - unwritten])?;
        Ok(payload_bytes);
    }

    fn send_rst<'a>(&mut self, nic: &mut tun_tap::Iface) -> io::Result<()> {
        self.tcp.rst = true;
        // TODO: fix sequence numbers here
        // If the incoming segment has an ACK field, the reset takes its
        // sequence number from the ACK field of the segment, otherwise the
        // reset has sequence number zero and the ACK field is set to the sum
        // of the sequence number and segment length of the incoming segment.
        // The connection remains in the same state.
        //
        // TODO: handle synchronized RST
        //  3.  If the connection is in a synchronized state (ESTABLISHED,
        // FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT),
        // any unacceptable segment (out of window sequence number or
        // unacceptible acknowledgment number) must elicit only an empty
        // acknowledgment segment containing the current send-sequence number
        // and an acknowledgment indicating the next sequence number expected
        // to be received, and the connection remains in the same state.
        self.tcp.sequence_number = 0;
        self.tcp.acknowledgment_number = 0;
        self.write(nic, &[])?;
        Ok(());
    }

    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<()> {
        // first, check that sequence numbers are valid (RFC 793 s3.3)
        //
        // acceptable ack check
        // SND.UNA < SEG.ACK =< SND.NXT
        // but remember wrapping!
        //
        let ackn = tcph.acknowledgment_number();
        if !is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
            if !self.state.is_synchronized() {
                //accourding top Reset generation, we should send a
                self.send_rst(nic);
            }
            return Ok(());
        }
        // If the data flow is momentarily idle and all data
        //sent has been acknowledged then the three variables will be equal
        self.send.una = ackn;

        //
        // valid segment check. okay if it acks at least one byte, which means that at least one of
        // the following is true:
        //
        // RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
        // RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
        //
        let seqn = tcph.sequence_number();
        let mut slen = data.len() as u32;
        if tcph.fin() {
            slen += 1;
        };
        if tcph.syn() {
            slen += 1;
        };
        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);
        if slen == 0 {
            // zero-length segment has separate rules for acceptance
            if self.recv.wnd == 0 {
                if seqn != self.recv.nxt {
                    return Ok(());
                }
            } else {
                if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend) {
                    return Ok(());
                }
            }
        } else {
            if self.recv.wnd == 0 {
                return Ok(());
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend)
                && !is_between_wrapped(
                    self.recv.nxt.wrapping_sub(1),
                    seqn.wrapping_add(slen - 1),
                    wend,
                )
            {
                return Ok(());
            }
        }

        // The sender of data keeps track of the next sequence number to use in
        // the variable SND.NXT
        self.recv.nxt = seqn.wrapping_add(slen);

        // TODO: make sure this

        match self.state {
            State::SynRcvd => {
                // expect to get an ACK for our SYN
                if !tcph.ack() {
                    return Ok(());
                }
                // must have ACKed our SYN, since we detected at least one acked byte, and we have
                // only sent one byte (the SYN).
                self.state = State::Estab;

                // now let's terminate the connection!
                // TODO: needs to be stored in the retransmission queue!
                self.tcp.fin = true;
                self.write(nic, &[])?;
                self.state = State::FinWait1;
            }
            State::Estab => {
                unimplemented!();
            }
            State::FinWait1 => {
                if !tcph.fin() || !data.is_empty() {
                    unimplemented!();
                }

                // must have ACKed our SYN, since we detected at least one acked byte, and we have
                // only sent one byte (the FIN).
                self.state = State::FinWait2;
            }
            State::Closing => {
                if !tcph.fin() || !data.is_empty() {
                    unimplemented!();
                }
                // must have ACKed our SYN, since we detected at least one acked byte, and we have
                // only sent one byte (the FIN).
                self.tcp.fin = false;
                self.write(nic, &[])?;
                self.state = State::Closing;
            }
        }

        Ok(());
    }
}

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    use std::cmp::Ordering;
    match start.cmp(x) {
        Ordering::Equal => false,
        Ordering::Less => {
            // we have:
            //
            //   0 |----------S-----X--------| (wraparound)
            //
            // X is between S and E (S < X < E) in these cases:
            //
            //   0 |----------S-----X--E-----| (wraparound)
            //
            //   0 |------E---S-----X--------| (wraparound)
            //
            // but not in these cases
            //
            //   0 |----------S--E--X--------| (wraparound)
            //
            //   0 |----------|-----X--------| (wraparound)
            //                ^-S+E
            //
            //   0 |----------S-----|--------| (wraparound)
            //                  X+E-^
            //
            //   or in other words, iff !(S <= E <= X)
            if end >= start && end <= x {
                return false;
            }
        }
        Ordering::Greater => {
            // we have the opposite of above::
            //
            //   0 |----------X-----S--------| (wraparound)
            //
            // X is between S and E (S < X < E) only in this cases:
            //
            //   0 |----------X--E--S--------| (wraparound)
            //
            // but not in these cases
            //
            //   0 |----------X-----S---E----| (wraparound)
            //
            //   0 |------E---X-----S--------| (wraparound)
            //
            //   0 |----------|-----S--------| (wraparound)
            //                ^-X+E
            //
            //   0 |----------X-----|--------| (wraparound)
            //                  S+E-^
            //
            //   or, in other words, iff S < E < X
            if end < start && end > x {
            } else {
                return false;
            }
        }
    }
    true
}
