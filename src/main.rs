use etherparse::{self, IpHeader, PacketHeaders};
use std::net;
use std::str;

fn main() {
    // pick an interface as returned by pcap_lookupdev or blow up
    let default_device = pcap::Device::lookup().unwrap();
    let mut cap = pcap::Capture::from_device(default_device)
        .unwrap()
        .open()
        .unwrap();

    // Using filter as this should be converted to a bpf filter. To test the validity, try the same
    // filter with tshark. For example,
    // tshark -i en0 -f "udp dst port 53"
    if let Err(v) = cap.filter("udp dst port 53", true) {
        println!("{:#?}", v);
    }

    while let Ok(packet) = cap.next() {
        parse_packet(&packet);
    }
}

fn parse_packet(packet: &pcap::Packet) {
    match PacketHeaders::from_ethernet_slice(packet.data) {
        Err(value) => println!("Err {:?}", value),
        Ok(value) => {
            let ip = match value.ip {
                Some(ip) => ip,
                None => return,
            };

            let transport = match value.transport {
                Some(t) => t,
                None => return,
            };

            if let Some((src_ip, dst_ip)) = parse_ip_header(&ip) {
                // Only parse UDP packets for now
                let udp = match transport.udp() {
                    Some(udp) => udp,
                    None => return,
                };

                let (src_port, dst_port) = parse_udp_header(&udp);
                match parse_dns_response(value.payload) {
                    Ok(h) => {
                        println!(
                            "{}:{} => {}:{} query = {}",
                            src_ip, src_port, dst_ip, dst_port, h
                        );
                    }
                    Err(e) => {
                        eprintln!("{}", e);
                    }
                };
            }
        }
    }
}

#[allow(dead_code)]
fn parse_ethernet_header(hdr: &etherparse::Ethernet2Header) {
    let source_mac = hdr
        .source
        .iter()
        .map(|b: &u8| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join(":");

    let dest_mac = hdr
        .destination
        .iter()
        .map(|b: &u8| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join(":");

    println!("{} => {}", source_mac, dest_mac);
}

fn parse_ip_header(ip_hdr: &etherparse::IpHeader) -> Option<(net::Ipv4Addr, net::Ipv4Addr)> {
    if let IpHeader::Version4(hdr, _) = ip_hdr {
        let source_ip =
            net::Ipv4Addr::new(hdr.source[0], hdr.source[1], hdr.source[2], hdr.source[3]);

        let dest_ip = net::Ipv4Addr::new(
            hdr.destination[0],
            hdr.destination[1],
            hdr.destination[2],
            hdr.destination[3],
        );

        return Some((source_ip, dest_ip));
    };

    None
}

fn parse_udp_header(udp: &etherparse::UdpHeader) -> (u16, u16) {
    (udp.source_port, udp.destination_port)
}

fn parse_dns_response(payload: &[u8]) -> Result<String, &'static str> {
    if payload.len() < 13 {
        // It should aleast have 12 octects of flags and the length octet for the payload
        return Err("malformed packet: len < 13");
    }

    let mut cnt = 12;
    let mut res: Vec<&str> = vec![];
    while cnt < payload.len() {
        let number_of_octets = payload[cnt];
        cnt += 1;
        if number_of_octets == 0x0 {
            break;
        }

        if cnt + (number_of_octets as usize) >= payload.len() {
            return Err("malformed packet: not enough bytes");
        }

        res.push(str::from_utf8(&payload[cnt..(cnt + number_of_octets as usize)]).unwrap());
        cnt += number_of_octets as usize;
    }

    Ok(res.join("."))
}
