use ya_relay_stack::packet::{EtherField, IpPacket, IpV4Field, PeekPacket};
use ya_relay_stack::Error;

//todo implement proper subnet translation, not only 255.255.255.0
//returns sum for fixup of checksum
fn translate_address(addr: &mut [u8], src_subnet: &[u8; 4], dst_subnet: &[u8; 4]) -> u32 {
    let before_translation_1 = u16::from_be_bytes([addr[0], addr[1]]);
    let before_translation_2 = u16::from_be_bytes([addr[2], addr[3]]);
    if addr[0] == src_subnet[0] && addr[1] == src_subnet[1] && addr[2] == src_subnet[2] {
        addr[0] = dst_subnet[0];
        addr[1] = dst_subnet[1];
        addr[2] = dst_subnet[2];
    }
    let after_translation_1 = u16::from_be_bytes([addr[0], addr[1]]);
    let after_translation_2 = u16::from_be_bytes([addr[2], addr[3]]);
    //returns sum that is used for fixup of checksums
    !before_translation_1 as u32
        + !before_translation_2 as u32
        + after_translation_1 as u32
        + after_translation_2 as u32
}

pub fn translate_packet(
    protocol: u8,
    payload_off: usize,
    packet_bytes: &mut [u8],
    src_subnet: &[u8; 4],
    dst_subnet: &[u8; 4],
) -> Result<(), Error> {
    let mut fixup_sum = 0_u32;
    fixup_sum += translate_address(
        &mut packet_bytes[IpV4Field::SRC_ADDR],
        src_subnet,
        dst_subnet,
    );
    fixup_sum += translate_address(
        &mut packet_bytes[IpV4Field::DST_ADDR],
        src_subnet,
        dst_subnet,
    );

    fix_packet_checksum(&mut packet_bytes[IpV4Field::CHECKSUM], fixup_sum);
    match protocol {
        0x01 => {
            //icmp protocol
        }
        0x06 => {
            let tcp_bytes = &mut packet_bytes[payload_off..];
            //tcp protocol checksum
            if tcp_bytes.len() < 20 {
                return Err(Error::Other(
                    "Error when wrapping IP packet: TCP packet too short".into(),
                ));
            }
            fix_packet_checksum(&mut tcp_bytes[16..18], fixup_sum);
            //https://blogs.igalia.com/dpino/2018/06/14/fast-checksum-computation/
        }
        0x11 => {
            //udp protocol
            let udp_bytes = &mut packet_bytes[payload_off..];
            if udp_bytes.len() < 8 {
                return Err(Error::Other(
                    "Error when wrapping IP packet: UDP packet too short".into(),
                ));
            }
            fix_packet_checksum(&mut udp_bytes[6..8], fixup_sum);
        }
        _ => {}
    }
    return Ok(());
}

pub fn packet_ip_wrap_to_ether(
    frame: &[u8],
    src_mac: Option<&[u8; 6]>,
    dst_mac: Option<&[u8; 6]>,
    src_subnet: Option<&[u8; 4]>,
    dst_subnet: Option<&[u8; 4]>,
) -> Result<Vec<u8>, Error> {
    if frame.is_empty() {
        return Err(Error::Other(
            "Error when wrapping IP packet: Empty packet".into(),
        ));
    }
    if let Err(err) = IpPacket::peek(frame) {
        return Err(Error::PacketMalformed(format!(
            "Error when wrapping IP packet {err}"
        )));
    }

    let mut eth_packet = vec![0u8; frame.len() + 14];
    if let Some(dst_mac) = dst_mac {
        eth_packet[EtherField::DST_MAC].copy_from_slice(dst_mac);
    } else {
        const DEFAULT_DST_MAC: &[u8; 6] = &[0x02, 0x02, 0x02, 0x02, 0x02, 0x02];
        eth_packet[EtherField::DST_MAC].copy_from_slice(DEFAULT_DST_MAC);
    }
    if let Some(src_mac) = src_mac {
        eth_packet[EtherField::SRC_MAC].copy_from_slice(src_mac);
    } else {
        const DEFAULT_SRC_MAC: &[u8; 6] = &[0x01, 0x01, 0x01, 0x01, 0x01, 0x01];
        eth_packet[EtherField::SRC_MAC].copy_from_slice(DEFAULT_SRC_MAC);
    }
    eth_packet[EtherField::PAYLOAD].copy_from_slice(&frame[0..]);
    match IpPacket::packet(frame) {
        IpPacket::V4(pkt) => {
            const ETHER_TYPE_IPV4: &[u8; 2] = &[0x08, 0x00];
            eth_packet[EtherField::ETHER_TYPE].copy_from_slice(ETHER_TYPE_IPV4);
            if let (Some(src_subnet), Some(dst_subnet)) = (src_subnet, dst_subnet) {
                translate_packet(
                    pkt.protocol,
                    pkt.payload_off,
                    &mut eth_packet[14..],
                    src_subnet,
                    dst_subnet,
                )?;
            }
        }
        IpPacket::V6(_pkt) => {
            const ETHER_TYPE_IPV6: &[u8; 2] = &[0x86, 0xdd];
            eth_packet[EtherField::ETHER_TYPE].copy_from_slice(ETHER_TYPE_IPV6);
        }
    };
    Ok(eth_packet)
}

pub fn fix_packet_checksum(checksum_bytes: &mut [u8], modify_sum: u32) {
    //https://www.rfc-editor.org/rfc/rfc1624
    //HC' = ~(~HC + ~m + m')
    let old_checksum = u16::from_be_bytes([checksum_bytes[0], checksum_bytes[1]]);
    let mut sum_f = (!old_checksum as u32) + modify_sum;
    while sum_f >> 16 != 0 {
        sum_f = (sum_f >> 16) + (sum_f & 0xffff);
    }
    checksum_bytes[0..2].copy_from_slice(&(!sum_f as u16).to_be_bytes());
}

pub fn packet_ether_to_ip_slice<'a, 'b>(
    eth_packet: &'a mut [u8],
    src_subnet: Option<&'b [u8; 4]>,
    dst_subnet: Option<&'b [u8; 4]>,
) -> Result<&'a mut [u8], Error> {
    const MIN_IP_HEADER_LENGTH: usize = 20;
    if eth_packet.len() <= 14 + MIN_IP_HEADER_LENGTH {
        return Err(Error::Other(format!(
            "Error when creating IP packet from ether packet: Packet too short. Packet length {}",
            eth_packet.len()
        )));
    }

    let ip_frame = &mut eth_packet[EtherField::PAYLOAD];
    if let Err(err) = IpPacket::peek(ip_frame) {
        return Err(Error::PacketMalformed(format!(
            "Error when creating IP packet from ether packet {err}"
        )));
    } else {
        match IpPacket::packet(ip_frame) {
            IpPacket::V4(pkt) => {
                if let (Some(src_subnet), Some(dst_subnet)) = (src_subnet, dst_subnet) {
                    translate_packet(
                        pkt.protocol,
                        pkt.payload_off,
                        ip_frame,
                        src_subnet,
                        dst_subnet,
                    )?;
                }
            }
            IpPacket::V6(_pkt) => {
                //todo handle ipv6
            }
        };
    }
    Ok(ip_frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ya_relay_stack::packet::IpV4Packet;

    /// Computes the checksum of an IPv4 packet in place. Not used because we are using incremental checksums.
    #[allow(dead_code)]
    pub fn compute_ipv4_checksum_in_place(bytes: &mut [u8]) {
        let packet_len = IpV4Packet::read_header_len(bytes);
        if bytes.len() < packet_len {
            log::warn!(
                "Error when computing IPv4 checksum: Packet too short. Packet length {}",
                bytes.len()
            );
            return;
        }

        let mut sum_f: u32 = 0;
        for i in 0..(packet_len / 2) {
            let byte_no = i * 2;
            if byte_no == 10 {
                //do not add checksum field
                continue;
            }
            let u16val = u16::from_be_bytes([bytes[byte_no], bytes[byte_no + 1]]);
            sum_f += u16val as u32;
        }
        while sum_f >> 16 != 0 {
            sum_f = (sum_f >> 16) + (sum_f & 0xffff);
        }
        let sum_f = (sum_f ^ 0xffff) as u16;
        bytes[IpV4Field::CHECKSUM].copy_from_slice(&u16::to_be_bytes(sum_f));
    }

    #[test]
    fn test_packet_ether_to_ip() {
        let mut valid_ether_packet = hex::decode("51bd2c1e5c202423d4418ef108004500002800010000401175ba0d0f1112717375765b941a850014476f48656c6c6f205061636b6574").unwrap();
        let valid_ip_packet = hex::decode(
            "4500002800010000401175ba0d0f1112717375765b941a850014476f48656c6c6f205061636b6574",
        )
        .unwrap();

        assert_eq!(
            hex::encode(valid_ip_packet),
            hex::encode(
                packet_ether_to_ip_slice(valid_ether_packet.as_mut_slice(), None, None).unwrap()
            )
        );
    }

    #[test]
    fn test_packet_ip_to_ether() {
        let valid_ip_packet = hex::decode(
            "4500002800010000401175ba0d0f1112717375765b941a850014476f48656c6c6f205061636b6574",
        )
        .unwrap();
        let valid_ether_packet = hex::decode("02020202020201010101010108004500002800010000401175ba0d0f1112717375765b941a850014476f48656c6c6f205061636b6574").unwrap();

        assert_eq!(
            hex::encode(&valid_ether_packet),
            hex::encode(packet_ip_wrap_to_ether(&valid_ip_packet, None, None, None, None).unwrap())
        );

        let valid_ether_packet2 = hex::decode("51bd2c1e5c202423d4418ef108004500002800010000401175ba0d0f1112717375765b941a850014476f48656c6c6f205061636b6574").unwrap();

        const SRC_MAC: &[u8; 6] = &[0x24, 0x23, 0xd4, 0x41, 0x8e, 0xf1];
        const DST_MAC: &[u8; 6] = &[0x51, 0xbd, 0x2c, 0x1e, 0x5c, 0x20];
        assert_eq!(
            hex::encode(&valid_ether_packet2),
            hex::encode(
                packet_ip_wrap_to_ether(&valid_ip_packet, Some(SRC_MAC), Some(DST_MAC), None, None)
                    .unwrap()
            )
        );
    }

    #[test]
    fn test_packet_translation() {
        {
            let mut packet_ether = hex::decode("a09fde7187fea09fde7187fe080045000028000100004011758a0d0f1142717375765b941a850014473f48656c6c6f205061636b6574").unwrap();
            let packet_ip_after_translation = hex::decode(
                "450000280001000040116f8711121342717375765b941a850014413c48656c6c6f205061636b6574",
            )
            .unwrap();

            let packet_out = packet_ether_to_ip_slice(
                packet_ether.as_mut_slice(),
                Some(&[13, 15, 17, 0]),
                Some(&[17, 18, 19, 0]),
            )
            .unwrap();
            assert_eq!(
                hex::encode(&packet_ip_after_translation),
                hex::encode(packet_out)
            );
        }
    }
}
