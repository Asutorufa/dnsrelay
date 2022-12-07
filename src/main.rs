use dns_parser::Packet;
use dnsrelay::netlink;
use netlink_packet_sock_diag::constants::*;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::thread;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();

    let check_arg = |r: &str, b: &str| -> bool {
        return r == format!("-{}", b)
            || r == format!("--{}", b)
            || r == format!("-{}", b.chars().nth(0).unwrap());
    };

    let host = args
        .get(args.iter().position(|r| check_arg(r, "host")).unwrap() + 1)
        .unwrap()
        .to_string();
    let target = args
        .get(args.iter().position(|r| check_arg(r, "target")).unwrap() + 1)
        .unwrap()
        .to_string();

    println!("listen at {:?}, relay to {:?}", host, target);

    let (host_tcp, target_tcp) = (host.clone(), target.clone());
    thread::spawn(move || {
        if let Err(e) = listener_tcp(host_tcp.as_str(), target_tcp.as_str()) {
            println!("listener tcp failed: {}", e)
        }
    });

    listener_udp(host.as_str(), target.as_str())?;

    Ok(())
}

fn listener_udp(host: &str, target_addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind(host)?;
    let target: SocketAddr = target_addr.parse()?;

    loop {
        let mut buf = [0; 2048];
        let (amt, src) = socket.recv_from(&mut buf)?;

        let socket_clone = socket.try_clone()?;
        thread::spawn(move || {
            let process =
                netlink::dump_process(IPPROTO_UDP, src).unwrap_or("dump_process err".to_owned());
            let (qname, qtype) = parse_request(&buf[..amt]);
            println!(
                "recv {} udp data to resolve {}({:?}) from {}({})",
                amt, qname, qtype, src, process
            );

            if let Err(e) = handle_udp(&mut buf, amt, src, socket_clone, target) {
                println!("relay to failed: {}", e);
            }
        });
    }
}

fn handle_udp(
    buf: &mut [u8],
    amt: usize,
    src: SocketAddr,
    socket: UdpSocket,
    target: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    client.set_write_timeout(Some(Duration::from_secs(10)))?;
    client.send_to(&buf[..amt], target)?;

    client.set_read_timeout(Some(Duration::from_secs(10)))?;
    let (amt, _) = client.recv_from(buf)?;
    socket.send_to(&buf[..amt], src)?;
    Ok(())
}

fn listener_tcp(host: &str, target: &str) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(host)?;
    let target_addr: SocketAddr = target.parse()?;

    for conn in listener.incoming() {
        let conn = conn?;
        thread::spawn(move || {
            if let Ok(target_conn) = TcpStream::connect(target_addr) {
                if let Err(e) = handle_conn(conn, target_conn) {
                    println!("handle conn failed: {}", e)
                }
            }
        });
    }
    Ok(())
}

fn handle_conn(
    mut lhs_stream: TcpStream,
    mut rhs_stream: TcpStream,
) -> Result<(), Box<dyn std::error::Error>> {
    lhs_stream.set_read_timeout(Some(Duration::new(30, 0)))?;
    let mut size_buf = [0, 2];
    lhs_stream.read(&mut size_buf)?;
    let size = u16::from_be_bytes(size_buf.try_into()?);
    let mut request = vec![0; size.into()];
    lhs_stream.read(&mut request)?;

    let process = netlink::dump_process(IPPROTO_TCP, lhs_stream.peer_addr()?)
        .unwrap_or("dump_process err".to_owned());
    let (qname, qtype) = parse_request(&request);
    println!(
        "recv {} tcp data to resolve {}({:?}) from {}({})",
        size,
        qname,
        qtype,
        lhs_stream.peer_addr()?,
        process
    );

    rhs_stream.write(&size_buf)?;
    rhs_stream.write(&request)?;

    rhs_stream.set_read_timeout(Some(Duration::new(30, 0)))?;
    rhs_stream.read(&mut size_buf)?;
    let size = u16::from_be_bytes(size_buf.try_into()?);
    let mut response = vec![0; size.into()];
    rhs_stream.read(&mut response)?;

    lhs_stream.write(&size_buf)?;
    lhs_stream.write(&mut response)?;

    Ok(())
}

fn parse_request(data: &[u8]) -> (String, dns_parser::QueryType) {
    let (qname, qtype) = match Packet::parse(&data) {
        Ok(v) => {
            if v.questions.len() == 1 {
                (String::from(""), dns_parser::QueryType::All);
            }
            (v.questions[0].qname.to_string(), v.questions[0].qtype)
        }
        Err(e) => {
            println!("parse dns request failed: {}", e);
            (String::from(""), dns_parser::QueryType::All)
        }
    };

    return (qname, qtype);
}
