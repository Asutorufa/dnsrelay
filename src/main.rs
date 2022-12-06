use dns_parser::Packet;
use dnsrelay::netlink;
use netlink_packet_sock_diag::constants::*;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn main() {
    let args: Vec<_> = std::env::args().collect();

    let check_arg = |r: &str, b: &str| -> bool {
        return r == format!("-{}", b)
            || r == format!("--{}", b)
            || r == format!("-{}", b.chars().nth(0).unwrap());
    };

    let host = args
        .get(args.iter().position(|r| check_arg(r, "host")).unwrap() + 1)
        .unwrap();
    let target = args
        .get(args.iter().position(|r| check_arg(r, "target")).unwrap() + 1)
        .unwrap();

    println!("listen at {:?}, relay to {:?}", host, target);
    listener(host, target).unwrap();
}

fn listener(host: &str, target_addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind(host)?;
    let target: SocketAddr = target_addr.parse()?;

    loop {
        let mut buf = [0; 2048];
        let (amt, src) = socket.recv_from(&mut buf)?;

        let socket_clone = socket.try_clone()?;
        thread::spawn(move || {
            let process =
                netlink::dump_process(IPPROTO_UDP, src).unwrap_or("dump_process err".to_owned());

            let (qname, qtype) = match Packet::parse(&buf[..amt]) {
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

            println!(
                "recv {} data to resolve {}({:?}) from {}({})",
                amt, qname, qtype, src, process
            );

            if let Err(e) = handle(&mut buf[..amt], src, socket_clone, target) {
                println!("relay to failed: {}", e);
            }
        });
    }
}

fn handle(
    buf: &mut [u8],
    src: SocketAddr,
    socket: UdpSocket,
    target: SocketAddr,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;

    client.set_write_timeout(Some(Duration::from_secs(10)))?;

    client.send_to(buf, target)?;

    let mut buf = [0; 2048];
    client.set_read_timeout(Some(Duration::from_secs(10)))?;
    let (amt, _) = client.recv_from(&mut buf)?;

    socket.send_to(&mut buf[..amt], src)?;
    Ok(())
}

fn listener_tcp(host: &str, target: &str) -> Result<(), Box<dyn std::error::Error>> {
    let r = TcpListener::bind(host)?;
    let target_addr: SocketAddr = target.parse()?;
    loop {
        let (conn, addr) = r.accept()?;
        println!("new connection from {}", addr);
        thread::spawn(move || {
            if let Ok(t) = TcpStream::connect(target_addr) {
                handle_conn(conn, t);
            }
        });
    }
}

fn handle_conn(lhs_stream: TcpStream, rhs_stream: TcpStream) {
    let lhs_arc = Arc::new(lhs_stream);
    let rhs_arc = Arc::new(rhs_stream);

    let (mut lhs_tx, mut lhs_rx) = (lhs_arc.try_clone().unwrap(), lhs_arc.try_clone().unwrap());
    let (mut rhs_tx, mut rhs_rx) = (rhs_arc.try_clone().unwrap(), rhs_arc.try_clone().unwrap());

    let connections = vec![
        thread::spawn(move || std::io::copy(&mut lhs_tx, &mut rhs_rx).unwrap()),
        thread::spawn(move || std::io::copy(&mut rhs_tx, &mut lhs_rx).unwrap()),
    ];

    for t in connections {
        t.join().unwrap();
    }
}
