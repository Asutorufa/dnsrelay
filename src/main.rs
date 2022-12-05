use dnsrelay::netlink;
use netlink_packet_sock_diag::constants::*;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn main() {
    let args: Vec<_> = std::env::args().collect();

    let host_i = args
        .iter()
        .position(|r| r == "-host" || r == "-s" || r == "--host")
        .expect("can't find host arguments");
    let target_i = args
        .iter()
        .position(|r| r == "-target" || r == "-t" || r == "--target")
        .expect("can't find target argument");

    let host = args.get(host_i + 1).expect("get host failed");
    let target = args.get(target_i + 1).expect("get target failed");

    println!("Hello, world!,{:?},{:?}", host, target);
    listener(host, target).unwrap();
}

fn listener(host: &str, target_addr: &str) -> std::io::Result<()> {
    let socket = UdpSocket::bind(host)?;
    let target: SocketAddr = target_addr.parse().expect("parse target addr failed");

    loop {
        let mut buf = [0; 2048];
        let (amt, src) = socket.recv_from(&mut buf).expect("recv data failed");

        let socket_clone = socket.try_clone().expect("clone self socket failed");
        thread::spawn(move || {
            match netlink::dump_process(IPPROTO_UDP, src.ip(), src.port()) {
                Ok(process) => println!("recv {} data from {},{}", amt, src, process),
                Err(e) => println!("dump process failed: {}", e),
            };
            match handle(&mut buf[..amt], src, socket_clone, target) {
                Ok(_) => {}
                Err(e) => println!("{}", e),
            }
        });
    }
}

fn handle(
    buf: &mut [u8],
    src: SocketAddr,
    socket: UdpSocket,
    target: SocketAddr,
) -> std::io::Result<()> {
    let client =
        UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).expect("bind dns client socket failed");

    client.set_write_timeout(Some(Duration::from_secs(10)))?;

    client
        .send_to(buf, target)
        .expect("send data to dns server failed");

    let mut buf = [0; 2048];
    client.set_read_timeout(Some(Duration::from_secs(10)))?;
    let (amt, _) = client
        .recv_from(&mut buf)
        .expect("recv data from dns server failed");

    socket
        .send_to(&mut buf[..amt], src)
        .expect("send relay data to client");
    Ok(())
}

fn listenerTCP(host: &str, target: &str) -> std::io::Result<()> {
    let r = TcpListener::bind(host)?;
    let target_addr: SocketAddr = target.parse().unwrap();
    loop {
        let (conn, addr) = r.accept().expect("accept failed");
        println!("new connection from {}", addr);
        thread::spawn(move || {
            let t = TcpStream::connect(target_addr).expect("connect to target failed");
            handle_conn(conn, t);
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
