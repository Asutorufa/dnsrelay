use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
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
            match handle(&mut buf[..amt], src, socket_clone, target) {
                Ok(_) => {}
                Err(e) => println!("{}", e),
            }
            println!("recv {} data from {}", amt, src);
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
