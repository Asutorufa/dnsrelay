use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::thread;
use std::time::Duration;

use clap::{Arg, Command};

fn main() {
    let matches = cli().get_matches();
    let host = matches
        .get_one::<String>("host")
        .map(|s| s.as_str())
        .unwrap();
    let target = matches
        .get_one::<String>("target")
        .map(|s| s.as_str())
        .unwrap();
    println!("Hello, world!,{:?},{:?}", host, target);
    listener(host, target).unwrap();
}

fn listener(host: &str, target_addr: &str) -> std::io::Result<()> {
    let socket = UdpSocket::bind(host)?;

    let mut buf = [0; 2048];

    let target: SocketAddr = target_addr.parse().expect("parse target addr failed");
    loop {
        let socket_clone = socket.try_clone().expect("clone self socket failed");
        let (amt, src) = socket_clone.recv_from(&mut buf).expect("recv data failed");
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

fn cli() -> Command {
    Command::new("dnsrelay")
        .arg_required_else_help(true)
        .allow_external_subcommands(true)
        .arg(Arg::new("host").short('s').long("host"))
        .arg(Arg::new("target").short('t').long("target"))
}
