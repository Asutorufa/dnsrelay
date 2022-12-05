use netlink_packet_sock_diag::{
    constants::*,
    inet::{ExtensionFlags, InetRequest, SocketId, StateFlags},
    NetlinkHeader, NetlinkMessage, NetlinkPayload, SockDiagMessage,
};
use netlink_sys::{protocols::NETLINK_SOCK_DIAG, Socket, SocketAddr};
use std::net::{IpAddr, Ipv4Addr};
use std::{fs, os::linux::fs::MetadataExt};

pub fn dump_inode(
    network: u8,
    source_address: IpAddr,
    source_port: u16,
) -> Result<Box<netlink_packet_sock_diag::inet::InetResponse>, Box<dyn std::error::Error>> {
    let mut socket = Socket::new(NETLINK_SOCK_DIAG)?;
    let _port_nmber = socket.bind_auto()?.port_number();
    socket.connect(&SocketAddr::new(0, 0))?;

    let socket_id = SocketId {
        cookie: [0; 8],
        destination_address: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        source_address: source_address,
        destination_port: 0,
        source_port: source_port,
        interface_id: 0,
    };

    let mut packet = NetlinkMessage {
        header: NetlinkHeader {
            flags: NLM_F_REQUEST | NLM_F_DUMP,
            ..Default::default()
        },
        payload: SockDiagMessage::InetRequest(InetRequest {
            family: AF_INET,
            protocol: network,
            extensions: ExtensionFlags::empty(),
            states: StateFlags::all(),
            socket_id: socket_id,
        })
        .into(),
    };

    packet.finalize();

    let mut buf = vec![0; packet.header.length as usize];

    // Before calling serialize, it is important to check that the buffer in which we're emitting is big
    // enough for the packet, other `serialize()` panics.
    assert_eq!(buf.len(), packet.buffer_len());

    packet.serialize(&mut buf[..]);

    // let mut n_response: Box<netlink_packet_sock_diag::inet::InetResponse>;

    // println!(">>> {:?}", packet);

    if let Err(e) = socket.send(&buf[..], 0) {
        // println!("SEND ERROR {}", e);
        return Err(e.into());
    }

    let mut receive_buffer = vec![0; 4096];
    let mut offset = 0;
    while let Ok(size) = socket.recv(&mut &mut receive_buffer[..], 0) {
        loop {
            let bytes = &receive_buffer[offset..];
            let rx_packet = <NetlinkMessage<SockDiagMessage>>::deserialize(bytes).unwrap();
            // println!("<<< {:?}", rx_packet);

            match rx_packet.payload {
                NetlinkPayload::Noop | NetlinkPayload::Ack(_) => {}
                NetlinkPayload::InnerMessage(SockDiagMessage::InetResponse(response)) => {
                    return Ok(response);
                    // println!("{:#?},", response);
                }
                NetlinkPayload::Done => {
                    // println!("Done!");
                    return Err("Done!".into());
                }
                NetlinkPayload::Error(_) | NetlinkPayload::Overrun(_) | _ => {
                    return Err("Done!".into())
                }
            }

            offset += rx_packet.header.length as usize;
            if offset == size || rx_packet.header.length == 0 {
                offset = 0;
                break;
            }
        }
    }

    return Err("Done!".into());
}

pub fn find_proc(uid: u32, inode: u32) -> Result<String, Box<dyn std::error::Error>> {
    let paths = fs::read_dir("/proc")?;

    for path in paths {
        let path = path?.path();
        if !path.is_dir() {
            continue;
        };

        if !path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .chars()
            .all(char::is_numeric)
        {
            continue;
        }

        if path.metadata()?.st_uid() != uid {
            continue;
        }

        let process_path = format!("/proc/{}", path.file_name().unwrap().to_str().unwrap());
        let fds_path = format!("{}/fd", process_path);
        // println!("{}", fds_path);
        let fds = match fs::read_dir(fds_path.clone()) {
            Ok(v) => v,
            Err(_) => {
                // print!("{}/fd: {}", process_path, err);
                continue;
            }
        };

        for fd in fds {
            // println!("fd_path: {}", fd.path().to_str().unwrap(),);
            let fd_link = match fs::read_link(fd?.path().to_str().unwrap()) {
                Ok(v) => v,
                Err(_) => {
                    continue;
                }
            };

            // println!("fd_link: {}", fd_link.to_str().unwrap());

            if format!("socket:[{}]", inode) == fd_link.to_str().unwrap() {
                let process = fs::read_link(format!("{}/exe", process_path))?;
                // println!("process: {}", process.to_str().unwrap());
                return Ok(process.to_str().unwrap().to_string());
            }
        }
    }

    return Err("Not Find".into());
}

pub fn dump_process(
    network: u8,
    source_address: IpAddr,
    source_port: u16,
) -> Result<String, Box<dyn std::error::Error>> {
    let resp = dump_inode(network, source_address, source_port)?;
    return find_proc(resp.header.uid, resp.header.inode);
}
