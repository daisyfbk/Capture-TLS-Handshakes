use std::thread;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicBool, Ordering};

use ctrlc;
use chrono;
use clap::Parser;
use pcap::{Capture};


const CLEAR_OLD_ENTRIES_TIMER: u64 = 60;

// Sizes in bytes
const ETH_SIZE: usize = 14;
const IPV4_MIN_SIZE: usize = 20;
const IPV6_SIZE: usize = 40;
const TCP_MIN_SIZE: usize = 20;
const TLS_RECORD_SIZE: usize = 5;

// Protocol values, TCP Flags and TLS values
const VLAN: u16 = 0x8100;
const IPV4: u16 = 0x0800;
const IPV6: u16 = 0x86DD;
const TCP: u8 = 0x06;

const TCP_FIN: u8 = 0x01;
const TCP_RST: u8 = 0x04;

const TLS_CCS_RECORD: u8 = 0x14;
const TLS_ALERT_RECORD: u8 = 0x15;
const TLS_HANDSHAKE_RECORD: u8 = 0x16;
const TLS_DATA_RECORD: u8 = 0x17;

const TLS_CLIENT_HELLO: u8 = 0x01;
const TLS_SERVER_HELLO: u8 = 0x02;



#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    interface: String,

    #[arg(short, long)]
    output_folder: String,

    #[arg(short, long, default_value_t = 443)]
    port_to_monitor: u16,

    #[arg(short, long, default_value_t = 60)]
    capturing_time: u64,
}


#[derive(Clone, Hash, Eq, PartialEq, Debug)]
struct Flow {
    layer4_protocol: u16,
    client_ip: Vec<u8>,
    server_ip: Vec<u8>,
    client_port: u16,
    server_port: u16
}

const POSSIBLE_VERSIONS: [usize; 11] = [0x0300, 0x0301, 0x0302, 0x0303, 0x0304, 0x101, 0x7f17, 0xfb17, 0x7f1a, 0xfb1a, 0x7f1c];
const BITMAP_POSSIBLE_VERSIONS: [bool; 65536] = {
    let mut array = [false; 65536];
    let mut i = 0;
    while i < POSSIBLE_VERSIONS.len() {
        array[POSSIBLE_VERSIONS[i]] = true;
        i += 1;
    }
    array
};


fn main()  {
    let args = Args::parse();

    let mut cap = Capture::from_device(args.interface.as_str())
        .unwrap()
        .promisc(true)
        .immediate_mode(true)
        .snaplen(262144)
        .open()
        .expect("Failed to open capture interface")
        .setnonblock()
        .unwrap();
    let linktype = cap.get_datalink();

    // Tracking handshakes and saving packets
    let mut tls_flow_tracker = HashMap::<Flow, (u8, u8, Instant)>::new();
    let mut reset_tracker = Instant::now();

    if !std::path::Path::new(&args.output_folder).exists() {
        std::fs::create_dir_all(&args.output_folder).expect("Failed to create output folder");
    }

    let filename: String = chrono::offset::Utc::now().to_string().split(".").next().unwrap().replace(":", "-").replace(" ", "__");
    let output_pcap = Arc::new(Mutex::new(
        cap.savefile(format!("{}/log_{}.pcap", args.output_folder, filename))
            .expect("Failed to create output pcap"),
    ));
    let output_pcap_clone = Arc::clone(&output_pcap);

    // Spawn a thread to create new pcap file and remove idle flows per N seconds
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(args.capturing_time));
            let mut output_pcap_guard = output_pcap_clone.lock().unwrap();

            let filename: String = chrono::offset::Utc::now().to_string().split(".").next().unwrap().replace(":", "-").replace(" ", "__");
            *output_pcap_guard = Capture::dead(linktype).unwrap()
                                    .savefile(format!("{}/log_{}.pcap", args.output_folder, filename))
                                    .expect("Failed to create output pcap");
        }
    });

     /* Initialize CTRL-C handler to stop loop */
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
        println!("Ctrl+C pressed.");
    }).expect("Error setting Ctrl-C handler");

    println!("Starting capture on interface: {}", args.interface);
    println!("Press CTRC-C to gracefully stop it\n");

    // Main loop to process packets
    while running.load(Ordering::SeqCst) {
        if let Ok(packet) = cap.next_packet() {
            if packet.data.len() < ETH_SIZE {
                continue;
            }
            let mut ethertype = u16::from_be_bytes([packet.data[12], packet.data[13]]);
            let mut offset = ETH_SIZE;

            // Read VLAN header
            if ethertype == VLAN {
                if packet.data.len() < offset + 4 {
                    continue;
                }
                ethertype = u16::from_be_bytes([packet.data[offset + 2], packet.data[offset + 3]]); // Capture Layer 3 proto
                offset += 4;
            }

            // Parse IPv4 or IPv6
            let (ip_proto, len_after_ip,  ip_payload_offset, client_ip, server_ip) = match ethertype {
                IPV4 => { 
                    if packet.data.len() < offset + IPV4_MIN_SIZE {
                        continue;
                    }
                    let len = u16::from_be_bytes([packet.data[offset + 2], packet.data[offset + 3]]) as usize;
                    let ihl = (packet.data[offset] & 0x0F) as usize * 4;
                    let proto = packet.data[offset + 9];
                    let src_ip = &packet.data[offset + 12..offset + 16];
                    let dst_ip = &packet.data[offset + 16..offset + 20];
                    (proto, len - ihl, offset + ihl, src_ip.to_vec(), dst_ip.to_vec())
                }
                IPV6 => { 
                    if packet.data.len() < offset + IPV6_SIZE {
                        continue;
                    }
                    let len = u16::from_be_bytes([packet.data[offset + 4], packet.data[offset + 5]]) as usize;
                    let proto = packet.data[offset + 6];
                    let src_ip = &packet.data[offset + 8..offset + 24];
                    let dst_ip = &packet.data[offset + 24..offset + 40];
                    (proto, len - IPV6_SIZE, offset + IPV6_SIZE, src_ip.to_vec(), dst_ip.to_vec())
                }
                _ => {
                    continue;
                }
            };

            // Only TCP and no parsing of IPv6 extension for now
            if ip_proto == TCP {
                if packet.data.len() < ip_payload_offset + TCP_MIN_SIZE {
                    continue;
                }

                let src_port = u16::from_be_bytes([packet.data[ip_payload_offset], packet.data[ip_payload_offset + 1]]);
                let dst_port = u16::from_be_bytes([packet.data[ip_payload_offset + 2], packet.data[ip_payload_offset + 3]]);

                // Only track flows with TLS port (443)
                if src_port != args.port_to_monitor && dst_port != args.port_to_monitor {
                    continue;
                }

                let tcp_flags = packet.data[ip_payload_offset + 13];

                let tcp_header_size = ((packet.data[ip_payload_offset + 12] >> 4) * 4) as usize;
                let tcp_payload_offset = ip_payload_offset + tcp_header_size;
                if packet.data.len() < tcp_payload_offset {
                    continue;
                }

                let tcp_payload = &packet.data[tcp_payload_offset..];
                let tcp_payload_len = len_after_ip - tcp_header_size; // Len from IP header - IP header size - TCP header size

                // No payload and not TCP connection ending go to the next packet
                if tcp_payload_len == 0 && (tcp_flags & TCP_FIN != TCP_FIN || tcp_flags & TCP_RST != TCP_RST) {
                    continue;
                }

                let flow = Flow {
                    layer4_protocol: ip_proto as u16,
                    client_ip: client_ip.clone(),
                    server_ip: server_ip.clone(),
                    client_port: src_port,
                    server_port: dst_port,
                };

                // Check if is a Client Hello and save the Handshake version
                if tcp_payload_len > 10 && tcp_payload[0] == TLS_HANDSHAKE_RECORD && tcp_payload[5] == TLS_CLIENT_HELLO
                    && BITMAP_POSSIBLE_VERSIONS[u16::from_be_bytes([tcp_payload[1], tcp_payload[2]]) as usize]
                    && BITMAP_POSSIBLE_VERSIONS[u16::from_be_bytes([tcp_payload[9], tcp_payload[10]]) as usize]  {
                    if !tls_flow_tracker.contains_key(&flow) {
                        let now = Instant::now();
                        tls_flow_tracker.insert(flow.clone(), (tcp_payload[9], tcp_payload[10], now));
                        tls_flow_tracker.insert(inverse_flow.clone(), (tcp_payload[9], tcp_payload[10], now));
                        output_pcap.lock().unwrap().write(&packet);
                        continue;
                    }
                }

                let inverse_flow = Flow {
                    layer4_protocol: ip_proto as u16,
                    client_ip: server_ip.clone(),
                    server_ip: client_ip.clone(),
                    client_port: dst_port,
                    server_port: src_port,
                };

                let mut flow_exists = false;
                let tls_version = match tls_flow_tracker.get(&flow) {
                    Some(&(first, second, _)) => {
                        flow_exists = true;
                        (first, second)
                    },
                    None => match tls_flow_tracker.get(&inverse_flow) {
                        Some(&(first, second, _)) => {
                            flow_exists = true;
                            (first, second)
                        },
                        None => (0, 0),
                    },
                };
                
                if flow_exists{
                    // If it is a TCP packet with FIN/RST flag stop monitoring (Safety measure to remove flows)
                    if tcp_flags & TCP_FIN == TCP_FIN || tcp_flags & TCP_RST == TCP_RST {
                        tls_flow_tracker.remove(&flow);
                        tls_flow_tracker.remove(&inverse_flow);
                    }else if tcp_payload_len > TLS_RECORD_SIZE{
                        let mut save_pkt = true; // By default, packets for a tracked flow should be fowarded
                        let mut tls_offset: usize = 0;
                        if tcp_payload[0] == TLS_HANDSHAKE_RECORD && tcp_payload[5] == TLS_SERVER_HELLO && ((tcp_payload[1], tcp_payload[2]) == (tls_version.0, tls_version.1)){
                            tls_offset = u16::from_be_bytes([tcp_payload[3], tcp_payload[4]]) as usize + TLS_RECORD_SIZE; // Go past Server Hello
                             // There is no record data after the server hello, save packet and continue to the next one
                            if tls_offset + 2 >= tcp_payload_len{
                                output_pcap.lock().unwrap().write(&packet);
                                continue;
                            }
                        } 

                        // If packet begins or has after the Server Hello a non-Handshake Record, stop capturing packets
                        if (tcp_payload[tls_offset] == TLS_CCS_RECORD || tcp_payload[tls_offset] == TLS_ALERT_RECORD || tcp_payload[tls_offset] == TLS_DATA_RECORD) && 
                            ((tcp_payload[tls_offset + 1], tcp_payload[tls_offset + 2]) == (tls_version.0, tls_version.1)){
                            tls_flow_tracker.remove(&flow);
                            tls_flow_tracker.remove(&inverse_flow);

                            // Save the packet if it had a Server Hello
                            if tls_offset == 0{
                                save_pkt = false;
                            }
                        }
                        
                        if save_pkt{
                            output_pcap.lock().unwrap().write(&packet);
                        }
                    }

                }
            }       
        }

        // Clean HashMap of old entries 
        let now = Instant::now();
        if now.duration_since(reset_tracker) >  Duration::from_secs(CLEAR_OLD_ENTRIES_TIMER){
            tls_flow_tracker.retain(|_, &mut (_, _, last_seen)| now.duration_since(last_seen) < Duration::from_secs(CLEAR_OLD_ENTRIES_TIMER)); // Remove idle flows
            reset_tracker = now;
        }
    }

    let _result = match output_pcap.lock().unwrap().flush(){
        Ok(_) => {},
        Err(_error) => return,
    };
}
