use std::env;
use std::thread;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicBool, Ordering};

use ctrlc;
use chrono;
use pcap::{Capture};

#[derive(Clone, Hash, Eq, PartialEq, Debug)]
struct Flow {
    layer4_protocol: u16,
    client_ip: Vec<u8>,
    server_ip: Vec<u8>,
    client_port: u16,
    server_port: u16
}

fn main()  {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: {} <interface> <capturing_time> (s) <output_folder>", args[0]);
        return;
    }

    let interface = args[1].clone();
    let mut cap = Capture::from_device(interface.as_str())
        .unwrap()
        .promisc(true)
        .snaplen(65535)
        .open()
        .expect("Failed to open capture interface");


    let tls_flow_tracker = Arc::new(Mutex::new(HashMap::<Flow, (u8, u8, Instant)>::new()));
    let tracker_clone = Arc::clone(&tls_flow_tracker);

    // Output pcap file management
    println!("UTC Timestamp: {}", chrono::Utc::now());
    let output_pcap = Arc::new(Mutex::new(
        cap.savefile(format!("{}/{}.pcap", &args[3], chrono::offset::Utc::now().to_string().split(".").next().unwrap()))
            .expect("Failed to create output pcap"),
    ));
    let output_pcap_clone = Arc::clone(&output_pcap);
    let output_folder = args[3].clone();

    if !std::path::Path::new(&output_folder).exists() {
        std::fs::create_dir_all(&output_folder).expect("Failed to create output folder");
    }

    // Spawn a thread to create new pcap file and remove idle flows per N seconds
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(args[2].parse::<u64>().unwrap_or(60)));
            let mut output_pcap_guard = output_pcap_clone.lock().unwrap();
            // Create a new savefile using a fresh Capture handle
            let new_cap = Capture::from_device(interface.as_str())
                .unwrap()
                .promisc(true)
                .snaplen(65535)
                .open()
                .expect("Failed to open capture interface");
            *output_pcap_guard = new_cap.savefile(format!("{}/{}.pcap", output_folder, chrono::offset::Utc::now().to_string().split(".").next().unwrap()))
                .expect("Failed to create output pcap");

            let mut tracker = tracker_clone.lock().unwrap();
            let now = Instant::now();
            tracker.retain(|_, &mut (_, _, last_seen)| now.duration_since(last_seen) < Duration::from_secs(args[2].parse::<u64>().unwrap_or(60))); // Remove idle flows

        }
    });

     /* Initialize CTRL-C handler to stop loop */
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
        println!("Ctrl+C pressed.");
    }).expect("Error setting Ctrl-C handler");

    println!("Press CTRC-C to gracefully stop it\n");
    while running.load(Ordering::SeqCst) {
        if let Ok(packet) = cap.next_packet() {
            if packet.data.len() < 14 {
                continue;
            }
            let mut ethertype = u16::from_be_bytes([packet.data[12], packet.data[13]]);
            let mut offset = 14;

            if ethertype == 0x8100 {
                if packet.data.len() < offset + 4 {
                    continue;
                }
                let _vlan_id = Some(u16::from_be_bytes([packet.data[offset], packet.data[offset + 1]]) & 0x0FFF);
                ethertype = u16::from_be_bytes([packet.data[offset + 2], packet.data[offset + 3]]);
                offset += 4;
            }

            // IPv4 or IPv6
            let (ip_proto, ip_payload_offset, client_ip, server_ip) = match ethertype {
                0x0800 => { 
                    if packet.data.len() < offset + 20 {
                        continue;
                    }
                    let ihl = (packet.data[offset] & 0x0F) as usize * 4;
                    let proto = packet.data[offset + 9];
                    let src_ip = &packet.data[offset + 12..offset + 16];
                    let dst_ip = &packet.data[offset + 16..offset + 20];
                    (proto, offset + ihl, src_ip.to_vec(), dst_ip.to_vec())
                }
                0x86DD => { 
                    if packet.data.len() < offset + 40 {
                        continue;
                    }
                    let proto = packet.data[offset + 6];
                    let src_ip = &packet.data[offset + 8..offset + 24];
                    let dst_ip = &packet.data[offset + 24..offset + 40];
                    (proto, offset + 40, src_ip.to_vec(), dst_ip.to_vec())
                }
                _ => {
                    continue;
                }
            };

            if ip_proto == 6 {
                if packet.data.len() < ip_payload_offset + 20 {
                    continue;
                }
                let src_port = u16::from_be_bytes([
                    packet.data[ip_payload_offset],
                    packet.data[ip_payload_offset + 1],
                ]);
                let dst_port = u16::from_be_bytes([
                    packet.data[ip_payload_offset + 2],
                    packet.data[ip_payload_offset + 3],
                ]);
                let data_offset = ((packet.data[ip_payload_offset + 12] >> 4) * 4) as usize;
                let tcp_payload_offset = ip_payload_offset + data_offset;
                if packet.data.len() < tcp_payload_offset {
                    continue;
                }
                let tcp_payload = &packet.data[tcp_payload_offset..];

                // Fill Flow struct
                let flow = Flow {
                    layer4_protocol: ip_proto as u16,
                    client_ip: client_ip.clone(),
                    server_ip: server_ip.clone(),
                    client_port: src_port,
                    server_port: dst_port,
                };

                let mut tracker = tls_flow_tracker.lock().unwrap();
                if tcp_payload.len() > 5 && tcp_payload[0] == 0x16 && tcp_payload[5] == 0x01 {
                    if !tracker.contains_key(&flow) {
                        println!("New TLS flow detected: {:?}", flow);
                        tracker.insert(flow.clone(), (tcp_payload[1], tcp_payload[2], Instant::now()));
                        output_pcap.lock().unwrap().write(&packet);
                    }
                }

                if tracker.contains_key(&flow) {
                    let version = tracker.get(&flow).unwrap();
                    if tcp_payload.len() > 5 && (tcp_payload[0] == 0x14 || tcp_payload[0] == 0x17) && ((tcp_payload[1], tcp_payload[2]) == (version.0, version.1)){
                        tracker.remove(&flow);
                    }else{
                        output_pcap.lock().unwrap().write(&packet);
                    }
                }
            }       
        }
    }
}
