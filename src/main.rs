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
    if args.len() != 5 {
        eprintln!("Usage: {} <interface> <port_to_monitor> <capturing_time> (s) <output_folder>", args[0]);
        return;
    }

    let interface = args[1].clone();
    println!("Starting capture on interface: {}", interface);
    let mut cap = Capture::from_device(interface.as_str())
        .unwrap()
        .promisc(true)
        .immediate_mode(true)
        .open()
        .expect("Failed to open capture interface")
        .setnonblock()
        .unwrap();

    let port_to_monitor: u16 = args[2].parse().unwrap_or(443);

    let tls_flow_tracker = Arc::new(Mutex::new(HashMap::<Flow, (u8, u8, Instant)>::new()));
    let tracker_clone = Arc::clone(&tls_flow_tracker);

    let output_folder = args.last().unwrap().clone();
    if !std::path::Path::new(&output_folder).exists() {
        std::fs::create_dir_all(&output_folder).expect("Failed to create output folder");
    }

    let output_pcap = Arc::new(Mutex::new(
        cap.savefile(format!("{}/{}.pcap", output_folder, chrono::offset::Utc::now().to_string().split(".").next().unwrap()))
            .expect("Failed to create output pcap"),
    ));
    let output_pcap_clone = Arc::clone(&output_pcap);

    // Spawn a thread to create new pcap file and remove idle flows per N seconds
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(args[2].parse::<u64>().unwrap_or(60)));
            let mut output_pcap_guard = output_pcap_clone.lock().unwrap();
            // Create a new savefile using a fresh Capture handle
            let new_cap = Capture::from_device(interface.as_str())
                .unwrap()
                .promisc(true)
                .immediate_mode(true)
                .open()
                .expect("Failed to open capture interface")
                .setnonblock()
                .unwrap();
            
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

                // Only track flows with TLS port (443)
                if src_port != port_to_monitor && dst_port != port_to_monitor {
                    continue;
                }

                let tcp_flags = packet.data[ip_payload_offset + 13];

                let data_offset = ((packet.data[ip_payload_offset + 12] >> 4) * 4) as usize;
                let tcp_payload_offset = ip_payload_offset + data_offset;
                if packet.data.len() < tcp_payload_offset {
                    continue;
                }

                let tcp_payload = &packet.data[tcp_payload_offset..];
                let tcp_payload_len = tcp_payload.len();

                // No payload and not end TCP connection
                if tcp_payload_len == 0 && (tcp_flags & 1 != 1 || tcp_flags & 4 != 4) {
                    continue;
                }

                let flow = Flow {
                    layer4_protocol: ip_proto as u16,
                    client_ip: client_ip.clone(),
                    server_ip: server_ip.clone(),
                    client_port: src_port,
                    server_port: dst_port,
                };

                let inverse_flow = Flow {
                    layer4_protocol: ip_proto as u16,
                    client_ip: server_ip.clone(),
                    server_ip: client_ip.clone(),
                    client_port: dst_port,
                    server_port: src_port,
                };

                let mut tracker = tls_flow_tracker.lock().unwrap();
                // Check if is a Client Hello and save the Handshake version
                if tcp_payload_len > 10 && tcp_payload[0] == 0x16 && tcp_payload[5] == 0x01 {
                    if !tracker.contains_key(&flow) {
                        let now = Instant::now();
                        tracker.insert(flow.clone(), (tcp_payload[9], tcp_payload[10], now));
                        tracker.insert(inverse_flow.clone(), (tcp_payload[9], tcp_payload[10], now));
                        output_pcap.lock().unwrap().write(&packet);
                        continue;
                    }
                }

                let mut flow_exists = false;
                let version = match tracker.get(&flow) {
                    Some(&(first, second, _)) => {
                        flow_exists = true;
                        (first, second)
                    },
                    None => match tracker.get(&inverse_flow) {
                        Some(&(first, second, _)) => {
                            flow_exists = true;
                            (first, second)
                        },
                        None => (0, 0),
                    },
                };
                
                if flow_exists{
                    // If it is a TCP packet with FIN/RST flag or a TLS record different from the Handshake, remove flow from tracker
                    if (tcp_flags & 1 == 1 || tcp_flags & 4 == 4) || 
                        (tcp_payload.len() > 5 && (tcp_payload[0] == 0x14 || tcp_payload[0] == 0x15 || tcp_payload[0] == 0x17) && ((tcp_payload[1], tcp_payload[2]) == (version.0, version.1))){
                        tracker.remove(&flow);
                        tracker.remove(&inverse_flow);
                    }else{
                        output_pcap.lock().unwrap().write(&packet);
                    }  
                }
            }       
        }
    }
}
