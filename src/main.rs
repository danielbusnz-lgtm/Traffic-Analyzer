//imports
use clap::{Parser,Subcommand};
use pcap::{Active, Device, Capture};
use pnet_packet::ethernet::{EthernetPacket, EtherTypes};
use pnet_packet::icmp::IcmpPacket;
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::udp::UdpPacket;
use pnet_packet::Packet;
use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

//parse command line arguments
#[derive(Parser, Debug)]
//help command
#[command(name = "traffic-analyzer")]
//descrption of what command does
#[command(version, about = "Network Traffic Analyzer and Packet Capture Tool")]


struct Args {
    //network Interface to capture on (eth0, wlan0)
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Capture {
        interface: Option<String>,

        #[arg(short,long)]
        file: Option<String>,

    },

    Scan {
        target: String,

        #[arg(short,long, default_value = "1")]
        start:u16,

        #[arg(short, long, default_value = "1024")]
        end:u16,
    },
}


// main function with Result as a error handler
fn main() -> Result<()> {
    let args = Args::parse();
    
    match args.command {
        Commands::Capture {interface, file} => {
            println!("Traffic Analyze Starting..");
            
            let interface_name = if let Some(iface) = interface {
                iface
            
            } else{
                    list_and_select_interface()?
        };
        
    
            let mut cap = start_capture(&interface_name)?;
            let mut stats = PacketStats{
            total: 0,
            tcp: 0,
            udp: 0,
            icmp:0,
    };
     
      
    //set up Ctrl + c handler
        let running = Arc::new(AtomicBool::new(true));
        let r = running.clone();
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        }).expect("Error setting Ctrl-C Handler");

    println!("Capturing packets... Press Ctrl+C to stop \n");
    
    while running.load(Ordering::SeqCst) {
        if let Ok(packet) = cap.next_packet() {
            parse_packet(&packet, &mut stats)
        }
    }
    
      
            println!("\n{:-<60}", "");
            println!("Packet Statistics:");
            println!("Total packets: {}", stats.total);
            println!("  TCP:  {}", stats.tcp);
            println!("  UDP:  {}", stats.udp);
            println!("  ICMP: {}", stats.icmp);
            println!("{:-<60}", "");
        },
        Commands::Scan { target, start, end } => {
            // Scanner code will go here
        },
    }

    Ok(())
}

fn list_and_select_interface() -> Result<String> {
    let devices = Device::list().context("Failed To List Network Devices")?;
    
    if devices.is_empty(){
        anyhow::bail!("No Network Devices Found")
    }
    println!("\nAvaliable network interface");
    println!("\n{:-<60}","");

    for (i, device) in devices.iter().enumerate(){
        println!("[{}]{}", i,device.name);
        
        if let Some(desc) = &device.desc {
            println!("    Description:{}", desc)
        }   
        for addr in &device.addresses {
            println!("    Addresses:{}", addr.addr)
        }
        println!();
    }
    
   
    print!("select interface number: ");
    
    io::stdout().flush()?;
    
    let mut input = String::new();

    io::stdin()
        .read_line(&mut input)
        .context("Failed to read user input")?;


    let choice: usize = input.trim().parse().context("Please input a valid number")?;
     
    if choice >= devices.len(){
        anyhow::bail!("Invalid Selection: {} (max:{})", choice, devices.len()-1);

    }

    Ok(devices[choice].name.clone())

}   

fn start_capture(interface_name: &str) -> Result<Capture<Active>> {
    println!("\nOpening capture on interface: {}", interface_name);
    let  cap = Capture::from_device(interface_name)?.promisc(true).snaplen(5000).open().context("error capturing interface")?;

    Ok(cap)
}

fn parse_packet(packet:&[u8], stats:&mut PacketStats){
    stats.total += 1;
    if let Some(ethernet) = EthernetPacket::new(packet){
        let src_mac = ethernet.get_source();
        let dst_mac = ethernet.get_destination();
        println!("MAC Adress {} -> {}", src_mac, dst_mac);
         
        //check whats inside the ethernet frame
        match ethernet.get_ethertype(){
            EtherTypes::Ipv4 => {
                if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()){
                    println!("ipv4 -> {} {}", ipv4.get_source(), ipv4.get_destination());
                    
                    match ipv4.get_next_level_protocol() {
                        IpNextHeaderProtocols::Tcp => {
                            if let Some(tcp) = TcpPacket::new(ipv4.payload()){
                                println!("tcp Source:{} Destination:{}", tcp.get_source(), tcp.get_destination());
                                stats.tcp += 1;
                            }
                        }
                        IpNextHeaderProtocols::Udp => {
                            if let Some(udp) = UdpPacket::new(ipv4.payload()){
                                println!("Udp source:{} Destination:{}",udp.get_source(), udp.get_destination());
                                stats.udp += 1;
                            }

                        }   
                        IpNextHeaderProtocols::Icmp =>{
                            if let Some(icmp) = IcmpPacket::new(ipv4.payload()){
                                println!("Icmp type:{:?} code:{:?}",icmp.get_icmp_type(), icmp.get_icmp_code());
                                stats.icmp += 1;
                            }
                        }
                        _=>{
                            println!("Other Protocols")
                        }
                    }
                    
                }
            }
            _ => {}
        }
    }
}

async fn scan_port(ip: &str, port:u16, timeout_ms: u64) -> bool {
    let address = format!("{}:{}",ip, port);

    let addr: SocketAddr = match address.parse() {
        Ok(a) => a,
        Err(_) => return false, 

    };

}
 






struct PacketStats {
    total: u64,
    tcp: u64,
    udp: u64,
    icmp: u64,
}




