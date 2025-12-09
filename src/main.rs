//imports
use clap::Parser;
use pcap::{Active, Device, Capture};
use pnet_packet::ethernet::{EthernetPacket, EtherTypes};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::udp::UdpPacket;
use pnet_packet::Packet;
use std::io::{self, Write};
use anyhow::{Context, Result};

//parse command line arguments
#[derive(Parser, Debug)]
//help command
#[command(name = "traffic-analyzer")]
//descrption of what command does
#[command(about = "Network Traffic Analyzer and Packet Capture Tool")]


struct Args {
    //network Interface to capture on (eth0, wlan0)
    interface: Option<String>,

    #[arg(short, long)]
    file: Option<String>,
}



// main function with Result as a error handler
fn main() -> Result<()> {
    let args = Args::parse();

    println!("Traffic Analyzer Starting...");
    
    let interface_name = if let Some(iface) = args.interface {
        iface 
    } else{
        list_and_select_interface()?

    };
    let mut cap = start_capture(&interface_name)?;

    while let Ok(packet) = cap.next_packet() {
        println!("recieved packet {:?}", packet)
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
    let mut cap = Capture::from_device(interface_name)?.promisc(true).snaplen(5000).open().context("error capturing interface")?;
}


