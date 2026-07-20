use libpcapng::{read_file, BLOCK_EPB, BLOCK_IDB, BLOCK_SHB};

fn main() {
    let path = std::env::args().nth(1).expect("usage: read <file.pcapng>");

    read_file(&path, |counter, block_type, data| {
        let name = match block_type {
            BLOCK_SHB => "SHB",
            BLOCK_IDB => "IDB",
            BLOCK_EPB => "EPB",
            _ => "???",
        };
        println!("#{counter:>5}  {name} (0x{block_type:08x})  {} bytes", data.len());
        true
    })
    .unwrap_or_else(|e| eprintln!("error: {e}"));
}
