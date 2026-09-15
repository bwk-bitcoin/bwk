use std::net::SocketAddr;

use dns_lookup::lookup_host;

use crate::error::Error;

pub const DNS_SEED_SERVERS: [&str; 8] = [
    "seed.bitcoin.sipa.be",
    "dnsseed.bluematt.me.",
    "seed.bitcoin.jonasschnelli.ch.",
    "seed.btc.petertodd.net.",
    "seed.bitcoin.sprovoost.nl.",
    "dnsseed.emzy.de.",
    "seed.bitcoin.wiz.biz.",
    "seed.mainnet.achownodes.xyz.",
];

pub fn fetch_peers(dns_seed: &str) -> Result<Vec<SocketAddr>, Error> {
    fetch_peers_with_port(dns_seed, 8333)
}

pub fn fetch_peers_with_port(dns_seed: &str, port: u16) -> Result<Vec<SocketAddr>, Error> {
    match lookup_host(dns_seed) {
        Ok(ips) => {
            let peers: Vec<SocketAddr> = ips
                .into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect();
            Ok(peers)
        }
        Err(e) => Err(Error::DnsLookup(e.to_string())),
    }
}

#[cfg(all(test, feature = "ci-p2p"))]
mod tests {
    use super::*;

    #[test]
    fn test_fetch_peers() {
        let peers = fetch_peers("seed.bitcoin.sipa.be").unwrap();
        println!("{} peers:", peers.len());
        for peer in peers {
            println!("{peer}");
        }
    }
}
