use ipnet::Ipv6Net;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::*;
use bolero::{Driver, ValueGenerator};
use rand::distributions::*;
use rand::*;
use std::ops::Bound;

#[test]
fn ipv6_tries() {
    let mut rng = thread_rng();

    let samples = {
        let prefix = Uniform::<u8>::from(8..=50);
        let addr = Uniform::<u128>::from(1..=u128::MAX);
        std::iter::repeat_with(|| {
            Ipv6Net::new(addr.sample(&mut rng).into(), prefix.sample(&mut rng)).unwrap()
        })
        .take(100_000)
        .collect::<Vec<_>>()
    };

    let t1: RTrieSet<Ipv6Prefix> = samples.iter().map(|i| Ipv6Prefix::from(*i)).collect();
    let t2: RTrieSet<Ipv6NetPrefix> = samples
        .iter()
        .map(|i| Ipv6NetPrefix::try_from(*i).unwrap())
        .collect();
    let t3: RTrieSet<Ipv6Net> = RTrieSet::from_iter(samples);

    let addr = Uniform::<u128>::from(((u64::MAX as u128) << 64)..=u128::MAX);
    std::iter::repeat_with(|| Ipv6Addr::from(addr.sample(&mut rng)))
        .take(100_000)
        .for_each(|ip| {
            let p1 = t1.lookup(&ip);
            let p2 = t2.lookup(&ip);
            let p3 = t3.lookup(&ip);
            assert!(p1.covers_equally(p2));
            assert!(p2.covers_equally(p3));
        });
}

#[test]
fn test_child_update_on_remove() {
    let mut trie = RTrieSet::<Ipv4Prefix>::new();
    trie.insert(Ipv4Prefix::new("128.0.0.0".parse::<Ipv4Addr>().unwrap(), 7).unwrap());
    trie.insert(Ipv4Prefix::new("130.0.0.0".parse::<Ipv4Addr>().unwrap(), 7).unwrap());
    trie.insert(Ipv4Prefix::new("128.0.0.0".parse::<Ipv4Addr>().unwrap(), 1).unwrap());
    trie.insert(Ipv4Prefix::new("128.0.0.0".parse::<Ipv4Addr>().unwrap(), 2).unwrap());
    trie.remove(&Ipv4Prefix::new("128.0.0.0".parse::<Ipv4Addr>().unwrap(), 1).unwrap());
    trie.remove(&Ipv4Prefix::new("183.154.0.0".parse::<Ipv4Addr>().unwrap(), 3).unwrap());
}

struct Ipv4PrefixOpGenerator {
    max_ops: usize,
}

#[derive(Debug)]
enum Op {
    Insert(Ipv4Prefix),
    Remove(Ipv4Prefix),
    Lookup(Ipv4Addr),
}

impl ValueGenerator for Ipv4PrefixOpGenerator {
    type Output = Vec<Op>;

    fn generate<D: Driver>(&self, d: &mut D) -> Option<Self::Output> {
        let op_count = d.gen_usize(Bound::Included(&0), Bound::Included(&self.max_ops))?;
        let mut ops = Vec::with_capacity(op_count);
        for _ in 0..op_count {
            let op_type = d.gen_u8(Bound::Included(&0), Bound::Included(&2))?;
            let addr = d.produce::<Ipv4Addr>()?;
            let prefix_len = d.gen_u8(Bound::Included(&0), Bound::Included(&32))?;
            match op_type {
                0 => {
                    // Insert operation
                    let prefix = Ipv4Prefix::new(addr, prefix_len).unwrap();
                    ops.push(Op::Insert(prefix));
                }
                1 => {
                    // Remove operation
                    let prefix = Ipv4Prefix::new(addr, prefix_len).unwrap();
                    // Don't try to remove the default prefix
                    if prefix.len() != 0 {
                        ops.push(Op::Remove(prefix));
                    }
                }
                2 => {
                    // Lookup operation
                    ops.push(Op::Lookup(addr));
                }
                _ => unreachable!(),
            }
        }

        Some(ops)
    }
}

fn oracle_v4_lookup(prefixes: &[Ipv4Prefix], addr: &Ipv4Addr) -> Ipv4Prefix {
    let mut ret: Option<Ipv4Prefix> = None;
    for prefix in prefixes {
        if prefix.covering(addr) != IpPrefixCoverage::NoCover {
            if let Some(p) = ret {
                if p.len() < prefix.len() {
                    ret = Some(*prefix);
                }
            } else {
                ret = Some(*prefix);
            }
        }
    }
    match ret {
        None => Ipv4Prefix::new(Ipv4Addr::new(0, 0, 0, 0), 0).unwrap(),
        Some(p) => p,
    }
}

#[test]
fn ipv4_tries() {
    bolero::check!()
        .with_generator(Ipv4PrefixOpGenerator { max_ops: 7 })
        .with_test_time(std::time::Duration::from_secs(10))
        .for_each(|ops| {
            let mut prefixes = Vec::new();
            let mut trie = RTrieSet::new();
            println!("\n\n\n");
            for op in ops {
                println!("op={op:?}");
                match op {
                    Op::Insert(prefix) => {
                        prefixes.push(*prefix);
                        trie.insert(*prefix);
                    }
                    Op::Remove(prefix) => {
                        let idx = prefixes.iter().position(|p| p == prefix);
                        if let Some(idx) = idx {
                            prefixes.remove(idx);
                        }
                        trie.remove(prefix);
                    }
                    Op::Lookup(addr) => {
                        let oracle_result = oracle_v4_lookup(prefixes.as_slice(), addr);
                        let trie_result = trie.lookup(addr);
                        assert!(
                            oracle_result.covering(trie_result) == IpPrefixCoverage::SameRange,
                            "Prefixes don't match oracle={oracle_result}, trie={trie_result}, addr={addr}"
                        );
                    }
                }
            }
        });
}
