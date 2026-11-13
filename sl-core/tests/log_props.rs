use proptest::prelude::*;
use sl_core::log::DurableLog;
use sl_core::mem_storage::MemStorage;
use sl_proto::ids::Class;

#[derive(Clone, Debug)]
enum Op {
    Append { class: u8, count: u32, len: usize },
    Ack { class: u8, quarters: u64 },
    Cut { bytes: u64 },
    Reopen,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        6 => (0u8..3, 1u32..5, 0usize..200).prop_map(|(class, count, len)| Op::Append { class, count, len }),
        2 => (0u8..3, 0u64..5).prop_map(|(class, quarters)| Op::Ack { class, quarters }),
        1 => (0u64..300).prop_map(|bytes| Op::Cut { bytes }),
        1 => Just(Op::Reopen),
    ]
}

/// `(first_seq, count, payload)` of each frame that should still be in the log.
type Model = [Vec<(u64, u32, Vec<u8>)>; 3];

fn held(log: &DurableLog<MemStorage>, class: Class) -> Vec<(u64, u32, Vec<u8>)> {
    log.read_all(class)
        .unwrap()
        .into_iter()
        .map(|f| (f.header.first_seq, f.header.count, f.payload))
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    #[test]
    fn the_log_holds_exactly_what_was_durably_appended(ops in proptest::collection::vec(op(), 1..80)) {
        let (mut log, _) = DurableLog::open(MemStorage::new(1 << 20)).unwrap();
        let mut model: Model = Default::default();
        let mut next = [0u64; 3];

        for op in ops {
            match op {
                Op::Append { class, count, len } => {
                    let class = Class::from_u8(class).unwrap();
                    let i = class.index();
                    let payload = vec![(next[i] as u8) ^ (i as u8); len];
                    if let Ok(first_seq) = log.append(class, 0, [i as u8; 16], count, &payload) {
                        prop_assert_eq!(first_seq, next[i]);
                        model[i].push((first_seq, count, payload));
                        next[i] += u64::from(count);
                    }
                }
                Op::Ack { class, quarters } => {
                    let class = Class::from_u8(class).unwrap();
                    let i = class.index();
                    let mark = next[i] * quarters / 4;
                    if log.ack(class, mark, mark).is_ok() {
                        model[i].retain(|(first, count, _)| first + u64::from(*count) > mark);
                    }
                }
                Op::Cut { bytes } => log.storage_mut().cut_power_after(bytes),
                Op::Reopen => {
                    let mut storage = log.into_storage();
                    storage.power_on();
                    let (reopened, recovery) = DurableLog::open(storage).unwrap();
                    log = reopened;
                    prop_assert!(recovery.corrupt.is_empty());
                    for class in Class::ALL {
                        let i = class.index();
                        prop_assert_eq!(held(&log, class), model[i].clone());
                        prop_assert_eq!(log.next_seq(class), next[i]);
                    }
                }
            }
        }
    }
}
