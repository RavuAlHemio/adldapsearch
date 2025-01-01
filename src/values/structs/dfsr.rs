use std::fmt::Write;


pub fn dfsr_schedule_to_string(schedule: &[u8]) -> Option<String> {
    if schedule.len() != 336 {
        return None;
    }

    let mut ret = "  |".to_owned();
    for n in 0..24 {
        write!(ret, "\u{250C}{:2}\u{2510}", n).unwrap();
    }
    write!(ret, "\n  |").unwrap();
    for _ in 0..24 {
        write!(ret, "\u{2582}\u{2584}\u{2586}\u{2588}").unwrap();
    }

    for (weekday_index, weekday_slice) in schedule.chunks(48).enumerate() {
        write!(ret, "\n").unwrap();
        let weekday = match weekday_index {
            0 => "Su",
            1 => "Mo",
            2 => "Tu",
            3 => "We",
            4 => "Th",
            5 => "Fr",
            6 => "Sa",
            _ => "  ",
        };
        write!(ret, "{}|", weekday).unwrap();
        for b in weekday_slice {
            write!(ret, "{:02X}", b).unwrap();
        }
    }

    Some(ret)
}
