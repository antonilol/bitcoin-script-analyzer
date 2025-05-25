use time::OffsetDateTime;
use time::format_description;

pub const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;
pub const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000ffff;

#[derive(PartialEq, Eq)]
pub enum LocktimeType {
    Height,
    Time,
}

impl LocktimeType {
    pub fn new(value: u32, relative: bool) -> Self {
        if value
            < if relative {
                SEQUENCE_LOCKTIME_TYPE_FLAG
            } else {
                500000000
            }
        {
            Self::Height
        } else {
            Self::Time
        }
    }
}

pub fn locktime_type_equals(a: u32, b: u32, relative: bool) -> bool {
    LocktimeType::new(a, relative) == LocktimeType::new(b, relative)
}

// Output of these functions should fit the following sentence:
// "This TXO becomes spendable ..."

pub fn absolute_timelock_height_to_string(n: u32) -> String {
    format!("at block {n}")
}

pub fn absolute_timelock_time_to_string(n: u32) -> String {
    const DATE_FORMAT_STR: &str = "on [year]-[month]-[day] [hour]:[minute]:[second] ([unix_timestamp] seconds since unix epoch)";

    let date = OffsetDateTime::from_unix_timestamp(n as i64).unwrap();
    let format = format_description::parse_borrowed::<2>(DATE_FORMAT_STR).unwrap();

    date.format(&format).unwrap()
}

pub fn relative_timelock_height_to_string(n: u32) -> String {
    format!("in {n} blocks")
}

pub fn relative_timelock_time_to_string(n: u32) -> String {
    let mut t = (n & SEQUENCE_LOCKTIME_MASK) * 512;
    let mut output = format!("in {}s", t % 60);
    let mut prev = 60;
    for unit in [('m', 60), ('h', 24), ('d', 999)] {
        t /= prev;
        if t == 0 {
            break;
        }
        output.insert_str(3, &format!("{}{} ", t % unit.1, unit.0));
        prev = unit.1;
    }
    output
}

pub fn locktime_to_string_unchecked(n: u32, relative: bool, type_: LocktimeType) -> String {
    (match (relative, type_) {
        (false, LocktimeType::Height) => absolute_timelock_height_to_string,
        (false, LocktimeType::Time) => absolute_timelock_time_to_string,
        (true, LocktimeType::Height) => relative_timelock_height_to_string,
        (true, LocktimeType::Time) => relative_timelock_time_to_string,
    })(n)
}

pub fn locktime_to_string(n: u32, relative: bool) -> String {
    locktime_to_string_unchecked(n, relative, LocktimeType::new(n, relative))
}
