//! Retransmission helpers per RFC 8415 §15.
//!
//! All durations are seconds with sub-second resolution. RAND is uniformly
//! distributed in `[-0.1, +0.1]`.

use std::time::Duration;

use rand::RngExt;

/// Default wall-clock SOLICIT deadline matching `udhcpc6 -n` semantics.
pub const DEFAULT_SOLICIT_TIMEOUT: Duration = Duration::from_secs(30);

fn rand_factor() -> f64 {
    let mut rng = rand::rng();
    rng.random_range(-0.1..=0.1)
}

/// First retransmission timeout: RT = IRT + RAND * IRT.
pub fn first_rt(irt: f64) -> Duration {
    let secs = irt + rand_factor() * irt;
    duration_from_secs_f64(secs)
}

/// Subsequent retransmission timeout: RT = 2*RTprev + RAND*RTprev, capped at MRT.
pub fn next_rt(prev: Duration, mrt: f64) -> Duration {
    let prev_s = prev.as_secs_f64();
    let next = 2.0 * prev_s + rand_factor() * prev_s;
    let capped = if mrt > 0.0 && next > mrt {
        mrt + rand_factor() * mrt
    } else {
        next
    };
    duration_from_secs_f64(capped)
}

fn duration_from_secs_f64(s: f64) -> Duration {
    if !s.is_finite() || s <= 0.0 {
        Duration::from_millis(1)
    } else {
        Duration::from_secs_f64(s)
    }
}

/// RFC 8415 §21.9 elapsed-time encoding: hundredths of a second, saturating at u16::MAX.
pub fn elapsed_centis(start: std::time::Instant) -> u16 {
    let ms = start.elapsed().as_millis();
    let centis = ms / 10;
    centis.min(u16::MAX as u128) as u16
}
