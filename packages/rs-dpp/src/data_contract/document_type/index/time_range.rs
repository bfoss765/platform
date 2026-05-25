#[cfg(feature = "serde-conversion")]
use serde::{Deserialize, Serialize};

/// Maximum allowed overlap factor (`range_ms / step_ms`) for a time-range
/// transform. This bounds the number of index entries a single document
/// produces, preventing a contract from inflating storage and processing
/// cost by declaring a huge window over a tiny step.
pub const MAX_TIME_RANGE_OVERLAP_FACTOR: u64 = 256;

/// An index-level transform that buckets a timestamp index property into
/// fixed-length, regularly-spaced time ranges.
///
/// A time range is identified by a single `u64`: the **start time of the
/// range** in milliseconds. Each range covers `[start, start + range_ms)`.
/// New ranges start every `step_ms`. When `range_ms > step_ms` the ranges
/// overlap, so a single timestamp falls into `range_ms / step_ms` ranges
/// (the "overlap factor") and a document is indexed under that many
/// bucket-start values.
///
/// The canonical use case is "trending" leaderboards: index on
/// `(timeRange($createdAt), hashtag)` with `countable`, then query a single
/// bucket ordered by count. Overlapping ranges guarantee that, at any
/// instant, there is always an active range covering a near-full `range_ms`
/// window of history (see [`Self::oldest_active_start`]).
///
/// This transform lives on the index definition only. At the GroveDB storage
/// layer a bucket start is an ordinary `u64` key segment (encoded exactly
/// like a `$createdAt` value), so existing index queries, count trees and
/// proofs apply unchanged — the only novelty is that one document produces
/// several index entries.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde-conversion", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde-conversion", serde(rename_all = "camelCase"))]
pub struct TimeRangeTransform {
    /// The source timestamp index property this transform buckets, e.g.
    /// `$createdAt`. Must be the first property of the index and must refer
    /// to a millisecond-timestamp field (`$createdAt` / `$updatedAt` /
    /// `$transferredAt` or a user `Date` property).
    pub source: String,
    /// Length of each range window, in milliseconds. Must be a positive
    /// multiple of `step_ms`.
    pub range_ms: u64,
    /// Interval between successive range starts, in milliseconds. Must be
    /// greater than zero.
    pub step_ms: u64,
    /// Reference origin for range alignment, in milliseconds. Range starts
    /// are `origin_ms + k * step_ms` for `k = 0, 1, 2, …`. Defaults to `0`.
    pub origin_ms: u64,
}

impl TimeRangeTransform {
    /// The number of overlapping ranges that contain any given instant, i.e.
    /// the number of bucket-start values a single document is indexed under.
    /// Equal to `range_ms / step_ms`.
    ///
    /// Returns `0` only for a malformed transform with `step_ms == 0`; callers
    /// constructing from a validated contract never observe that.
    pub fn overlap_factor(&self) -> u64 {
        if self.step_ms == 0 {
            return 0;
        }
        self.range_ms / self.step_ms
    }

    /// The start of the most recent range that has begun at or before `t`,
    /// i.e. the largest `origin_ms + k * step_ms` that is `<= t`.
    ///
    /// For `t < origin_ms` (no range has started yet) this saturates to
    /// `origin_ms`.
    pub fn most_recent_start(&self, t: u64) -> u64 {
        if self.step_ms == 0 {
            return self.origin_ms;
        }
        let elapsed = t.saturating_sub(self.origin_ms);
        self.origin_ms + (elapsed / self.step_ms) * self.step_ms
    }

    /// All bucket-start values whose range `[start, start + range_ms)`
    /// contains the timestamp `t`. This is the set of index entries a
    /// document with timestamp `t` must be written under.
    ///
    /// The result is sorted in descending order (newest range first) and has
    /// exactly [`Self::overlap_factor`] elements, except near `origin_ms`
    /// where fewer ranges have started.
    pub fn containing_buckets(&self, t: u64) -> Vec<u64> {
        let overlap = self.overlap_factor();
        if overlap == 0 {
            return Vec::new();
        }
        let newest = self.most_recent_start(t);
        (0..overlap)
            .filter_map(|j| {
                let offset = j.checked_mul(self.step_ms)?;
                newest.checked_sub(offset)
            })
            .filter(|start| *start >= self.origin_ms)
            .collect()
    }

    /// The start of the newest range that is active at `now` (the freshest
    /// started range). Querying this bucket returns documents from the latest
    /// partial slice — between `0` and `step_ms` of history.
    pub fn newest_active_start(&self, now: u64) -> u64 {
        self.most_recent_start(now)
    }

    /// The start of the oldest range still active at `now`. Its window
    /// `[start, start + range_ms)` still contains `now`, so querying this
    /// bucket returns a near-full trailing window of `~range_ms` of history
    /// (between `range_ms - step_ms` and `range_ms`). This is the bucket to
    /// query for "trending over the last range window".
    pub fn oldest_active_start(&self, now: u64) -> u64 {
        let overlap = self.overlap_factor();
        if overlap == 0 {
            return self.origin_ms;
        }
        let newest = self.most_recent_start(now);
        let back = (overlap - 1).saturating_mul(self.step_ms);
        newest.saturating_sub(back).max(self.origin_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transform() -> TimeRangeTransform {
        // range = 6h, step = 2h, origin = 0 → overlap factor 3.
        TimeRangeTransform {
            source: "$createdAt".to_string(),
            range_ms: 6 * 3_600_000,
            step_ms: 2 * 3_600_000,
            origin_ms: 0,
        }
    }

    #[test]
    fn overlap_factor_is_range_over_step() {
        assert_eq!(transform().overlap_factor(), 3);
    }

    #[test]
    fn most_recent_start_floors_to_step_multiple() {
        let t = transform();
        let h = 3_600_000;
        // now = 7h → most recent start = 6h
        assert_eq!(t.most_recent_start(7 * h), 6 * h);
        // exactly on a boundary stays put
        assert_eq!(t.most_recent_start(6 * h), 6 * h);
        // before origin saturates to origin
        assert_eq!(t.most_recent_start(0), 0);
    }

    #[test]
    fn containing_buckets_are_the_overlapping_ranges() {
        let t = transform();
        let h = 3_600_000;
        // doc at 7h belongs to ranges starting at 6h, 4h, 2h
        assert_eq!(t.containing_buckets(7 * h), vec![6 * h, 4 * h, 2 * h]);
        // every returned range actually contains the timestamp
        for start in t.containing_buckets(7 * h) {
            assert!(start <= 7 * h && 7 * h < start + t.range_ms);
        }
    }

    #[test]
    fn containing_buckets_truncate_near_origin() {
        let t = transform();
        let h = 3_600_000;
        // doc at 3h: ranges starting at 2h and 0h (4h start would be in future)
        assert_eq!(t.containing_buckets(3 * h), vec![2 * h, 0]);
    }

    #[test]
    fn newest_vs_oldest_active() {
        let t = transform();
        let h = 3_600_000;
        let now = 7 * h;
        // newest active = freshest started range
        assert_eq!(t.newest_active_start(now), 6 * h);
        // oldest active = covers the full trailing window
        assert_eq!(t.oldest_active_start(now), 2 * h);
        // oldest active range still contains now
        let oldest = t.oldest_active_start(now);
        assert!(oldest <= now && now < oldest + t.range_ms);
    }

    #[test]
    fn origin_offset_shifts_alignment() {
        let t = TimeRangeTransform {
            source: "$createdAt".to_string(),
            range_ms: 60,
            step_ms: 20,
            origin_ms: 5,
        };
        // starts are 5, 25, 45, ... ; now=50 → most recent start 45
        assert_eq!(t.most_recent_start(50), 45);
        assert_eq!(t.containing_buckets(50), vec![45, 25, 5]);
    }
}
