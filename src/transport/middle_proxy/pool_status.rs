use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;

use super::pool::{MePool, WriterContour};

#[derive(Clone, Debug)]
pub(crate) struct MeApiWriterStatusSnapshot {
    pub writer_id: u64,
    pub dc: Option<i16>,
    pub endpoint: SocketAddr,
    pub generation: u64,
    pub state: &'static str,
    pub draining: bool,
    pub degraded: bool,
    pub bound_clients: usize,
    pub idle_for_secs: Option<u64>,
    pub rtt_ema_ms: Option<f64>,
}

#[derive(Clone, Debug)]
pub(crate) struct MeApiDcStatusSnapshot {
    pub dc: i16,
    pub endpoints: Vec<SocketAddr>,
    pub available_endpoints: usize,
    pub available_pct: f64,
    pub required_writers: usize,
    pub alive_writers: usize,
    pub coverage_pct: f64,
    pub rtt_ms: Option<f64>,
    pub load: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct MeApiStatusSnapshot {
    pub generated_at_epoch_secs: u64,
    pub configured_dc_groups: usize,
    pub configured_endpoints: usize,
    pub available_endpoints: usize,
    pub available_pct: f64,
    pub required_writers: usize,
    pub alive_writers: usize,
    pub coverage_pct: f64,
    pub writers: Vec<MeApiWriterStatusSnapshot>,
    pub dcs: Vec<MeApiDcStatusSnapshot>,
}

impl MePool {
    pub(crate) async fn api_status_snapshot(&self) -> MeApiStatusSnapshot {
        let now_epoch_secs = Self::now_epoch_secs();

        let mut endpoints_by_dc = BTreeMap::<i16, BTreeSet<SocketAddr>>::new();
        if self.decision.ipv4_me {
            let map = self.proxy_map_v4.read().await.clone();
            for (dc, addrs) in map {
                let abs_dc = dc.abs();
                if abs_dc == 0 {
                    continue;
                }
                let Ok(dc_idx) = i16::try_from(abs_dc) else {
                    continue;
                };
                let entry = endpoints_by_dc.entry(dc_idx).or_default();
                for (ip, port) in addrs {
                    entry.insert(SocketAddr::new(ip, port));
                }
            }
        }
        if self.decision.ipv6_me {
            let map = self.proxy_map_v6.read().await.clone();
            for (dc, addrs) in map {
                let abs_dc = dc.abs();
                if abs_dc == 0 {
                    continue;
                }
                let Ok(dc_idx) = i16::try_from(abs_dc) else {
                    continue;
                };
                let entry = endpoints_by_dc.entry(dc_idx).or_default();
                for (ip, port) in addrs {
                    entry.insert(SocketAddr::new(ip, port));
                }
            }
        }

        let mut endpoint_to_dc = HashMap::<SocketAddr, i16>::new();
        for (dc, endpoints) in &endpoints_by_dc {
            for endpoint in endpoints {
                endpoint_to_dc.entry(*endpoint).or_insert(*dc);
            }
        }

        let configured_dc_groups = endpoints_by_dc.len();
        let configured_endpoints = endpoints_by_dc.values().map(BTreeSet::len).sum();

        let required_writers = endpoints_by_dc
            .values()
            .map(|endpoints| self.required_writers_for_dc_with_floor_mode(endpoints.len(), false))
            .sum();

        let idle_since = self.registry.writer_idle_since_snapshot().await;
        let activity = self.registry.writer_activity_snapshot().await;
        let rtt = self.rtt_stats.lock().await.clone();
        let writers = self.writers.read().await.clone();

        let mut live_writers_by_endpoint = HashMap::<SocketAddr, usize>::new();
        let mut live_writers_by_dc = HashMap::<i16, usize>::new();
        let mut dc_rtt_agg = HashMap::<i16, (f64, u64)>::new();
        let mut writer_rows = Vec::<MeApiWriterStatusSnapshot>::with_capacity(writers.len());

        for writer in writers {
            let endpoint = writer.addr;
            let dc = endpoint_to_dc.get(&endpoint).copied();
            let draining = writer.draining.load(Ordering::Relaxed);
            let degraded = writer.degraded.load(Ordering::Relaxed);
            let bound_clients = activity
                .bound_clients_by_writer
                .get(&writer.id)
                .copied()
                .unwrap_or(0);
            let idle_for_secs = idle_since
                .get(&writer.id)
                .map(|idle_ts| now_epoch_secs.saturating_sub(*idle_ts));
            let rtt_ema_ms = rtt.get(&writer.id).map(|(_, ema)| *ema);
            let state = match WriterContour::from_u8(writer.contour.load(Ordering::Relaxed)) {
                WriterContour::Warm => "warm",
                WriterContour::Active => "active",
                WriterContour::Draining => "draining",
            };

            if !draining {
                *live_writers_by_endpoint.entry(endpoint).or_insert(0) += 1;
                if let Some(dc_idx) = dc {
                    *live_writers_by_dc.entry(dc_idx).or_insert(0) += 1;
                    if let Some(ema_ms) = rtt_ema_ms {
                        let entry = dc_rtt_agg.entry(dc_idx).or_insert((0.0, 0));
                        entry.0 += ema_ms;
                        entry.1 += 1;
                    }
                }
            }

            writer_rows.push(MeApiWriterStatusSnapshot {
                writer_id: writer.id,
                dc,
                endpoint,
                generation: writer.generation,
                state,
                draining,
                degraded,
                bound_clients,
                idle_for_secs,
                rtt_ema_ms,
            });
        }

        writer_rows.sort_by_key(|row| (row.dc.unwrap_or(i16::MAX), row.endpoint, row.writer_id));

        let mut dcs = Vec::<MeApiDcStatusSnapshot>::with_capacity(endpoints_by_dc.len());
        let mut available_endpoints = 0usize;
        let mut alive_writers = 0usize;
        for (dc, endpoints) in endpoints_by_dc {
            let endpoint_count = endpoints.len();
            let dc_available_endpoints = endpoints
                .iter()
                .filter(|endpoint| live_writers_by_endpoint.contains_key(endpoint))
                .count();
            let dc_required_writers =
                self.required_writers_for_dc_with_floor_mode(endpoint_count, false);
            let dc_alive_writers = live_writers_by_dc.get(&dc).copied().unwrap_or(0);
            let dc_load = activity
                .active_sessions_by_target_dc
                .get(&dc)
                .copied()
                .unwrap_or(0);
            let dc_rtt_ms = dc_rtt_agg
                .get(&dc)
                .and_then(|(sum, count)| (*count > 0).then_some(*sum / (*count as f64)));

            available_endpoints += dc_available_endpoints;
            alive_writers += dc_alive_writers;

            dcs.push(MeApiDcStatusSnapshot {
                dc,
                endpoints: endpoints.into_iter().collect(),
                available_endpoints: dc_available_endpoints,
                available_pct: ratio_pct(dc_available_endpoints, endpoint_count),
                required_writers: dc_required_writers,
                alive_writers: dc_alive_writers,
                coverage_pct: ratio_pct(dc_alive_writers, dc_required_writers),
                rtt_ms: dc_rtt_ms,
                load: dc_load,
            });
        }

        MeApiStatusSnapshot {
            generated_at_epoch_secs: now_epoch_secs,
            configured_dc_groups,
            configured_endpoints,
            available_endpoints,
            available_pct: ratio_pct(available_endpoints, configured_endpoints),
            required_writers,
            alive_writers,
            coverage_pct: ratio_pct(alive_writers, required_writers),
            writers: writer_rows,
            dcs,
        }
    }
}

fn ratio_pct(part: usize, total: usize) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let pct = ((part as f64) / (total as f64)) * 100.0;
    pct.clamp(0.0, 100.0)
}

#[cfg(test)]
mod tests {
    use super::ratio_pct;

    #[test]
    fn ratio_pct_is_zero_when_denominator_is_zero() {
        assert_eq!(ratio_pct(1, 0), 0.0);
    }

    #[test]
    fn ratio_pct_is_capped_at_100() {
        assert_eq!(ratio_pct(7, 3), 100.0);
    }

    #[test]
    fn ratio_pct_reports_expected_value() {
        assert_eq!(ratio_pct(1, 4), 25.0);
    }
}
