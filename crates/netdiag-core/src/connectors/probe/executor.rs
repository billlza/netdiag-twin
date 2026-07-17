use super::measurement::{ProbeMeasurement, build_http_client, measure_target};
use super::target::ProbeTarget;
use super::{MAX_PROBE_CONCURRENCY, ProbeExecutionOptions};
use crate::connectors::CaptureControl;
use crate::error::{NetdiagError, Result};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

const RESULT_QUEUE_CAPACITY: usize = MAX_PROBE_CONCURRENCY * 2;
const CANCELLATION_POLL_INTERVAL: Duration = Duration::from_millis(10);
const CANCELLATION_CONTEXT: &str = "active probe before completion";

pub(super) fn execute_probe_plan(
    targets: Vec<ProbeTarget>,
    samples_per_target: usize,
    options: ProbeExecutionOptions,
    control: &CaptureControl,
) -> Result<Vec<ProbeMeasurement>> {
    let expected = targets
        .len()
        .checked_mul(samples_per_target)
        .ok_or_else(|| NetdiagError::Connector("active probe work size overflowed".to_string()))?;
    let worker_count = targets.len().min(MAX_PROBE_CONCURRENCY);
    let targets = Arc::new(targets);
    let next_target = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let deadline = Instant::now()
        .checked_add(options.overall_timeout)
        .ok_or_else(|| NetdiagError::Connector("active probe deadline overflowed".to_string()))?;
    let http_client = targets
        .iter()
        .any(|target| matches!(target, ProbeTarget::Http(_)))
        .then(|| build_http_client(options.request_timeout))
        .transpose()?
        .map(Arc::new);
    let (result_sender, result_receiver) = mpsc::sync_channel(RESULT_QUEUE_CAPACITY);

    let mut measurements = Vec::with_capacity(expected);
    let mut terminal_error = None;
    let worker_failure = std::thread::scope(|scope| {
        let mut workers = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let worker_targets = Arc::clone(&targets);
            let worker_next = Arc::clone(&next_target);
            let worker_stop = Arc::clone(&stop);
            let worker_sender = result_sender.clone();
            let worker_client = http_client.clone();
            workers.push(scope.spawn(move || {
                worker_loop(WorkerContext {
                    targets: &worker_targets,
                    samples_per_target,
                    request_timeout: options.request_timeout,
                    deadline,
                    next_target: &worker_next,
                    stop: &worker_stop,
                    control,
                    http_client: worker_client.as_deref(),
                    result_sender: &worker_sender,
                })
            }));
        }
        drop(result_sender);

        while measurements.len() < expected {
            match result_receiver.try_recv() {
                Ok(measurement) => {
                    measurements.push(measurement);
                    continue;
                }
                Err(mpsc::TryRecvError::Disconnected) => break,
                Err(mpsc::TryRecvError::Empty) => {}
            }
            if control.is_cancelled() {
                terminal_error = Some(NetdiagError::capture_cancelled(CANCELLATION_CONTEXT));
                break;
            }
            let now = Instant::now();
            if now >= deadline {
                terminal_error = Some(NetdiagError::Connector(
                    "active probe exceeded its overall deadline".to_string(),
                ));
                break;
            }
            let wait = deadline
                .saturating_duration_since(now)
                .min(CANCELLATION_POLL_INTERVAL);
            match result_receiver.recv_timeout(wait) {
                Ok(measurement) => measurements.push(measurement),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        stop.store(true, Ordering::Relaxed);
        while result_receiver.recv().is_ok() {}

        let mut failure = None;
        for worker in workers {
            match worker.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    if failure.is_none() {
                        failure = Some(error);
                    }
                }
                Err(_) => {
                    if failure.is_none() {
                        failure = Some(NetdiagError::Connector(
                            "active probe worker panicked".to_string(),
                        ));
                    }
                }
            }
        }
        failure
    });

    finalize_execution(
        measurements,
        expected,
        worker_failure.or(terminal_error),
        control,
        deadline,
    )
}

fn finalize_execution(
    mut measurements: Vec<ProbeMeasurement>,
    expected: usize,
    error: Option<NetdiagError>,
    control: &CaptureControl,
    deadline: Instant,
) -> Result<Vec<ProbeMeasurement>> {
    if let Some(error) = error {
        return Err(error);
    }
    if measurements.len() != expected {
        if control.is_cancelled() {
            return Err(NetdiagError::capture_cancelled(CANCELLATION_CONTEXT));
        }
        let reason = if Instant::now() >= deadline {
            "active probe exceeded its overall deadline"
        } else {
            "active probe workers stopped before completing the bounded plan"
        };
        return Err(NetdiagError::Connector(reason.to_string()));
    }
    measurements.sort_by_key(|measurement| (measurement.sample_index, measurement.target_index));
    Ok(measurements)
}

struct WorkerContext<'a> {
    targets: &'a [ProbeTarget],
    samples_per_target: usize,
    request_timeout: Duration,
    deadline: Instant,
    next_target: &'a AtomicUsize,
    stop: &'a AtomicBool,
    control: &'a CaptureControl,
    http_client: Option<&'a reqwest::blocking::Client>,
    result_sender: &'a mpsc::SyncSender<ProbeMeasurement>,
}

fn worker_loop(context: WorkerContext<'_>) -> Result<()> {
    loop {
        if should_stop(context.stop, context.control, context.deadline) {
            return Ok(());
        }
        let target_index = context.next_target.fetch_add(1, Ordering::Relaxed);
        let Some(target) = context.targets.get(target_index) else {
            return Ok(());
        };
        for sample_index in 0..context.samples_per_target {
            if should_stop(context.stop, context.control, context.deadline) {
                return Ok(());
            }
            let remaining = context.deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(());
            }
            let measurement = measure_target(
                target,
                target_index,
                sample_index,
                context.request_timeout.min(remaining),
                context.http_client,
            )?;
            if context.result_sender.send(measurement).is_err() {
                return Err(NetdiagError::Connector(
                    "active probe result consumer stopped unexpectedly".to_string(),
                ));
            }
        }
    }
}

fn should_stop(stop: &AtomicBool, control: &CaptureControl, deadline: Instant) -> bool {
    stop.load(Ordering::Relaxed) || control.is_cancelled() || Instant::now() >= deadline
}
