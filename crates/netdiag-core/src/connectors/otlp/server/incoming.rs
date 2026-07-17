use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{AcquireError, OwnedSemaphorePermit, Semaphore};
use tonic::codegen::tokio_stream::Stream;
use tonic::transport::server::{Connected, TcpConnectInfo, TcpIncoming};

pub(super) const MAX_CONCURRENT_CONNECTIONS: usize = 16;

pub(super) struct BoundedIncoming {
    inner: TcpIncoming,
    semaphore: Arc<Semaphore>,
    acquire: Option<Pin<Box<PermitFuture>>>,
    permit: Option<OwnedSemaphorePermit>,
    active_connections: Arc<AtomicUsize>,
}

type PermitFuture =
    dyn Future<Output = std::result::Result<OwnedSemaphorePermit, AcquireError>> + Send;

impl BoundedIncoming {
    pub(super) fn new(inner: TcpIncoming, active_connections: Arc<AtomicUsize>) -> Self {
        Self {
            inner,
            semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS)),
            acquire: None,
            permit: None,
            active_connections,
        }
    }
}

impl Stream for BoundedIncoming {
    type Item = io::Result<AdmittedConnection>;

    fn poll_next(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.permit.is_none() {
            if self.acquire.is_none() {
                self.acquire = Some(Box::pin(Arc::clone(&self.semaphore).acquire_owned()));
            }
            let acquire = self
                .acquire
                .as_mut()
                .expect("OTLP connection permit future exists while acquiring");
            match acquire.as_mut().poll(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(permit)) => {
                    self.acquire = None;
                    self.permit = Some(permit);
                }
                Poll::Ready(Err(_)) => return Poll::Ready(None),
            }
        }
        match Pin::new(&mut self.inner).poll_next(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Ok(stream))) => {
                let permit = self
                    .permit
                    .take()
                    .expect("OTLP connection permit exists before accepting");
                Poll::Ready(Some(Ok(AdmittedConnection::new(
                    stream,
                    permit,
                    Arc::clone(&self.active_connections),
                ))))
            }
            Poll::Ready(Some(Err(error))) => {
                self.permit = None;
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                self.permit = None;
                Poll::Ready(None)
            }
        }
    }
}

pub(super) struct AdmittedConnection {
    stream: TcpStream,
    _permit: OwnedSemaphorePermit,
    active_connections: Arc<AtomicUsize>,
}

impl AdmittedConnection {
    fn new(
        stream: TcpStream,
        permit: OwnedSemaphorePermit,
        active_connections: Arc<AtomicUsize>,
    ) -> Self {
        active_connections.fetch_add(1, Ordering::Relaxed);
        Self {
            stream,
            _permit: permit,
            active_connections,
        }
    }
}

impl Drop for AdmittedConnection {
    fn drop(&mut self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

impl AsyncRead for AdmittedConnection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

impl AsyncWrite for AdmittedConnection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

impl Connected for AdmittedConnection {
    type ConnectInfo = TcpConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.stream.connect_info()
    }
}
