// Copyright 2018-2024 the Deno authors. All rights reserved. MIT license.

use deno_core::error::bad_resource;
use deno_core::error::generic_error;
use deno_core::error::type_error;
use deno_core::error::AnyError;
use deno_core::futures::task::noop_waker_ref;
use deno_core::op2;
use deno_core::AsyncRefCell;
use deno_core::AsyncResult;
use deno_core::BufView;
use deno_core::JsBuffer;
use deno_core::OpState;
use deno_core::RcRef;
use deno_core::Resource;
use deno_core::ResourceId;
use deno_core::WriteOutcome;
use deno_net::resolve_addr::resolve_addr;
use deno_net::DefaultTlsOptions;
use deno_net::NetPermissions;
use deno_net::UnsafelyIgnoreCertificateErrors;
use deno_tls::create_client_config;
use deno_tls::load_certs;
use deno_tls::load_private_keys;
use deno_tls::RootCertStoreProvider;
use deno_tls::SocketUse;
use serde::Deserialize;
use serde::Serialize;
use std::borrow::Cow;
use std::cell::RefCell;
use std::future::Future;
use std::io::BufReader;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::path::PathBuf;
use std::pin::pin;
use std::rc::Rc;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;

pub fn get_declaration() -> PathBuf {
  PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("lib.deno_quic.d.ts")
}

pub const UNSTABLE_FEATURE_NAME: &str = "quic";

deno_core::extension!(
  deno_quic,
  // deps = [],
  parameters = [ P: NetPermissions ],
  ops = [
    op_quic_listen<P>,
    op_quic_accept,
    op_quic_connect<P>,
    op_quic_accept_bi,
    op_quic_accept_uni,
    op_quic_open_bi,
    op_quic_open_uni,
    op_quic_max_datagram_size,
    op_quic_send_datagram,
    op_quic_read_datagram,
    op_quic_close_connection,
    op_quic_close_endpoint,
    op_quic_connection_closed,
    op_quic_get_send_stream_priority,
    op_quic_set_send_stream_priority,
    op_quic_get_conn_remote_addr,
  ],
  esm = ["01_quic.js"],
  options = {
    root_cert_store_provider: Option<Arc<dyn RootCertStoreProvider>>,
    unsafely_ignore_certificate_errors: Option<Vec<String>>,
  },
  state = |state, options| {
    state.put(DefaultTlsOptions {
      root_cert_store_provider: options.root_cert_store_provider,
    });
    state.put(UnsafelyIgnoreCertificateErrors(
      options.unsafely_ignore_certificate_errors,
    ));
  },
);

#[derive(Debug, Deserialize, Serialize)]
struct Addr {
  hostname: String,
  port: u16,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListenArgs {
  cert: String,
  key: String,
  alpn_protocols: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransportConfig {
  keep_alive_interval: Option<u64>,
  max_idle_timeout: Option<u64>,
  max_concurrent_bidirectional_streams: Option<u32>,
  max_concurrent_unidirectional_streams: Option<u32>,
}

impl TryInto<quinn::TransportConfig> for TransportConfig {
  type Error = AnyError;

  fn try_into(self) -> Result<quinn::TransportConfig, AnyError> {
    let mut cfg = quinn::TransportConfig::default();

    if let Some(interval) = self.keep_alive_interval {
      cfg.keep_alive_interval(Some(Duration::from_millis(interval)));
    }

    if let Some(timeout) = self.max_idle_timeout {
      cfg.max_idle_timeout(Some(Duration::from_millis(timeout).try_into()?));
    }

    if let Some(max) = self.max_concurrent_bidirectional_streams {
      cfg.max_concurrent_bidi_streams(max.into());
    }

    if let Some(max) = self.max_concurrent_unidirectional_streams {
      cfg.max_concurrent_uni_streams(max.into());
    }

    Ok(cfg)
  }
}

struct EndpointResource(quinn::Endpoint);

impl Resource for EndpointResource {
  fn name(&self) -> Cow<str> {
    "quicListener".into()
  }
}

#[op2(async)]
#[serde]
async fn op_quic_listen<NP>(
  state: Rc<RefCell<OpState>>,
  #[serde] addr: Addr,
  #[serde] args: ListenArgs,
  #[serde] transport_config: TransportConfig,
) -> Result<(ResourceId, Addr), AnyError>
where
  NP: NetPermissions + 'static,
{
  state
    .borrow_mut()
    .borrow_mut::<NP>()
    .check_net(&(&addr.hostname, Some(addr.port)), "Deno.listenQuic()")?;

  let cert_chain = load_certs(&mut BufReader::new(args.cert.as_bytes()))?;
  let key_der = load_private_keys(args.key.as_bytes())?.remove(0);

  let addr = resolve_addr(&addr.hostname, addr.port)
    .await?
    .next()
    .ok_or_else(|| generic_error("No resolved address found"))?;

  let mut crypto = rustls::ServerConfig::builder()
    .with_safe_defaults()
    .with_no_client_auth()
    .with_single_cert(cert_chain, key_der)?;
  if let Some(alpn_protocols) = args.alpn_protocols {
    crypto.alpn_protocols = alpn_protocols
      .into_iter()
      .map(|alpn| alpn.into_bytes())
      .collect();
  }
  let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
  config.transport_config(Arc::new(transport_config.try_into()?));
  let endpoint = quinn::Endpoint::server(config, addr)?;

  let addr = endpoint.local_addr()?;
  let addr = Addr {
    hostname: format!("{}", addr.ip()),
    port: addr.port(),
  };

  let rid = state
    .borrow_mut()
    .resource_table
    .add(EndpointResource(endpoint));
  Ok((rid, addr))
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CloseInfo {
  close_code: u64,
  reason: String,
}

#[op2(fast)]
fn op_quic_close_endpoint(
  state: Rc<RefCell<OpState>>,
  #[smi] rid: ResourceId,
  #[bigint] close_code: u64,
  #[string] reason: String,
) -> Result<(), AnyError> {
  let endpoint = state
    .borrow_mut()
    .resource_table
    .take::<EndpointResource>(rid)?
    .0
    .clone();
  endpoint.close(quinn::VarInt::from_u64(close_code)?, reason.as_bytes());
  Ok(())
}

struct ConnectionResource(quinn::Connection);

impl Resource for ConnectionResource {
  fn name(&self) -> Cow<str> {
    "quicConnection".into()
  }
}

#[op2(async)]
#[serde]
async fn op_quic_accept(
  state: Rc<RefCell<OpState>>,
  #[smi] rid: ResourceId,
) -> Result<(ResourceId, Option<String>), AnyError> {
  let endpoint = {
    state
      .borrow()
      .resource_table
      .get::<EndpointResource>(rid)?
      .0
      .clone()
  };
  match endpoint.accept().await {
    Some(connecting) => {
      let conn = connecting.await?;
      let protocol = conn
        .handshake_data()
        .and_then(|h| h.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|h| h.protocol)
        .map(|p| String::from_utf8_lossy(&p).into_owned());
      let rid = state
        .borrow_mut()
        .resource_table
        .add(ConnectionResource(conn));
      Ok((rid, protocol))
    }
    None => Err(bad_resource("QuicListener is closed")),
  }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConnectArgs {
  ca_certs: Option<Vec<String>>,
  cert_chain: Option<String>,
  private_key: Option<String>,
  alpn_protocols: Option<Vec<String>>,
  server_name: Option<String>,
}

#[op2(async)]
#[serde]
async fn op_quic_connect<NP>(
  state: Rc<RefCell<OpState>>,
  #[serde] addr: Addr,
  #[serde] args: ConnectArgs,
  #[serde] transport_config: TransportConfig,
) -> Result<(ResourceId, Option<String>), AnyError>
where
  NP: NetPermissions + 'static,
{
  state
    .borrow_mut()
    .borrow_mut::<NP>()
    .check_net(&(&addr.hostname, Some(addr.port)), "Deno.connectQuic()")?;

  let sock_addr = resolve_addr(&addr.hostname, addr.port)
    .await?
    .next()
    .ok_or_else(|| generic_error("No resolved address found"))?;

  let root_cert_store = state
    .borrow()
    .borrow::<DefaultTlsOptions>()
    .root_cert_store()?;

  let unsafely_ignore_certificate_errors = state
    .borrow()
    .try_borrow::<UnsafelyIgnoreCertificateErrors>()
    .and_then(|it| it.0.clone());

  let ca_certs = args
    .ca_certs
    .unwrap_or_default()
    .into_iter()
    .map(|s| s.into_bytes())
    .collect::<Vec<_>>();

  let cert_chain_and_key =
    if args.cert_chain.is_some() || args.private_key.is_some() {
      let cert_chain = args
        .cert_chain
        .ok_or_else(|| type_error("No certificate chain provided"))?;
      let private_key = args
        .private_key
        .ok_or_else(|| type_error("No private key provided"))?;
      Some((cert_chain, private_key))
    } else {
      None
    };

  let mut tls_config = create_client_config(
    root_cert_store,
    ca_certs,
    unsafely_ignore_certificate_errors,
    cert_chain_and_key,
    SocketUse::GeneralSsl,
  )?;

  if let Some(alpn_protocols) = args.alpn_protocols {
    tls_config.alpn_protocols =
      alpn_protocols.into_iter().map(|s| s.into_bytes()).collect();
  }

  let mut client_config = quinn::ClientConfig::new(Arc::new(tls_config));
  client_config.transport_config(Arc::new(transport_config.try_into()?));

  let local_addr = match sock_addr.ip() {
    IpAddr::V4(_) => IpAddr::from(Ipv4Addr::new(0, 0, 0, 0)),
    IpAddr::V6(_) => IpAddr::from(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
  };

  let conn = quinn::Endpoint::client((local_addr, 0).into())?
    .connect_with(
      client_config,
      sock_addr,
      &args.server_name.unwrap_or(addr.hostname),
    )?
    .await?;

  let protocol = conn
    .handshake_data()
    .and_then(|h| h.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
    .and_then(|h| h.protocol)
    .map(|p| String::from_utf8_lossy(&p).into_owned());

  let rid = state
    .borrow_mut()
    .resource_table
    .add(ConnectionResource(conn));
  Ok((rid, protocol))
}

#[op2(fast)]
fn op_quic_close_connection(
  state: Rc<RefCell<OpState>>,
  #[smi] rid: ResourceId,
  #[bigint] close_code: u64,
  #[string] reason: String,
) -> Result<(), AnyError> {
  let conn = {
    state
      .borrow()
      .resource_table
      .get::<ConnectionResource>(rid)?
      .0
      .clone()
  };
  conn.close(quinn::VarInt::from_u64(close_code)?, reason.as_bytes());
  Ok(())
}

#[op2(async)]
#[serde]
async fn op_quic_connection_closed(
  state: Rc<RefCell<OpState>>,
  #[smi] rid: ResourceId,
) -> Result<CloseInfo, AnyError> {
  let conn = {
    state
      .borrow()
      .resource_table
      .get::<ConnectionResource>(rid)?
      .0
      .clone()
  };
  let e = conn.closed().await;
  match e {
    quinn::ConnectionError::LocallyClosed => Ok(CloseInfo {
      close_code: 0,
      reason: "".into(),
    }),
    quinn::ConnectionError::ApplicationClosed(i) => Ok(CloseInfo {
      close_code: i.error_code.into(),
      reason: String::from_utf8_lossy(&i.reason).into_owned(),
    }),
    e => Err(e.into()),
  }
}

struct SendStreamResource(AsyncRefCell<quinn::SendStream>);

impl SendStreamResource {
  fn new(stream: quinn::SendStream) -> Self {
    Self(AsyncRefCell::new(stream))
  }
}

impl Resource for SendStreamResource {
  fn name(&self) -> Cow<str> {
    "quicSendStream".into()
  }

  fn write(self: Rc<Self>, view: BufView) -> AsyncResult<WriteOutcome> {
    Box::pin(async move {
      let mut r = RcRef::map(self, |r| &r.0).borrow_mut().await;
      let nwritten = r.write(&view).await?;
      Ok(WriteOutcome::Partial { nwritten, view })
    })
  }
}

struct RecvStreamResource(AsyncRefCell<quinn::RecvStream>);

impl RecvStreamResource {
  fn new(stream: quinn::RecvStream) -> Self {
    Self(AsyncRefCell::new(stream))
  }
}

impl Resource for RecvStreamResource {
  fn name(&self) -> Cow<str> {
    "quicReceiveStream".into()
  }

  fn read(self: Rc<Self>, limit: usize) -> AsyncResult<BufView> {
    Box::pin(async move {
      let mut r = RcRef::map(self, |r| &r.0).borrow_mut().await;
      let mut data = vec![0; limit];
      let nread = r.read(&mut data).await?.unwrap_or(0);
      data.truncate(nread);
      Ok(BufView::from(data))
    })
  }
}

#[op2(async)]
#[serde]
async fn op_quic_accept_bi(
  state: Rc<RefCell<OpState>>,
  #[smi] rid: ResourceId,
) -> Result<(ResourceId, ResourceId), AnyError> {
  let conn = {
    state
      .borrow()
      .resource_table
      .get::<ConnectionResource>(rid)?
      .0
      .clone()
  };
  match conn.accept_bi().await {
    Ok((tx, rx)) => {
      let mut state = state.borrow_mut();
      let tx_rid = state.resource_table.add(SendStreamResource::new(tx));
      let rx_rid = state.resource_table.add(RecvStreamResource::new(rx));
      Ok((tx_rid, rx_rid))
    }
    Err(e) => match e {
      quinn::ConnectionError::LocallyClosed
      | quinn::ConnectionError::ApplicationClosed(..) => {
        Err(bad_resource("QuicConn is closed"))
      }
      _ => Err(e.into()),
    },
  }
}

#[op2(async)]
#[serde]
async fn op_quic_open_bi(
  state: Rc<RefCell<OpState>>,
  #[smi] rid: ResourceId,
  wait_for_available: bool,
) -> Result<(ResourceId, ResourceId), AnyError> {
  let conn = {
    state
      .borrow()
      .resource_table
      .get::<ConnectionResource>(rid)?
      .0
      .clone()
  };
  let (tx, rx) = if wait_for_available {
    conn.open_bi().await?
  } else {
    let waker = noop_waker_ref();
    let mut cx = Context::from_waker(waker);
    match pin!(conn.open_bi()).poll(&mut cx) {
      Poll::Ready(r) => r?,
      Poll::Pending => {
        return Err(generic_error("Connection has reached the maximum number of outgoing concurrent bidirectional streams"));
      }
    }
  };
  let mut state = state.borrow_mut();
  let tx_rid = state.resource_table.add(SendStreamResource::new(tx));
  let rx_rid = state.resource_table.add(RecvStreamResource::new(rx));
  Ok((tx_rid, rx_rid))
}

#[op2(async)]
#[serde]
async fn op_quic_accept_uni(
  state: Rc<RefCell<OpState>>,
  #[smi] rid: ResourceId,
) -> Result<ResourceId, AnyError> {
  let conn = {
    state
      .borrow()
      .resource_table
      .get::<ConnectionResource>(rid)?
      .0
      .clone()
  };
  match conn.accept_uni().await {
    Ok(rx) => {
      let rid = state
        .borrow_mut()
        .resource_table
        .add(RecvStreamResource::new(rx));
      Ok(rid)
    }
    Err(e) => match e {
      quinn::ConnectionError::LocallyClosed
      | quinn::ConnectionError::ApplicationClosed(..) => {
        Err(bad_resource("QuicConn is closed"))
      }
      _ => Err(e.into()),
    },
  }
}

#[op2(async)]
#[serde]
async fn op_quic_open_uni(
  state: Rc<RefCell<OpState>>,
  #[smi] rid: ResourceId,
  wait_for_available: bool,
) -> Result<ResourceId, AnyError> {
  let conn = {
    state
      .borrow()
      .resource_table
      .get::<ConnectionResource>(rid)?
      .0
      .clone()
  };
  let tx = if wait_for_available {
    conn.open_uni().await?
  } else {
    let waker = noop_waker_ref();
    let mut cx = Context::from_waker(waker);
    match pin!(conn.open_uni()).poll(&mut cx) {
      Poll::Ready(r) => r?,
      Poll::Pending => {
        return Err(generic_error("Connection has reached the maximum number of outgoing concurrent unidirectional streams"));
      }
    }
  };
  let rid = state
    .borrow_mut()
    .resource_table
    .add(SendStreamResource::new(tx));
  Ok(rid)
}

#[op2(async)]
async fn op_quic_send_datagram(
  state: Rc<RefCell<OpState>>,
  #[smi] rid: ResourceId,
  #[buffer] zero_copy: JsBuffer,
) -> Result<(), AnyError> {
  let conn = {
    state
      .borrow()
      .resource_table
      .get::<ConnectionResource>(rid)?
      .0
      .clone()
  };
  // TODO: https://github.com/quinn-rs/quinn/issues/1738
  conn.send_datagram(zero_copy.into())?;
  Ok(())
}

#[op2(async)]
async fn op_quic_read_datagram(
  state: Rc<RefCell<OpState>>,
  #[smi] rid: ResourceId,
  #[buffer] mut buf: JsBuffer,
) -> Result<u32, AnyError> {
  let conn = {
    state
      .borrow()
      .resource_table
      .get::<ConnectionResource>(rid)?
      .0
      .clone()
  };
  let data = conn.read_datagram().await?;
  buf[0..data.len()].copy_from_slice(&data);
  Ok(data.len() as _)
}

#[op2(fast)]
fn op_quic_max_datagram_size(
  state: Rc<RefCell<OpState>>,
  #[smi] rid: ResourceId,
) -> Result<u32, AnyError> {
  let resource = state
    .borrow()
    .resource_table
    .get::<ConnectionResource>(rid)?;
  Ok(resource.0.max_datagram_size().unwrap_or(0) as _)
}

#[op2(fast)]
fn op_quic_get_send_stream_priority(
  state: Rc<RefCell<OpState>>,
  #[smi] rid: ResourceId,
) -> Result<i32, AnyError> {
  let resource = state
    .borrow()
    .resource_table
    .get::<SendStreamResource>(rid)?;
  let r = RcRef::map(resource, |r| &r.0).try_borrow();
  match r {
    Some(s) => Ok(s.priority()?),
    None => Err(generic_error("Unable to get priority")),
  }
}

#[op2(fast)]
fn op_quic_set_send_stream_priority(
  state: Rc<RefCell<OpState>>,
  #[smi] rid: ResourceId,
  priority: i32,
) -> Result<(), AnyError> {
  let resource = state
    .borrow()
    .resource_table
    .get::<SendStreamResource>(rid)?;
  let r = RcRef::map(resource, |r| &r.0).try_borrow();
  match r {
    Some(s) => {
      s.set_priority(priority)?;
      Ok(())
    }
    None => Err(generic_error("Unable to set priority")),
  }
}

#[op2]
#[serde]
fn op_quic_get_conn_remote_addr(
  state: Rc<RefCell<OpState>>,
  #[smi] rid: ResourceId,
) -> Result<Addr, AnyError> {
  let resource = state
    .borrow()
    .resource_table
    .get::<ConnectionResource>(rid)?;
  let addr = resource.0.remote_address();
  Ok(Addr {
    hostname: format!("{}", addr.ip()),
    port: addr.port(),
  })
}
