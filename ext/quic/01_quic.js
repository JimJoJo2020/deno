// Copyright 2018-2024 the Deno authors. All rights reserved. MIT license.
import { core, primordials } from "ext:core/mod.js";
import {
  op_quic_accept,
  op_quic_accept_bi,
  op_quic_accept_uni,
  op_quic_close_connection,
  op_quic_close_endpoint,
  op_quic_connect,
  op_quic_connection_closed,
  op_quic_get_conn_remote_addr,
  op_quic_get_send_stream_priority,
  op_quic_listen,
  op_quic_max_datagram_size,
  op_quic_open_bi,
  op_quic_open_uni,
  op_quic_read_datagram,
  op_quic_send_datagram,
  op_quic_set_send_stream_priority,
} from "ext:core/ops";
import {
  getWritableStreamResourceBacking,
  ReadableStream,
  readableStreamForRid,
  WritableStream,
  writableStreamForRid,
} from "ext:deno_web/06_streams.js";
const {
  BadResourcePrototype,
} = core;
const {
  Uint8Array,
  TypedArrayPrototypeSubarray,
  SymbolAsyncIterator,
  SafePromisePrototypeFinally,
  ObjectPrototypeIsPrototypeOf,
} = primordials;

class QuicSendStream extends WritableStream {
  get sendOrder() {
    return op_quic_get_send_stream_priority(
      getWritableStreamResourceBacking(this).rid,
    );
  }

  set sendOrder(p) {
    op_quic_set_send_stream_priority(
      getWritableStreamResourceBacking(this).rid,
      p,
    );
  }
}

class QuicReceiveStream extends ReadableStream {}

function readableStream(rid, closed) {
  // stream can be indirectly closed by closing connection.
  SafePromisePrototypeFinally(closed, () => {
    core.tryClose(rid);
  });
  return readableStreamForRid(rid, true, QuicReceiveStream);
}

function writableStream(rid, closed) {
  // stream can be indirectly closed by closing connection.
  SafePromisePrototypeFinally(closed, () => {
    core.tryClose(rid);
  });
  return writableStreamForRid(rid, true, QuicSendStream);
}

class QuicBidirectionalStream {
  #readable = null;
  #writable = null;

  constructor(txRid, rxRid, closed) {
    this.#readable = readableStream(rxRid, closed);
    this.#writable = writableStream(txRid, closed);
  }

  get readable() {
    return this.#readable;
  }

  get writable() {
    return this.#writable;
  }
}

async function* bidiStream(rid, closed) {
  try {
    while (true) {
      const r = await op_quic_accept_bi(rid);
      yield new QuicBidirectionalStream(r[0], r[1], closed);
    }
  } catch (error) {
    if (ObjectPrototypeIsPrototypeOf(BadResourcePrototype, error)) {
      return;
    }
    throw error;
  }
}

async function* uniStream(rid, closed) {
  try {
    while (true) {
      const uniRid = await op_quic_accept_uni(rid);
      yield readableStream(uniRid, closed);
    }
  } catch (error) {
    if (ObjectPrototypeIsPrototypeOf(BadResourcePrototype, error)) {
      return;
    }
    throw error;
  }
}

class QuicConn {
  #rid = 0;
  #protocol = null;
  #bidiStream = null;
  #uniStream = null;
  #closed = null;

  constructor(rid, protocol) {
    this.#rid = rid;
    this.#protocol = protocol;

    this.#closed = op_quic_connection_closed(this.#rid);
    core.unrefOpPromise(this.#closed);

    // connection can be indirectly closed by closing listener.
    SafePromisePrototypeFinally(this.#closed, () => {
      core.tryClose(rid);
    });
  }

  get protocol() {
    return this.#protocol;
  }

  get remoteAddr() {
    return op_quic_get_conn_remote_addr(this.#rid);
  }

  async createBidirectionalStream({ sendOrder, waitUntilAvailable } = {}) {
    const { 0: txRid, 1: rxRid } = await op_quic_open_bi(
      this.#rid,
      waitUntilAvailable ?? false,
    );
    if (sendOrder != null) {
      op_quic_set_send_stream_priority(txRid, sendOrder);
    }
    return new QuicBidirectionalStream(txRid, rxRid, this.#closed);
  }

  async createUnidirectionalStream({ sendOrder, waitUntilAvailable } = {}) {
    const rid = await op_quic_open_uni(this.#rid, waitUntilAvailable ?? false);
    if (sendOrder != null) {
      op_quic_set_send_stream_priority(rid, sendOrder);
    }
    return writableStream(rid, this.#closed);
  }

  get incomingBidirectionalStreams() {
    if (this.#bidiStream == null) {
      this.#bidiStream = ReadableStream.from(
        bidiStream(this.#rid, this.#closed),
      );
    }
    return this.#bidiStream;
  }

  get incomingUnidirectionalStreams() {
    if (this.#uniStream == null) {
      this.#uniStream = ReadableStream.from(uniStream(this.#rid, this.#closed));
    }
    return this.#uniStream;
  }

  get maxDatagramSize() {
    return op_quic_max_datagram_size(this.#rid);
  }

  async readDatagram(p) {
    const view = p || new Uint8Array(this.maxDatagramSize);
    const nread = await op_quic_read_datagram(this.#rid, view);
    return TypedArrayPrototypeSubarray(view, 0, nread);
  }

  async sendDatagram(data) {
    await op_quic_send_datagram(this.#rid, data);
  }

  get closed() {
    core.refOpPromise(this.#closed);
    return this.#closed;
  }

  close({ closeCode, reason }) {
    op_quic_close_connection(this.#rid, closeCode, reason);
  }
}

class QuicListener {
  #rid = 0;
  #addr = null;

  constructor(rid, addr) {
    this.#rid = rid;
    this.#addr = addr;
  }

  get addr() {
    return this.#addr;
  }

  async accept() {
    const { 0: rid, 1: protocol } = await op_quic_accept(this.#rid);
    return new QuicConn(rid, protocol);
  }

  async next() {
    let conn;
    try {
      conn = await this.accept();
    } catch (error) {
      if (ObjectPrototypeIsPrototypeOf(BadResourcePrototype, error)) {
        return { value: undefined, done: true };
      }
      throw error;
    }
    return { value: conn, done: false };
  }

  [SymbolAsyncIterator]() {
    return this;
  }

  close({ closeCode, reason }) {
    op_quic_close_endpoint(this.#rid, closeCode, reason);
  }
}

async function listenQuic(
  {
    hostname,
    port,
    cert,
    key,
    alpnProtocols,
    keepAliveInterval,
    maxIdleTimeout,
    maxConcurrentBidirectionalStreams,
    maxConcurrentUnidirectionalStreams,
  },
) {
  hostname = hostname || "0.0.0.0";
  const { 0: rid, 1: addr } = await op_quic_listen({ hostname, port }, {
    cert,
    key,
    alpnProtocols,
  }, {
    keepAliveInterval,
    maxIdleTimeout,
    maxConcurrentBidirectionalStreams,
    maxConcurrentUnidirectionalStreams,
  });
  return new QuicListener(rid, addr);
}

async function connectQuic(
  {
    hostname,
    port,
    serverName,
    caCerts,
    certChain,
    privateKey,
    alpnProtocols,
    keepAliveInterval,
    maxIdleTimeout,
    maxConcurrentBidirectionalStreams,
    maxConcurrentUnidirectionalStreams,
  },
) {
  const { 0: rid, 1: protocol } = await op_quic_connect({ hostname, port }, {
    caCerts,
    certChain,
    privateKey,
    alpnProtocols,
    serverName,
  }, {
    keepAliveInterval,
    maxIdleTimeout,
    maxConcurrentBidirectionalStreams,
    maxConcurrentUnidirectionalStreams,
  });
  return new QuicConn(rid, protocol);
}

export {
  connectQuic,
  listenQuic,
  QuicBidirectionalStream,
  QuicConn,
  QuicListener,
  QuicReceiveStream,
  QuicSendStream,
};
