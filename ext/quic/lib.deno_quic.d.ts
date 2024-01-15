// Copyright 2018-2024 the Deno authors. All rights reserved. MIT license.

/// <reference no-default-lib="true" />
/// <reference lib="esnext" />

declare namespace Deno {
  /** @category Network */
  export interface QuicTransportOptions {
    /** Period of inactivity before sending a keep-alive packet. Keep-alive
     * packets prevent an inactive but otherwise healthy connection from timing
     * out. Only one side of any given connection needs keep-alive enabled for
     * the connection to be preserved.
     */
    keepAliveInterval?: number;
    /** Maximum duration of inactivity to accept before timing out the
     * connection. The true idle timeout is the minimum of this and the peer’s
     * own max idle timeout.
     */
    maxIdleTimeout?: number;
    /** Maximum number of incoming bidirectional streams that may be open
     * concurrently.
     */
    maxConcurrentBidirectionalStreams?: number;
    /** Maximum number of incoming unidirectional streams that may be open
     * concurrently.
     */
    maxConcurrentUnidirectionalStreams?: number;
  }

  /** @category Network */
  export interface ListenQuicOptions extends QuicTransportOptions {
    /** The port to connect to. */
    port: number;
    /** A literal IP address or host name that can be resolved to an IP address. */
    hostname?: string;
    /** Server private key in PEM format */
    key: string;
    /** Cert chain in PEM format */
    cert: string;
    /** Application-Layer Protocol Negotiation (ALPN) protocols to announce to
     * the client. QUIC requires the use of ALPN.
     */
    alpnProtocols: string[];
  }

  /** Listen announces on the local transport address over QUIC.
   *
   * ```ts
   * const lstnr = await Deno.listenQuic({ port: 443, cert: "...", key: "...", alpnProtocols: ["h3"] });
   * ```
   *
   * Requires `allow-net` permission.
   *
   * @tags allow-net
   * @category Network
   */
  export function listenQuic(options: ListenQuicOptions): Promise<QuicListener>;

  /** @category Network */
  export interface ConnectQuicOptions extends QuicTransportOptions {
    /** The port to connect to. */
    port: number;
    /** A literal IP address or host name that can be resolved to an IP address. */
    hostname: string;
    /** The name used for validating the certificate provided by the server. If
     * not provided, defaults to `hostname`. */
    serverName?: string | undefined;
    /** Application-Layer Protocol Negotiation (ALPN) protocols supported by
     * the client. QUIC requires the use of ALPN.
     */
    alpnProtocols: string[];
    /** A list of root certificates that will be used in addition to the
     * default root certificates to verify the peer's certificate.
     *
     * Must be in PEM format. */
    caCerts?: string[];
  }

  /** Establishes a secure connection over QUIC using a hostname and port.  The
   * cert file is optional and if not included Mozilla's root certificates will
   * be used (see also https://github.com/ctz/webpki-roots for specifics)
   *
   * ```ts
   * const caCert = await Deno.readTextFile("./certs/my_custom_root_CA.pem");
   * const conn1 = await Deno.connectQuic({ hostname: "example.com", port: 443, alpnProtocols: ["h3"] });
   * const conn2 = await Deno.connectQuic({ caCerts: [caCert], hostname: "example.com", port: 443, alpnProtocols: ["h3"] });
   * ```
   *
   * Requires `allow-net` permission.
   *
   * @tags allow-net
   * @category Network
   */
  export function connectQuic(options: ConnectQuicOptions): Promise<QuicConn>;

  /** @category Network */
  export interface QuicCloseInfo {
    /** A number representing the error code for the error. */
    closeCode: number;
    /** A string representing the reason for closing the connection. */
    reason: string;
  }

  /** Specialized listener that accepts QUIC connections.
   *
   * @category Network
   */
  export interface QuicListener extends AsyncIterable<QuicConn> {
    /** Return the address of the `QuicListener`. */
    readonly addr: NetAddr;

    /** Waits for and resolves to the next connection to the `QuicListener`. */
    accept(): Promise<QuicConn>;
    /** Close closes the listener. Any pending accept promises will be rejected
     * with errors. */
    close(info: QuicCloseInfo): void;

    [Symbol.asyncIterator](): AsyncIterableIterator<QuicConn>;
  }

  /** @category Network */
  export interface QuicSendStreamOptions {
    sendOrder?: number;
    waitUntilAvailable?: boolean;
  }

  /** @category Network */
  export interface QuicConn {
    /** Close closes the listener. Any pending accept promises will be rejected
     * with errors. */
    close(info: QuicCloseInfo): void;
    /** Opens and returns a bidirectional stream. */
    createBidirectionalStream(
      options?: QuicSendStreamOptions,
    ): Promise<QuicBidirectionalStream>;
    /** Opens and returns a unidirectional stream. */
    createUnidirectionalStream(
      options?: QuicSendStreamOptions,
    ): Promise<QuicSendStream>;
    /** Send a datagram. The provided data cannot be larger than
     * `maxDatagramSize`. */
    sendDatagram(data: Uint8Array): Promise<void>;
    /** Receive a datagram. If no buffer is provider, one will be allocated.
     * The zie of the provided buffer should be at least `maxDatagramSize`. */
    readDatagram(buffer?: Uint8Array): Promise<Uint8Array>;

    /** Return the remote address for the connection. Clients may change
     * addresses at will, e.g. when switching to a cellular internet connection.
     */
    readonly remoteAddr: NetAddr;
    /** The negotiated ALPN protocol, if provided. */
    readonly protocol: string | undefined;
    /** Returns a promise that resolves when the connection is closed. */
    readonly closed: Promise<QuicCloseInfo>;
    /** A stream of bidirectional streams opened by the peer. */
    readonly incomingBidirectionalStreams: ReadableStream<
      QuicBidirectionalStream
    >;
    /** A stream of unidirectional streams opened by the peer. */
    readonly incomingUnidirectionalStreams: ReadableStream<QuicReceiveStream>;
    /** Returns the datagram stream for sending and receiving datagrams. */
    readonly maxDatagramSize: number;
  }

  /** @category Network */
  export interface QuicBidirectionalStream {
    /** Returns a QuicReceiveStream instance that can be used to read incoming data. */
    readonly readable: QuicReceiveStream;
    /** Returns a QuicSendStream instance that can be used to write outgoing data. */
    readonly writable: QuicSendStream;
  }

  /** @category Network */
  export interface QuicSendStream extends WritableStream<Uint8Array> {
    /** Indicates the send priority of this stream relative to other streams for
     * which the value has been set. */
    sendOrder: number;
  }

  /** @category Network */
  // deno-lint-ignore no-empty-interface
  export interface QuicReceiveStream extends ReadableStream<Uint8Array> {}
}
