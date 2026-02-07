export interface ZeekRecord {
  ts: number;
  uid?: string;
  [key: string]: unknown;
}

export interface ConnRecord extends ZeekRecord {
  "id.orig_h": string;
  "id.orig_p": number;
  "id.resp_h": string;
  "id.resp_p": number;
  proto: string;
  service?: string;
  duration?: number;
  orig_bytes?: number;
  resp_bytes?: number;
  conn_state?: string;
  local_orig?: boolean;
  local_resp?: boolean;
  missed_bytes?: number;
  history?: string;
  orig_pkts?: number;
  orig_ip_bytes?: number;
  resp_pkts?: number;
  resp_ip_bytes?: number;
}

export interface DnsRecord extends ZeekRecord {
  "id.orig_h": string;
  "id.orig_p": number;
  "id.resp_h": string;
  "id.resp_p": number;
  proto: string;
  trans_id?: number;
  rtt?: number;
  query: string;
  qclass?: number;
  qclass_name?: string;
  qtype?: number;
  qtype_name?: string;
  rcode?: number;
  rcode_name?: string;
  AA?: boolean;
  TC?: boolean;
  RD?: boolean;
  RA?: boolean;
  Z?: number;
  answers?: string[];
  TTLs?: number[];
  rejected?: boolean;
}

export interface HttpRecord extends ZeekRecord {
  "id.orig_h": string;
  "id.orig_p": number;
  "id.resp_h": string;
  "id.resp_p": number;
  trans_depth?: number;
  method?: string;
  host?: string;
  uri?: string;
  referrer?: string;
  version?: string;
  user_agent?: string;
  origin?: string;
  request_body_len?: number;
  response_body_len?: number;
  status_code?: number;
  status_msg?: string;
  info_code?: number;
  info_msg?: string;
  tags?: string[];
  username?: string;
  password?: string;
  proxied?: string[];
  resp_fuids?: string[];
  resp_mime_types?: string[];
}

export interface SslRecord extends ZeekRecord {
  "id.orig_h": string;
  "id.orig_p": number;
  "id.resp_h": string;
  "id.resp_p": number;
  version?: string;
  cipher?: string;
  curve?: string;
  server_name?: string;
  resumed?: boolean;
  last_alert?: string;
  next_protocol?: string;
  established?: boolean;
  subject?: string;
  issuer?: string;
  client_subject?: string;
  client_issuer?: string;
  validation_status?: string;
}

export interface FileRecord extends ZeekRecord {
  fuid: string;
  tx_hosts?: string[];
  rx_hosts?: string[];
  conn_uids?: string[];
  source?: string;
  depth?: number;
  analyzers?: string[];
  mime_type?: string;
  filename?: string;
  duration?: number;
  local_orig?: boolean;
  is_orig?: boolean;
  seen_bytes?: number;
  total_bytes?: number;
  missing_bytes?: number;
  overflow_bytes?: number;
  timedout?: boolean;
  parent_fuid?: string;
  md5?: string;
  sha1?: string;
  sha256?: string;
  extracted?: string;
  extracted_cutoff?: boolean;
  extracted_size?: number;
}

export interface NoticeRecord extends ZeekRecord {
  "id.orig_h"?: string;
  "id.orig_p"?: number;
  "id.resp_h"?: string;
  "id.resp_p"?: number;
  fuid?: string;
  file_mime_type?: string;
  file_desc?: string;
  proto?: string;
  note: string;
  msg: string;
  sub?: string;
  src?: string;
  dst?: string;
  p?: number;
  n?: number;
  peer_descr?: string;
  actions?: string[];
  suppress_for?: number;
  remote_location_country_code?: string;
  remote_location_region?: string;
  remote_location_city?: string;
  remote_location_latitude?: number;
  remote_location_longitude?: number;
}

export interface SshRecord extends ZeekRecord {
  "id.orig_h": string;
  "id.orig_p": number;
  "id.resp_h": string;
  "id.resp_p": number;
  version?: number;
  auth_success?: boolean;
  auth_attempts?: number;
  direction?: string;
  client?: string;
  server?: string;
  cipher_alg?: string;
  mac_alg?: string;
  compression_alg?: string;
  kex_alg?: string;
  host_key_alg?: string;
  host_key?: string;
}

export interface X509Record extends ZeekRecord {
  id: string;
  "certificate.version"?: number;
  "certificate.serial"?: string;
  "certificate.subject"?: string;
  "certificate.issuer"?: string;
  "certificate.not_valid_before"?: number;
  "certificate.not_valid_after"?: number;
  "certificate.key_alg"?: string;
  "certificate.sig_alg"?: string;
  "certificate.key_type"?: string;
  "certificate.key_length"?: number;
  "certificate.exponent"?: string;
  "certificate.curve"?: string;
  san_dns?: string[];
  san_uri?: string[];
  san_email?: string[];
  san_ip?: string[];
  basic_constraints_ca?: boolean;
  basic_constraints_path_len?: number;
}

export interface SmtpRecord extends ZeekRecord {
  "id.orig_h": string;
  "id.orig_p": number;
  "id.resp_h": string;
  "id.resp_p": number;
  trans_depth?: number;
  helo?: string;
  mailfrom?: string;
  rcptto?: string[];
  date?: string;
  from?: string;
  to?: string[];
  cc?: string[];
  reply_to?: string;
  msg_id?: string;
  in_reply_to?: string;
  subject?: string;
  x_originating_ip?: string;
  first_received?: string;
  second_received?: string;
  last_reply?: string;
  path?: string[];
  user_agent?: string;
  tls?: boolean;
  fuids?: string[];
  is_webmail?: boolean;
}

export interface WeirdRecord extends ZeekRecord {
  "id.orig_h"?: string;
  "id.orig_p"?: number;
  "id.resp_h"?: string;
  "id.resp_p"?: number;
  name: string;
  addl?: string;
  notice?: boolean;
  peer?: string;
  source?: string;
}

export interface DpdRecord extends ZeekRecord {
  "id.orig_h": string;
  "id.orig_p": number;
  "id.resp_h": string;
  "id.resp_p": number;
  proto: string;
  analyzer: string;
  failure_reason: string;
}

export interface SoftwareRecord extends ZeekRecord {
  host: string;
  host_p?: number;
  software_type: string;
  name: string;
  "version.major"?: number;
  "version.minor"?: number;
  "version.minor2"?: number;
  "version.minor3"?: number;
  "version.addl"?: string;
  unparsed_version?: string;
}

export type LogType =
  | "conn"
  | "dns"
  | "http"
  | "ssl"
  | "files"
  | "notice"
  | "weird"
  | "x509"
  | "smtp"
  | "ssh"
  | "dpd"
  | "software";

export interface LogFieldDef {
  name: string;
  type: string;
  description: string;
}

export const LOG_FIELD_DEFINITIONS: Record<LogType, LogFieldDef[]> = {
  conn: [
    { name: "ts", type: "time", description: "Timestamp" },
    { name: "uid", type: "string", description: "Unique connection ID" },
    { name: "id.orig_h", type: "addr", description: "Source IP address" },
    { name: "id.orig_p", type: "port", description: "Source port" },
    { name: "id.resp_h", type: "addr", description: "Destination IP address" },
    { name: "id.resp_p", type: "port", description: "Destination port" },
    { name: "proto", type: "enum", description: "Transport protocol (tcp/udp/icmp)" },
    { name: "service", type: "string", description: "Detected application protocol" },
    { name: "duration", type: "interval", description: "Connection duration in seconds" },
    { name: "orig_bytes", type: "count", description: "Bytes sent by originator" },
    { name: "resp_bytes", type: "count", description: "Bytes sent by responder" },
    { name: "conn_state", type: "string", description: "Connection state (S0, S1, SF, REJ, etc.)" },
  ],
  dns: [
    { name: "ts", type: "time", description: "Timestamp" },
    { name: "uid", type: "string", description: "Connection UID" },
    { name: "id.orig_h", type: "addr", description: "Source IP" },
    { name: "query", type: "string", description: "DNS query domain" },
    { name: "qtype_name", type: "string", description: "Query type (A, AAAA, MX, etc.)" },
    { name: "rcode_name", type: "string", description: "Response code (NOERROR, NXDOMAIN, etc.)" },
    { name: "answers", type: "vector", description: "DNS response answers" },
    { name: "TTLs", type: "vector", description: "Response TTL values" },
  ],
  http: [
    { name: "ts", type: "time", description: "Timestamp" },
    { name: "uid", type: "string", description: "Connection UID" },
    { name: "id.orig_h", type: "addr", description: "Source IP" },
    { name: "method", type: "string", description: "HTTP method" },
    { name: "host", type: "string", description: "HTTP Host header" },
    { name: "uri", type: "string", description: "Request URI" },
    { name: "status_code", type: "count", description: "HTTP response status code" },
    { name: "user_agent", type: "string", description: "User-Agent header" },
    { name: "resp_mime_types", type: "vector", description: "Response MIME types" },
  ],
  ssl: [
    { name: "ts", type: "time", description: "Timestamp" },
    { name: "uid", type: "string", description: "Connection UID" },
    { name: "id.orig_h", type: "addr", description: "Source IP" },
    { name: "id.resp_h", type: "addr", description: "Destination IP" },
    { name: "version", type: "string", description: "SSL/TLS version" },
    { name: "cipher", type: "string", description: "Cipher suite" },
    { name: "server_name", type: "string", description: "SNI hostname" },
    { name: "subject", type: "string", description: "Certificate subject" },
    { name: "issuer", type: "string", description: "Certificate issuer" },
    { name: "validation_status", type: "string", description: "Certificate validation result" },
  ],
  files: [
    { name: "ts", type: "time", description: "Timestamp" },
    { name: "fuid", type: "string", description: "File unique ID" },
    { name: "source", type: "string", description: "Protocol source (HTTP, FTP, etc.)" },
    { name: "mime_type", type: "string", description: "MIME type" },
    { name: "filename", type: "string", description: "Filename if available" },
    { name: "md5", type: "string", description: "MD5 hash" },
    { name: "sha1", type: "string", description: "SHA1 hash" },
    { name: "sha256", type: "string", description: "SHA256 hash" },
    { name: "total_bytes", type: "count", description: "Total file size" },
  ],
  notice: [
    { name: "ts", type: "time", description: "Timestamp" },
    { name: "uid", type: "string", description: "Connection UID" },
    { name: "note", type: "string", description: "Notice type (e.g. Scan::Port_Scan)" },
    { name: "msg", type: "string", description: "Notice message" },
    { name: "src", type: "addr", description: "Source address" },
    { name: "dst", type: "addr", description: "Destination address" },
    { name: "p", type: "port", description: "Associated port" },
    { name: "actions", type: "set", description: "Actions taken" },
  ],
  weird: [
    { name: "ts", type: "time", description: "Timestamp" },
    { name: "uid", type: "string", description: "Connection UID" },
    { name: "name", type: "string", description: "Weird activity name" },
    { name: "addl", type: "string", description: "Additional info" },
    { name: "notice", type: "bool", description: "Whether a notice was generated" },
    { name: "peer", type: "string", description: "Peer that generated the weird" },
  ],
  x509: [
    { name: "ts", type: "time", description: "Timestamp" },
    { name: "id", type: "string", description: "Certificate file ID" },
    { name: "certificate.version", type: "count", description: "X.509 version" },
    { name: "certificate.serial", type: "string", description: "Serial number" },
    { name: "certificate.subject", type: "string", description: "Subject" },
    { name: "certificate.issuer", type: "string", description: "Issuer" },
    { name: "certificate.not_valid_before", type: "time", description: "Not valid before" },
    { name: "certificate.not_valid_after", type: "time", description: "Not valid after" },
  ],
  smtp: [
    { name: "ts", type: "time", description: "Timestamp" },
    { name: "uid", type: "string", description: "Connection UID" },
    { name: "id.orig_h", type: "addr", description: "Source IP" },
    { name: "mailfrom", type: "string", description: "Envelope sender" },
    { name: "rcptto", type: "set", description: "Envelope recipients" },
    { name: "subject", type: "string", description: "Email subject" },
    { name: "date", type: "string", description: "Email date header" },
  ],
  ssh: [
    { name: "ts", type: "time", description: "Timestamp" },
    { name: "uid", type: "string", description: "Connection UID" },
    { name: "id.orig_h", type: "addr", description: "Source IP" },
    { name: "id.resp_h", type: "addr", description: "Destination IP" },
    { name: "auth_success", type: "bool", description: "Authentication result" },
    { name: "direction", type: "string", description: "Connection direction" },
    { name: "client", type: "string", description: "Client software string" },
    { name: "server", type: "string", description: "Server software string" },
  ],
  dpd: [
    { name: "ts", type: "time", description: "Timestamp" },
    { name: "uid", type: "string", description: "Connection UID" },
    { name: "proto", type: "enum", description: "Transport protocol" },
    { name: "analyzer", type: "string", description: "Protocol analyzer" },
    { name: "failure_reason", type: "string", description: "Reason for detection failure" },
  ],
  software: [
    { name: "ts", type: "time", description: "Timestamp" },
    { name: "host", type: "addr", description: "Host IP" },
    { name: "software_type", type: "string", description: "Software type category" },
    { name: "name", type: "string", description: "Software name" },
    { name: "version.major", type: "count", description: "Major version" },
    { name: "version.minor", type: "count", description: "Minor version" },
  ],
};
