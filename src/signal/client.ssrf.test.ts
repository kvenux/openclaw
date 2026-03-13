import { describe, expect, it } from "vitest";
import { assertSignalBaseUrlAllowed } from "./client.js";

describe("CWE-918: Signal base URL SSRF validation", () => {
  it("should block cloud metadata IP (169.254.169.254)", () => {
    expect(() => assertSignalBaseUrlAllowed("http://169.254.169.254/")).toThrow(
      /link-local\/metadata/,
    );
    expect(() => assertSignalBaseUrlAllowed("http://169.254.169.254:80/")).toThrow(
      /link-local\/metadata/,
    );
  });

  it("should block IPv6-mapped metadata IP (::ffff:169.254.169.254)", () => {
    expect(() => assertSignalBaseUrlAllowed("http://[::ffff:169.254.169.254]/")).toThrow(/blocked/);
  });

  it("should block link-local range (169.254.x.x)", () => {
    expect(() => assertSignalBaseUrlAllowed("http://169.254.1.1:8080/")).toThrow(
      /link-local\/metadata/,
    );
    expect(() => assertSignalBaseUrlAllowed("http://169.254.0.1/")).toThrow(/link-local\/metadata/);
  });

  it("should block metadata.google.internal", () => {
    expect(() =>
      assertSignalBaseUrlAllowed("http://metadata.google.internal/computeMetadata/v1/"),
    ).toThrow(/blocked hostname/);
  });

  it("should block *.internal and *.local hostnames", () => {
    expect(() => assertSignalBaseUrlAllowed("http://service.internal:8080/")).toThrow(
      /blocked hostname/,
    );
    expect(() => assertSignalBaseUrlAllowed("http://signal.local:8080/")).toThrow(
      /blocked hostname/,
    );
  });

  it("should block localhost.localdomain", () => {
    expect(() => assertSignalBaseUrlAllowed("http://localhost.localdomain:8080/")).toThrow(
      /blocked hostname/,
    );
  });

  it("should allow localhost (default signal-cli target)", () => {
    expect(() => assertSignalBaseUrlAllowed("http://localhost:8080")).not.toThrow();
  });

  it("should allow 127.0.0.1 (default signal-cli target)", () => {
    expect(() => assertSignalBaseUrlAllowed("http://127.0.0.1:8080")).not.toThrow();
  });

  it("should allow private network IPs (signal-cli may run on LAN)", () => {
    expect(() => assertSignalBaseUrlAllowed("http://192.168.1.100:8080")).not.toThrow();
    expect(() => assertSignalBaseUrlAllowed("http://10.0.0.5:8080")).not.toThrow();
    expect(() => assertSignalBaseUrlAllowed("http://172.16.0.10:8080")).not.toThrow();
  });

  it("should allow public IPs", () => {
    expect(() => assertSignalBaseUrlAllowed("http://93.184.216.34:8080")).not.toThrow();
  });

  it("should allow public hostnames", () => {
    expect(() => assertSignalBaseUrlAllowed("http://signal.example.com:8080")).not.toThrow();
  });

  it("should reject invalid URLs", () => {
    expect(() => assertSignalBaseUrlAllowed("not-a-url")).toThrow(/Invalid Signal base URL/);
  });
});
