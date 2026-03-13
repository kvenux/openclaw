import { describe, expect, it } from "vitest";
import { assertTtsBaseUrlAllowed } from "./tts-core.js";

describe("CWE-918: TTS base URL SSRF validation", () => {
  describe("blocked addresses (cloud metadata and dangerous hostnames)", () => {
    it("should block cloud metadata IP (169.254.169.254)", () => {
      expect(() => assertTtsBaseUrlAllowed("http://169.254.169.254/")).toThrow(
        /link-local\/metadata/,
      );
      expect(() => assertTtsBaseUrlAllowed("http://169.254.169.254:80/")).toThrow(
        /link-local\/metadata/,
      );
    });

    it("should block link-local range (169.254.x.x)", () => {
      expect(() => assertTtsBaseUrlAllowed("http://169.254.1.1:8080/")).toThrow(
        /link-local\/metadata/,
      );
      expect(() => assertTtsBaseUrlAllowed("http://169.254.0.1/")).toThrow(/link-local\/metadata/);
    });

    it("should block 0.0.0.0", () => {
      expect(() => assertTtsBaseUrlAllowed("http://0.0.0.0:8880/v1")).toThrow(/blocked address/);
    });

    it("should block metadata.google.internal", () => {
      expect(() =>
        assertTtsBaseUrlAllowed("http://metadata.google.internal/computeMetadata/v1/"),
      ).toThrow(/blocked hostname/);
    });

    it("should block *.internal and *.local hostnames", () => {
      expect(() => assertTtsBaseUrlAllowed("http://service.internal:8080/")).toThrow(
        /blocked hostname/,
      );
      expect(() => assertTtsBaseUrlAllowed("http://tts.local:8080/")).toThrow(/blocked hostname/);
    });

    it("should block localhost.localdomain", () => {
      expect(() => assertTtsBaseUrlAllowed("http://localhost.localdomain:8080/")).toThrow(
        /blocked hostname/,
      );
    });
  });

  describe("allowed addresses (legitimate TTS endpoints)", () => {
    it("should allow localhost (self-hosted TTS like Kokoro)", () => {
      expect(() => assertTtsBaseUrlAllowed("http://localhost:8880/v1")).not.toThrow();
    });

    it("should allow public hostnames", () => {
      expect(() => assertTtsBaseUrlAllowed("https://api.elevenlabs.io/v1")).not.toThrow();
      expect(() => assertTtsBaseUrlAllowed("https://api.openai.com/v1")).not.toThrow();
      expect(() => assertTtsBaseUrlAllowed("https://tts.example.com/v1")).not.toThrow();
    });

    it("should allow public IPs", () => {
      expect(() => assertTtsBaseUrlAllowed("http://93.184.216.34:8880/v1")).not.toThrow();
    });

    it("should reject invalid URLs", () => {
      expect(() => assertTtsBaseUrlAllowed("not-a-url")).toThrow(/Invalid TTS base URL/);
    });
  });
});
