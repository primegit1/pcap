/**
 * Load the built-in test PCAP data from its base64-encoded representation.
 * This allows demo/test traffic to be loaded without an external file upload.
 */
const TEST_PCAP_B64_PATH = "/test-traffic.pcap.b64";

export async function fetchTestPcap(): Promise<File> {
  const resp = await fetch(TEST_PCAP_B64_PATH);
  if (!resp.ok) {
    throw new Error(`Failed to load test PCAP data (HTTP ${resp.status})`);
  }
  const b64 = await resp.text();
  const binaryStr = atob(b64.trim());
  const bytes = new Uint8Array(binaryStr.length);
  for (let i = 0; i < binaryStr.length; i++) {
    bytes[i] = binaryStr.charCodeAt(i);
  }
  return new File([bytes], "test-traffic.pcap", {
    type: "application/vnd.tcpdump.pcap",
  });
}
