import { config } from "../config.js";
import { syncAllOpenVPNInfo } from "./agentChannel.js";

export function startOpenvpnInfoSyncLoop() {
  let inFlight = false;
  const sync = async () => {
    if (inFlight) return;
    inFlight = true;
    try {
      await syncAllOpenVPNInfo();
    } catch (error) {
      console.error("OpenVPN info sync failed:", error.message);
    } finally {
      inFlight = false;
    }
  };

  sync();
  return setInterval(sync, config.openvpnInfoSyncIntervalMs);
}
