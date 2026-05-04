import { config } from "./config.js";
import { createApp } from "./app.js";
import { startAgentSyncLoop } from "./services/agentSyncLoop.js";
import { startClientSyncLoop } from "./services/clientSyncLoop.js";
import { startOpenvpnInfoSyncLoop } from "./services/openvpnInfoSyncLoop.js";
import { startPanelBackupScheduler } from "./services/panelBackupScheduler.js";

const app = createApp();

startAgentSyncLoop();
startOpenvpnInfoSyncLoop();
startClientSyncLoop();
startPanelBackupScheduler();

app.listen(config.port, () => {
  console.log(`Backend listening on port ${config.port}`);
});
