import { config } from "../config.js";
import { prisma } from "../prisma.js";
import { syncAllNodes } from "./agentChannel.js";
import { processPendingTasksForNode } from "./panelTasks.js";

export function startAgentSyncLoop() {
  let inFlight = false;
  const sync = async () => {
    if (inFlight) return;
    inFlight = true;
    try {
      await syncAllNodes();
      const online = await prisma.agentNode.findMany({
        where: { status: "ONLINE" },
      });
      for (const node of online) {
        try {
          await processPendingTasksForNode(node);
        } catch (e) {
          console.error(`Panel task for ${node.name}:`, e.message);
        }
      }
    } catch (error) {
      console.error("Agent sync failed:", error.message);
    } finally {
      inFlight = false;
    }
  };

  sync();
  return setInterval(sync, config.agentSyncIntervalMs);
}
