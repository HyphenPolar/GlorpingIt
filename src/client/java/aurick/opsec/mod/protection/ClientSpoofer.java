package aurick.opsec.mod.protection;

import aurick.opsec.mod.config.OpsecConfig;

/**
 * Handles client brand spoofing and channel filtering logic.
 * Provides methods to check spoofing modes (vanilla, fabric)
 * and determines which network channels should be blocked.
 */
public class ClientSpoofer {

    /**
     * Check if running in vanilla mode for channel filtering purposes.
     * Requires both brand spoofing and channel spoofing to be enabled.
     * Delegates to SpoofSettings for brand mode check.
     */
    public static boolean isVanillaMode() {
        OpsecConfig config = OpsecConfig.getInstance();
        return config.shouldSpoofChannels() && config.getSettings().isVanillaMode();
    }

    /**
     * Check if running in fabric mode for channel filtering purposes.
     * Requires both brand spoofing and channel spoofing to be enabled.
     * Delegates to SpoofSettings for brand mode check.
     */
    public static boolean isFabricMode() {
        OpsecConfig config = OpsecConfig.getInstance();
        return config.shouldSpoofChannels() && config.getSettings().isFabricMode();
    }
}
