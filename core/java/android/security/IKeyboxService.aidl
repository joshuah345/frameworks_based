// IKeyboxService.aidl
package android.security;

/** @FlaggedApi (class android.security.IKeyboxService) 
 *  @FlaggedApi (class android.security.IKeyboxService.default)
 *  @hide
 */
interface IKeyboxService {
    /**
     * Sets the Keybox data.
     * @hide
     * @param keyboxData An array of Strings containing Keybox entries.
     */
    void setKeyboxData(in String[] keyboxData);

    /**
     * Retrieves the Keybox data.
     * @hide
     * @return An array of Strings containing Keybox entries.
     * 
     */
    String[] getKeyboxData();
}