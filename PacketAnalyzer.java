import java.nio.ByteBuffer;

/**
 * An interface that analyzer components of this application implement.
 *
 * @author Daichi Mae
 */
public interface PacketAnalyzer {

    /**
     * Takes a packet as a ByteBuffer object and store the header information.
     *
     * @param bb packet to analyze
     */
	void readPacket(ByteBuffer bb);

    /**
     * Print the header information.
     */
	void printHeader();
}
