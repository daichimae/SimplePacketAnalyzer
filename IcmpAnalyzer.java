import java.nio.ByteBuffer;

/**
 * Takes an ICMP packet as a ByteBuffer object and analyze it.
 *
 * @author Daichi Mae
 */
public class IcmpAnalyzer implements PacketAnalyzer {
    private int icmpType;
    private int icmpCode;
    private int icmpChecksum;
    //long restOfHeader;

    public IcmpAnalyzer(ByteBuffer bb) {
        readPacket(bb);
    }

    @Override
    public void readPacket(ByteBuffer bb) {
        icmpType = bb.get() & 0xFF;
        icmpCode = bb.get() & 0xFF;
        icmpChecksum = bb.getShort() & 0xFFFF;
        // restOfHeader = bb.getInt() & 0xFFFFFFFFL;
    }

    @Override
    public void printHeader() {
        String tag = "ICMP:  ";
        System.out.println(tag + "----- ICMP Header -----");
        System.out.println(tag + "Type = " + icmpType);
        System.out.println(tag + "Code = " + icmpCode);
        System.out.println(tag + "Checksum = " + Integer.toHexString(icmpChecksum));
        System.out.println(tag);
    }
}
